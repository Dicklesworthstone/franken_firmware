//! The durable duplicate-suppression table for relative commands (N02 / `ffw-ugf`, over U01 / `ffw-mgb`).
//!
//! # What it remembers, and why this much
//!
//! A relative command (`AdjustMemberVolume`, `AdjustGroupVolume`) is the one kind that must never be applied twice
//! ("relative volume requires duplicate suppression"; an absolute set is naturally repeatable). The channel's
//! [ledger](super::ledger) answers a retry from memory, but a restart empties it, and the revision checks that cover
//! a controller across a restart do not cover the local user and depend on the rebuilt session's revision. So for every
//! identity the channel keeps one number, its **floor**: the highest sequence number of a relative command the channel
//! has *begun* to apply. A relative command whose number is at or below its identity's floor and is not remembered by
//! the ledger is answered `OutOfWindow`: whether it was applied is **unknown**, and it is never applied. That is
//! the ledger's own contract for a forgotten entry; this table only makes the forgetting survive a restart.
//!
//! The floor is written **before** the effect, not after (see `pipeline::persist`): whatever a crash interrupts, a
//! command that may have taken effect is at or below a durable floor.
//!
//! # The record
//!
//! One value in U01's `Records` namespace, under `n02.seq`:
//!
//! ```text
//! offset  size  field
//!      0     1  format, 1
//!      1     1  count, at most MAX_PEERS (16)
//!      2   14n  n entries in strictly ascending tag order, each: tag (6 bytes) then the floor (8 bytes, big-endian)
//! ```
//!
//! An identity is named by a **tag**: the first six bytes of SHA-256 over `"FFCP-v1-seqfloor"` and the peer label.
//! Six bytes keep sixteen identities in `2 + 16 * 14 = 226` bytes, under the journal's 256-byte value limit, and make
//! a collision between two of at most sixteen labels about four in 10^13. If one ever happened the two identities
//! would share the larger floor, which can only refuse a command and never apply one twice.
//!
//! # Fail closed
//!
//! A record that cannot be read gives [`SeqFloors::refusing`]: every relative command is answered `OutOfWindow` for
//! the run, because the channel cannot tell a fresh one from a repeat. Absolute and stop commands do not use the
//! table and keep working.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::peer::{ControlProfile, MAX_PEERS, PeerId};

/// Bytes of an identity's tag.
pub const TAG_LEN: usize = 6;
/// Bytes of one entry: a tag and a big-endian floor.
pub const ENTRY_LEN: usize = TAG_LEN + 8;
/// Bytes before the entries: the format and the count.
pub const HEADER_LEN: usize = 2;
/// The format byte of the record.
pub const FORMAT: u8 = 1;
/// Most identities in the legacy profile.
pub const MAX_ENTRIES: usize = MAX_PEERS;
/// The longest an encoded legacy table can be.
pub const MAX_ENCODED_LEN: usize = HEADER_LEN + MAX_ENTRIES * ENTRY_LEN;
/// Domain separation: a tag made for another purpose over the same label is not a floor tag.
const TAG_CONTEXT: &[u8] = b"FFCP-v1-seqfloor";

/// The name of an identity in the record.
pub type Tag = [u8; TAG_LEN];

/// The tag of `peer`.
#[must_use]
pub fn tag_of(peer: &PeerId) -> Tag {
    let mut hasher = Sha256::new();
    hasher.update(TAG_CONTEXT);
    hasher.update(peer.as_str().as_bytes());
    let full = hasher.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

/// Why a stored table was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("the table is shorter than its header")]
    Short,
    #[error("unknown table format {0}")]
    Format(u8),
    #[error("the table names {count} identities; the most is {max}")]
    TooMany { count: usize, max: usize },
    #[error("the table is {got} bytes; its count makes {expected}")]
    Length { expected: usize, got: usize },
    #[error("the table's entries are not in strictly ascending tag order")]
    NotAscending,
}

/// Each identity's floor: the highest relative-command number the channel has begun to apply for it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeqFloors {
    floors: BTreeMap<Tag, u64>,
    refusing: bool,
    profile: ControlProfile,
}

impl SeqFloors {
    /// A table with no floors: nothing has been applied that this table knows of.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_profile(profile: ControlProfile) -> Self {
        Self {
            floors: BTreeMap::new(),
            refusing: false,
            profile,
        }
    }

    #[must_use]
    pub const fn profile(&self) -> ControlProfile {
        self.profile
    }

    /// The table of a channel that could not read its record: every identity's floor is the largest number, so
    /// every relative command is answered `OutOfWindow`, and no floor can be raised.
    #[must_use]
    pub fn refusing() -> Self {
        Self::refusing_with_profile(ControlProfile::Legacy)
    }

    #[must_use]
    pub fn refusing_with_profile(profile: ControlProfile) -> Self {
        Self {
            floors: BTreeMap::new(),
            refusing: true,
            profile,
        }
    }

    #[must_use]
    pub fn is_refusing(&self) -> bool {
        self.refusing
    }

    /// How many identities have a floor.
    #[must_use]
    pub fn len(&self) -> usize {
        self.floors.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.floors.is_empty()
    }

    /// `peer`'s floor, if it has one. In a refusing table, the largest number for everybody.
    #[must_use]
    pub fn floor_of(&self, peer: &PeerId) -> Option<u64> {
        if self.refusing {
            return Some(u64::MAX);
        }
        self.floors.get(&tag_of(peer)).copied()
    }

    /// A copy of this table with `peer`'s floor raised to at least `seq`. A floor never goes down. `None` if the table
    /// is refusing, or if `peer` would be a seventeenth identity.
    #[must_use]
    pub fn raised(&self, peer: &PeerId, seq: u64) -> Option<Self> {
        if self.refusing {
            return None;
        }
        let tag = tag_of(peer);
        let mut next = self.clone();
        match next.floors.get_mut(&tag) {
            Some(floor) => *floor = (*floor).max(seq),
            None => {
                if next.floors.len() >= self.profile.max_identities() {
                    return None;
                }
                next.floors.insert(tag, seq);
            }
        }
        Some(next)
    }

    /// The table that knows everything both do: each identity's larger floor. It refuses if either does, or if the two
    /// together name more identities than a record holds (nothing can then be said for the rest).
    #[must_use]
    pub fn merged(&self, other: &Self) -> Self {
        if self.refusing || other.refusing || self.profile != other.profile {
            return Self::refusing_with_profile(self.profile);
        }
        let mut floors = self.floors.clone();
        for (tag, floor) in &other.floors {
            let entry = floors.entry(*tag).or_insert(*floor);
            *entry = (*entry).max(*floor);
        }
        if floors.len() > self.profile.max_identities() {
            return Self::refusing_with_profile(self.profile);
        }
        Self {
            floors,
            refusing: false,
            profile: self.profile,
        }
    }

    /// The record's bytes: canonical, so equal tables encode equally. A refusing table is never stored; it encodes
    /// as an empty one.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.floors.len() * ENTRY_LEN);
        out.push(match self.profile {
            ControlProfile::Legacy => FORMAT,
            ControlProfile::FleetDevelopment => 2,
        });
        out.push(u8::try_from(self.floors.len()).unwrap_or(u8::MAX));
        for (tag, floor) in &self.floors {
            out.extend_from_slice(tag);
            out.extend_from_slice(&floor.to_be_bytes());
        }
        out
    }

    /// Read a stored record, refusing everything that is not exactly what [`SeqFloors::encode`] writes.
    ///
    /// # Errors
    /// [`DecodeError`] by name: a short record, another format, more identities than the directory admits, a length
    /// that disagrees with the count, entries out of order or repeated.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode_with_profile(bytes, ControlProfile::Legacy)
    }

    pub fn decode_with_profile(bytes: &[u8], profile: ControlProfile) -> Result<Self, DecodeError> {
        let [format, count, rest @ ..] = bytes else {
            return Err(DecodeError::Short);
        };
        let expected_format = match profile {
            ControlProfile::Legacy => FORMAT,
            ControlProfile::FleetDevelopment => 2,
        };
        if *format != expected_format {
            return Err(DecodeError::Format(*format));
        }
        let count = usize::from(*count);
        if count > profile.max_identities() {
            return Err(DecodeError::TooMany {
                count,
                max: profile.max_identities(),
            });
        }
        let expected = HEADER_LEN + count * ENTRY_LEN;
        if bytes.len() != expected {
            return Err(DecodeError::Length {
                expected,
                got: bytes.len(),
            });
        }
        let mut floors = BTreeMap::new();
        let mut previous: Option<Tag> = None;
        for entry in rest.as_chunks::<ENTRY_LEN>().0 {
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&entry[..TAG_LEN]);
            let mut floor = [0u8; 8];
            floor.copy_from_slice(&entry[TAG_LEN..]);
            if previous.is_some_and(|before| before >= tag) {
                return Err(DecodeError::NotAscending);
            }
            previous = Some(tag);
            floors.insert(tag, u64::from_be_bytes(floor));
        }
        Ok(Self {
            floors,
            refusing: false,
            profile,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    // The tags and the record are worked out before the Rust ran, with Python's `hashlib`: the first six bytes of
    // SHA-256 over `FFCP-v1-seqfloor` and the label, and the canonical table of `{panel: 7, ctl-a: 258}`, whose
    // entries are in ascending tag order (`ctl-a`'s tag begins 0x09, `panel`'s 0xa0).
    const TAG_PANEL: Tag = [0xa0, 0x98, 0x7e, 0xc6, 0x87, 0x00];
    const TAG_CTL_A: Tag = [0x09, 0x8f, 0xaa, 0xdd, 0x8d, 0x50];
    const RECORD: [u8; 30] = [
        0x01, 0x02, 0x09, 0x8f, 0xaa, 0xdd, 0x8d, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02, 0xa0, 0x98, 0x7e, 0xc6, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    ];

    fn table() -> SeqFloors {
        SeqFloors::new()
            .raised(&id("panel"), 7)
            .unwrap()
            .raised(&id("ctl-a"), 258)
            .unwrap()
    }

    #[test]
    fn the_tags_are_the_ones_sha256_gives() {
        assert_eq!(tag_of(&id("panel")), TAG_PANEL);
        assert_eq!(tag_of(&id("ctl-a")), TAG_CTL_A);
        assert_ne!(tag_of(&id("ctl-a")), tag_of(&id("ctl-b")));
    }

    #[test]
    fn the_record_bytes_are_the_ones_a_person_wrote() {
        assert_eq!(table().encode(), RECORD.to_vec());
        assert_eq!(SeqFloors::decode(&RECORD), Ok(table()));
        // The empty table is two bytes.
        assert_eq!(SeqFloors::new().encode(), vec![FORMAT, 0]);
        assert_eq!(SeqFloors::decode(&[FORMAT, 0]), Ok(SeqFloors::new()));
    }

    #[test]
    fn a_floor_is_found_by_its_identity_and_only_by_it() {
        let t = SeqFloors::decode(&RECORD).unwrap();
        assert_eq!(t.floor_of(&id("panel")), Some(7));
        assert_eq!(t.floor_of(&id("ctl-a")), Some(258));
        assert_eq!(t.floor_of(&id("ctl-b")), None);
        assert_eq!((t.len(), t.is_empty()), (2, false));
    }

    #[test]
    fn a_floor_only_goes_up_and_the_original_table_is_not_changed() {
        let before = table();
        let up = before.raised(&id("panel"), 9).unwrap();
        assert_eq!(up.floor_of(&id("panel")), Some(9));
        assert_eq!(before.floor_of(&id("panel")), Some(7));
        let same = up.raised(&id("panel"), 3).unwrap();
        assert_eq!(
            same.floor_of(&id("panel")),
            Some(9),
            "a lower number lowers nothing"
        );
        assert_eq!(same, up);
    }

    #[test]
    fn sixteen_identities_fit_in_226_bytes_and_a_seventeenth_does_not() {
        let mut t = SeqFloors::new();
        for i in 0..MAX_ENTRIES {
            t = t.raised(&id(&format!("ctl-{i:02}")), 1 + i as u64).unwrap();
        }
        assert_eq!(t.len(), MAX_ENTRIES);
        assert_eq!(t.encode().len(), 226);
        assert_eq!(MAX_ENCODED_LEN, 226);
        assert_eq!(SeqFloors::decode(&t.encode()), Ok(t.clone()));
        // A seventeenth identity has no room, and an identity that already has a floor still can be raised.
        assert_eq!(t.raised(&id("ctl-99"), 1), None);
        assert!(t.raised(&id("ctl-00"), 50).is_some());
    }

    #[test]
    fn the_decoder_refuses_everything_that_is_not_the_record_by_name() {
        assert_eq!(SeqFloors::decode(&[]), Err(DecodeError::Short));
        assert_eq!(SeqFloors::decode(&[FORMAT]), Err(DecodeError::Short));
        assert_eq!(SeqFloors::decode(&[2, 0]), Err(DecodeError::Format(2)));
        let mut seventeen = vec![FORMAT, 17];
        seventeen.resize(2 + 17 * ENTRY_LEN, 0);
        assert_eq!(
            SeqFloors::decode(&seventeen),
            Err(DecodeError::TooMany { count: 17, max: 16 })
        );
        // The length must agree with the count: a byte short, a byte over.
        assert_eq!(
            SeqFloors::decode(&RECORD[..29]),
            Err(DecodeError::Length {
                expected: 30,
                got: 29
            })
        );
        let mut long = RECORD.to_vec();
        long.push(0);
        assert_eq!(
            SeqFloors::decode(&long),
            Err(DecodeError::Length {
                expected: 30,
                got: 31
            })
        );
        // The entries must be in strictly ascending tag order: swapped, and repeated.
        let mut swapped = RECORD.to_vec();
        let (first, second) = (RECORD[2..16].to_vec(), RECORD[16..30].to_vec());
        swapped[2..16].copy_from_slice(&second);
        swapped[16..30].copy_from_slice(&first);
        assert_eq!(SeqFloors::decode(&swapped), Err(DecodeError::NotAscending));
        let mut repeated = RECORD.to_vec();
        repeated[16..30].copy_from_slice(&first);
        assert_eq!(SeqFloors::decode(&repeated), Err(DecodeError::NotAscending));
        // The permitted positive, from the same bytes.
        assert!(SeqFloors::decode(&RECORD).is_ok());
    }

    #[test]
    fn a_table_that_could_not_be_read_refuses_every_relative_number_and_raises_nothing() {
        let refusing = SeqFloors::refusing();
        assert!(refusing.is_refusing());
        assert_eq!(refusing.floor_of(&id("panel")), Some(u64::MAX));
        assert_eq!(refusing.floor_of(&id("anyone")), Some(u64::MAX));
        assert_eq!(refusing.raised(&id("panel"), 1), None);
        assert!(!SeqFloors::new().is_refusing());
        assert!(!SeqFloors::decode(&RECORD).unwrap().is_refusing());
    }

    #[test]
    fn merging_keeps_each_identitys_larger_floor_and_never_lowers_either_side() {
        let ours = SeqFloors::new()
            .raised(&id("panel"), 9)
            .unwrap()
            .raised(&id("ctl-b"), 2)
            .unwrap();
        let theirs = table();
        let both = ours.merged(&theirs);
        assert_eq!(both.floor_of(&id("panel")), Some(9));
        assert_eq!(both.floor_of(&id("ctl-a")), Some(258));
        assert_eq!(both.floor_of(&id("ctl-b")), Some(2));
        assert_eq!(both.len(), 3);
        // Merging a table with itself, or with an empty one, changes nothing.
        assert_eq!(theirs.merged(&theirs), theirs);
        assert_eq!(theirs.merged(&SeqFloors::new()), theirs);
        assert_eq!(SeqFloors::new().merged(&theirs), theirs);
    }

    #[test]
    fn merging_with_a_table_that_could_not_be_read_or_that_overflows_refuses() {
        assert!(table().merged(&SeqFloors::refusing()).is_refusing());
        assert!(SeqFloors::refusing().merged(&table()).is_refusing());
        // Two tables of nine different identities each name eighteen: a record cannot hold them.
        let nine = |prefix: &str| {
            let mut t = SeqFloors::new();
            for i in 0..9 {
                t = t.raised(&id(&format!("{prefix}-{i}")), 1).unwrap();
            }
            t
        };
        let (a, b) = (nine("aa"), nine("bb"));
        assert_eq!((a.len(), b.len()), (9, 9));
        assert!(a.merged(&b).is_refusing());
        // The permitted positive: nine and the same nine merge to nine.
        assert_eq!(a.merged(&a).len(), 9);
    }

    #[test]
    fn fleet_floors_survive_journal_compaction_and_restore_fail_closed_on_downgrade() {
        use crate::channel::peer::PeerDirectory;
        use crate::channel::pipeline::{
            ChannelConfig, ControlChannel, RestoredFloors, SEQ_FLOORS_KEY,
            restore_seq_floors_from_open,
        };
        use crate::contracts::secret_store::EphemeralSecretStore;
        use franken_journal::{Journal, Limits, MemStorage, Namespace};

        let profile = ControlProfile::FleetDevelopment;
        let mut floors = SeqFloors::with_profile(profile);
        for i in 0..33 {
            floors = floors.raised(&id(&format!("peer-{i:02}")), i + 1).unwrap();
        }
        assert_eq!(floors.len(), 33);
        assert_eq!(floors.encode().len(), 464);
        assert!(floors.raised(&id("overflow"), 1).is_none());
        assert_eq!(
            SeqFloors::decode_with_profile(&floors.encode(), profile),
            Ok(floors.clone())
        );
        assert!(SeqFloors::decode(&floors.encode()).is_err());
        assert!(SeqFloors::decode_with_profile(&floors.encode()[..463], profile).is_err());
        let limits = Limits::fleet_control_development();
        let mut medium = MemStorage::new(limits.segment_bytes);
        {
            let (mut journal, recovery) = Journal::open(&mut medium, limits.clone()).unwrap();
            crate::channel::custody::claim_fleet_profile(&mut journal, &recovery).unwrap();
            for seq in 1..=80 {
                floors = floors.raised(&id("peer-00"), seq).unwrap();
                journal
                    .put(Namespace::Records, SEQ_FLOORS_KEY, &floors.encode())
                    .unwrap();
            }
            assert!(journal.compactions() > 0);
        }
        let image = medium.durable();
        let mut reborn = MemStorage::from_image(limits.segment_bytes, image);
        let opened = Journal::open(&mut reborn, limits);
        let mut authority =
            PeerDirectory::with_profile(EphemeralSecretStore::fleet_control_development(), profile);
        use crate::channel::peer::ephemeral::test_key;
        use crate::channel::peer::{PeerRole, compute_proof};
        use crate::channel::pipeline::SubmitResult;
        use crate::channel::request::{ControlCommand, ControlRequest, RequestBody};
        authority
            .admit(
                &id("peer-32"),
                PeerRole::Controller,
                &test_key("peer-32"),
                Some(10),
                1,
            )
            .unwrap();
        let mut channel = ControlChannel::new(authority, ChannelConfig::provisional()).unwrap();
        assert_eq!(
            restore_seq_floors_from_open(&mut channel, &opened),
            Ok(RestoredFloors::Table { identities: 33 })
        );
        for i in 0..33 {
            assert_eq!(
                channel.seq_floors().floor_of(&id(&format!("peer-{i:02}"))),
                Some(if i == 0 { 80 } else { i + 1 })
            );
        }
        let request = |seq| {
            let body = RequestBody::new(
                id("peer-32"),
                seq,
                10,
                Some(1),
                ControlCommand::AdjustGroupVolume { delta: 1 },
            )
            .unwrap();
            let proof = compute_proof(&test_key("peer-32"), &body.signing_bytes());
            ControlRequest::new(body, proof)
        };
        assert_eq!(
            channel.submit(0, request(33)),
            SubmitResult::OutOfWindow { floor: 33 }
        );
        assert!(matches!(
            channel.submit(0, request(34)),
            SubmitResult::Queued { .. }
        ));
        let legacy = PeerDirectory::with_store(EphemeralSecretStore::with_capacity(16));
        let mut downgraded = ControlChannel::new(legacy, ChannelConfig::provisional()).unwrap();
        assert!(matches!(
            restore_seq_floors_from_open(&mut downgraded, &opened),
            Ok(RestoredFloors::Refusing(_))
        ));
        assert_eq!(downgraded.seq_floors().floor_of(&id("any")), Some(u64::MAX));
    }

    #[test]
    fn fleet_boot_rejects_legacy_journal_limits_and_accepts_explicit_limits() {
        use crate::channel::peer::PeerDirectory;
        use crate::channel::pipeline::{Booted, ChannelConfig, ControlChannel, boot_durable};
        use crate::contracts::secret_store::EphemeralSecretStore;
        use franken_journal::{Limits, MemStorage};

        let channel = || {
            ControlChannel::new(
                PeerDirectory::with_profile(
                    EphemeralSecretStore::fleet_control_development(),
                    ControlProfile::FleetDevelopment,
                ),
                ChannelConfig::provisional(),
            )
            .unwrap()
        };
        let legacy = Limits::standard();
        let mut rejected = channel();
        assert!(matches!(
            boot_durable(&mut rejected, MemStorage::new(legacy.segment_bytes), legacy),
            Ok(Booted::Latched { .. })
        ));
        assert!(rejected.seq_floors().is_refusing());
        let fleet = Limits::fleet_control_development();
        let mut accepted = channel();
        let boot = match boot_durable(&mut accepted, MemStorage::new(fleet.segment_bytes), fleet) {
            Ok(Booted::Durable(boot)) => boot,
            _ => panic!("fresh fleet boot must persist its profile"),
        };
        assert_eq!(
            boot.stepper
                .journal()
                .state()
                .marks
                .get(crate::channel::custody::CONTROL_PROFILE_KEY),
            Some(&2)
        );
        assert!(!accepted.seq_floors().is_refusing());
    }

    #[test]
    fn boot_refuses_profile_mismatch_in_both_directions_without_floor_record() {
        use crate::channel::custody::{admit_durably, claim_fleet_profile};
        use crate::channel::peer::ephemeral::test_key;
        use crate::channel::peer::{PeerDirectory, PeerRole};
        use crate::channel::pipeline::{Booted, ChannelConfig, ControlChannel, boot_durable};
        use crate::contracts::secret_store::EphemeralSecretStore;
        use franken_journal::{Journal, Limits, MemStorage};

        let limits = Limits::fleet_control_development();
        let mut fleet_medium = MemStorage::new(limits.segment_bytes);
        {
            let (mut journal, recovery) = Journal::open(&mut fleet_medium, limits.clone()).unwrap();
            claim_fleet_profile(&mut journal, &recovery).unwrap();
            let mut peer = PeerDirectory::with_profile(
                EphemeralSecretStore::fleet_control_development(),
                ControlProfile::FleetDevelopment,
            );
            admit_durably(
                &mut peer,
                &mut journal,
                &id("one"),
                PeerRole::Controller,
                &test_key("one"),
                Some(10),
                1,
            )
            .unwrap();
        }
        let legacy = PeerDirectory::with_store(EphemeralSecretStore::with_capacity(16));
        let mut legacy_channel = ControlChannel::new(legacy, ChannelConfig::provisional()).unwrap();
        let fleet_image = MemStorage::from_image(limits.segment_bytes, fleet_medium.durable());
        assert!(matches!(
            boot_durable(&mut legacy_channel, fleet_image, limits.clone()),
            Ok(Booted::Latched {
                code: "profile_mismatch",
                ..
            })
        ));
        let mut legacy_medium = MemStorage::new(limits.segment_bytes);
        {
            let (mut journal, _) = Journal::open(&mut legacy_medium, limits.clone()).unwrap();
            let mut peer = PeerDirectory::with_store(EphemeralSecretStore::with_capacity(16));
            admit_durably(
                &mut peer,
                &mut journal,
                &id("one"),
                PeerRole::Controller,
                &test_key("one"),
                Some(10),
                1,
            )
            .unwrap();
        }
        let fleet = PeerDirectory::with_profile(
            EphemeralSecretStore::fleet_control_development(),
            ControlProfile::FleetDevelopment,
        );
        let mut fleet_channel = ControlChannel::new(fleet, ChannelConfig::provisional()).unwrap();
        let legacy_image = MemStorage::from_image(limits.segment_bytes, legacy_medium.durable());
        assert!(matches!(
            boot_durable(&mut fleet_channel, legacy_image, limits),
            Ok(Booted::Latched {
                code: "profile_mismatch",
                ..
            })
        ));
    }
}
