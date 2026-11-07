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

use super::peer::{MAX_PEERS, PeerId};

/// Bytes of an identity's tag.
pub const TAG_LEN: usize = 6;
/// Bytes of one entry: a tag and a big-endian floor.
pub const ENTRY_LEN: usize = TAG_LEN + 8;
/// Bytes before the entries: the format and the count.
pub const HEADER_LEN: usize = 2;
/// The format byte of the record.
pub const FORMAT: u8 = 1;
/// Most identities a table holds: the most the peer directory ever admits.
pub const MAX_ENTRIES: usize = MAX_PEERS;
/// The longest an encoded table can be.
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
}

impl SeqFloors {
    /// A table with no floors: nothing has been applied that this table knows of.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The table of a channel that could not read its record: every identity's floor is the largest number, so
    /// every relative command is answered `OutOfWindow`, and no floor can be raised.
    #[must_use]
    pub fn refusing() -> Self {
        Self {
            floors: BTreeMap::new(),
            refusing: true,
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
                if next.floors.len() >= MAX_ENTRIES {
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
        if self.refusing || other.refusing {
            return Self::refusing();
        }
        let mut floors = self.floors.clone();
        for (tag, floor) in &other.floors {
            let entry = floors.entry(*tag).or_insert(*floor);
            *entry = (*entry).max(*floor);
        }
        if floors.len() > MAX_ENTRIES {
            return Self::refusing();
        }
        Self {
            floors,
            refusing: false,
        }
    }

    /// The record's bytes: canonical, so equal tables encode equally. A refusing table is never stored; it encodes
    /// as an empty one.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.floors.len() * ENTRY_LEN);
        out.push(FORMAT);
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
        let [format, count, rest @ ..] = bytes else {
            return Err(DecodeError::Short);
        };
        if *format != FORMAT {
            return Err(DecodeError::Format(*format));
        }
        let count = usize::from(*count);
        if count > MAX_ENTRIES {
            return Err(DecodeError::TooMany {
                count,
                max: MAX_ENTRIES,
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
}
