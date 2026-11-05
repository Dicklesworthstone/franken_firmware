//! Control requests and their canonical encoding (N02 / `ffw-ugf`).
//!
//! A [`ControlRequest`] is a [`RequestBody`] plus the peer's [`AuthProof`]. The body names the peer, a
//! per-peer command number (`seq`, the idempotency key), the epoch the sender issues the command
//! under, the state revision it last saw (mandatory for relative commands, optional otherwise) and the
//! command itself.
//!
//! The proof covers [`RequestBody::signing_bytes`], an explicit big-endian encoding written by hand,
//! not a serialized struct: a four-byte magic, a version, then every field in a fixed order with
//! lengths where the size varies. Because every field is in those bytes, changing any one of them
//! invalidates the proof; a test changes them one at a time and checks that.
//!
//! The first slice carries volume, mute, stop and cancel. Membership changes (admit, remove, clock
//! lock) are deliberately not commands here: they follow the propose / ready / commit-at-a-frame
//! protocol of the group state machine, not a retried control message.

use super::peer::{AuthProof, PeerId};

/// Longest member id, in bytes.
pub const MAX_MEMBER_ID_LEN: usize = 64;
/// Largest relative volume step in either direction.
pub const MAX_VOLUME_DELTA: i8 = 100;
/// Magic that opens every signed body, for domain separation from any other use of the key.
pub const WIRE_MAGIC: [u8; 4] = *b"FFCP";
/// Version of the signed encoding.
pub const WIRE_VERSION: u8 = 1;

/// Which queue a command travels in. Stop, mute and cancel get their own, so a backlog of ordinary
/// work cannot delay them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lane {
    Ordinary,
    Priority,
}

/// What a request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand {
    SetMemberVolume {
        member_id: String,
        volume: u8,
    },
    SetGroupVolume {
        volume: u8,
    },
    AdjustMemberVolume {
        member_id: String,
        delta: i8,
    },
    AdjustGroupVolume {
        delta: i8,
    },
    SetMemberMute {
        member_id: String,
        muted: bool,
    },
    StopGroupPlayback {
        now_ns: u64,
        irrevocable_dma_tail_ns: u64,
    },
    /// Withdraw an earlier ordinary command of the same peer that has not been applied yet.
    Cancel {
        target_seq: u64,
    },
}

impl ControlCommand {
    #[must_use]
    pub const fn lane(&self) -> Lane {
        match self {
            Self::SetMemberMute { .. } | Self::StopGroupPlayback { .. } | Self::Cancel { .. } => {
                Lane::Priority
            }
            Self::SetMemberVolume { .. }
            | Self::SetGroupVolume { .. }
            | Self::AdjustMemberVolume { .. }
            | Self::AdjustGroupVolume { .. } => Lane::Ordinary,
        }
    }

    /// Commands that set a volume or a mute state from a remote controller must name the revision the
    /// sender last read, so a copy composed before a restart can be told from a fresh command. (Relative
    /// commands name it too, and are held to it exactly.) A stop and a cancel need none: a stale stop
    /// only silences, and a cancel only withdraws its own sender's waiting work.
    #[must_use]
    pub const fn needs_observed_revision(&self) -> bool {
        matches!(
            self,
            Self::SetMemberVolume { .. } | Self::SetGroupVolume { .. } | Self::SetMemberMute { .. }
        )
    }

    /// Relative commands depend on what the sender last saw, so they must name that revision.
    #[must_use]
    pub const fn is_relative(&self) -> bool {
        matches!(
            self,
            Self::AdjustMemberVolume { .. } | Self::AdjustGroupVolume { .. }
        )
    }

    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::SetMemberVolume { .. } => "set-member-volume",
            Self::SetGroupVolume { .. } => "set-group-volume",
            Self::AdjustMemberVolume { .. } => "adjust-member-volume",
            Self::AdjustGroupVolume { .. } => "adjust-group-volume",
            Self::SetMemberMute { .. } => "set-member-mute",
            Self::StopGroupPlayback { .. } => "stop-group-playback",
            Self::Cancel { .. } => "cancel",
        }
    }

    fn validate(&self) -> Result<(), RequestError> {
        match self {
            Self::SetMemberVolume { member_id, volume } => {
                validate_member_id(member_id)?;
                validate_volume(*volume)
            }
            Self::SetGroupVolume { volume } => validate_volume(*volume),
            Self::AdjustMemberVolume { member_id, delta } => {
                validate_member_id(member_id)?;
                validate_delta(*delta)
            }
            Self::AdjustGroupVolume { delta } => validate_delta(*delta),
            Self::SetMemberMute { member_id, .. } => validate_member_id(member_id),
            Self::StopGroupPlayback { .. } => Ok(()),
            Self::Cancel { target_seq } => {
                if *target_seq == 0 {
                    Err(RequestError::ZeroSequence)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::SetMemberVolume { member_id, volume } => {
                out.push(1);
                put_label(out, member_id);
                out.push(*volume);
            }
            Self::SetGroupVolume { volume } => {
                out.push(2);
                out.push(*volume);
            }
            Self::AdjustMemberVolume { member_id, delta } => {
                out.push(3);
                put_label(out, member_id);
                out.extend_from_slice(&delta.to_be_bytes());
            }
            Self::AdjustGroupVolume { delta } => {
                out.push(4);
                out.extend_from_slice(&delta.to_be_bytes());
            }
            Self::SetMemberMute { member_id, muted } => {
                out.push(5);
                put_label(out, member_id);
                out.push(u8::from(*muted));
            }
            Self::StopGroupPlayback {
                now_ns,
                irrevocable_dma_tail_ns,
            } => {
                out.push(6);
                out.extend_from_slice(&now_ns.to_be_bytes());
                out.extend_from_slice(&irrevocable_dma_tail_ns.to_be_bytes());
            }
            Self::Cancel { target_seq } => {
                out.push(7);
                out.extend_from_slice(&target_seq.to_be_bytes());
            }
        }
    }
}

/// Why a request could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    #[error("a command number must be at least 1")]
    ZeroSequence,
    #[error("invalid member id: {reason}")]
    InvalidMemberId { reason: &'static str },
    #[error("volume {volume} is above 100")]
    VolumeOutOfRange { volume: u8 },
    #[error("volume step {delta} is zero or beyond +/-100")]
    DeltaOutOfRange { delta: i8 },
    #[error("`{command}` is relative, so it must name the revision it was computed from")]
    RelativeNeedsExpectedRevision { command: &'static str },
    #[error("a command cannot cancel itself")]
    CancelsItself,
}

fn validate_volume(volume: u8) -> Result<(), RequestError> {
    if volume > 100 {
        Err(RequestError::VolumeOutOfRange { volume })
    } else {
        Ok(())
    }
}

fn validate_delta(delta: i8) -> Result<(), RequestError> {
    if delta == 0 || delta.unsigned_abs() > MAX_VOLUME_DELTA.unsigned_abs() {
        Err(RequestError::DeltaOutOfRange { delta })
    } else {
        Ok(())
    }
}

fn validate_member_id(raw: &str) -> Result<(), RequestError> {
    if raw.is_empty() {
        return Err(RequestError::InvalidMemberId { reason: "empty" });
    }
    if raw.len() > MAX_MEMBER_ID_LEN {
        return Err(RequestError::InvalidMemberId {
            reason: "longer than the member id limit",
        });
    }
    let alphabet_ok = raw
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'));
    if !alphabet_ok {
        return Err(RequestError::InvalidMemberId {
            reason: "only a-z, 0-9, '.', '_' and '-' are allowed",
        });
    }
    Ok(())
}

/// A length-prefixed label. Labels are at most 64 bytes, so the length fits one byte.
fn put_label(out: &mut Vec<u8>, label: &str) {
    out.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(label.as_bytes());
}

/// Everything in a request except its proof: what the proof covers and what the ledger remembers to
/// recognize a retry (and to refuse a different request that reuses the same number).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBody {
    peer: PeerId,
    seq: u64,
    epoch: u64,
    expected_revision: Option<u64>,
    command: ControlCommand,
}

impl RequestBody {
    /// Build and validate a body: `seq` of at least 1, in-range values, a relative command naming its
    /// revision, and a cancel that does not target itself.
    pub fn new(
        peer: PeerId,
        seq: u64,
        epoch: u64,
        expected_revision: Option<u64>,
        command: ControlCommand,
    ) -> Result<Self, RequestError> {
        if seq == 0 {
            return Err(RequestError::ZeroSequence);
        }
        command.validate()?;
        if command.is_relative() && expected_revision.is_none() {
            return Err(RequestError::RelativeNeedsExpectedRevision {
                command: command.label(),
            });
        }
        if matches!(command, ControlCommand::Cancel { target_seq } if target_seq == seq) {
            return Err(RequestError::CancelsItself);
        }
        Ok(Self {
            peer,
            seq,
            epoch,
            expected_revision,
            command,
        })
    }

    #[must_use]
    pub const fn peer(&self) -> &PeerId {
        &self.peer
    }

    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn expected_revision(&self) -> Option<u64> {
        self.expected_revision
    }

    #[must_use]
    pub const fn command(&self) -> &ControlCommand {
        &self.command
    }

    /// The bytes the proof is computed over: magic, version, peer, `seq`, `epoch`, the expected
    /// revision (a presence byte, then eight bytes if present) and the command (a tag byte and its
    /// fields). All integers are big-endian.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&WIRE_MAGIC);
        out.push(WIRE_VERSION);
        put_label(&mut out, self.peer.as_str());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        match self.expected_revision {
            None => out.push(0),
            Some(revision) => {
                out.push(1);
                out.extend_from_slice(&revision.to_be_bytes());
            }
        }
        self.command.encode(&mut out);
        out
    }
}

/// A request as it arrives: a body and the proof over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRequest {
    body: RequestBody,
    proof: AuthProof,
}

impl ControlRequest {
    #[must_use]
    pub const fn new(body: RequestBody, proof: AuthProof) -> Self {
        Self { body, proof }
    }

    #[must_use]
    pub const fn body(&self) -> &RequestBody {
        &self.body
    }

    #[must_use]
    pub const fn proof(&self) -> &AuthProof {
        &self.proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn adjust(member: &str, delta: i8) -> ControlCommand {
        ControlCommand::AdjustMemberVolume {
            member_id: member.to_string(),
            delta,
        }
    }

    fn body(
        peer: &str,
        seq: u64,
        epoch: u64,
        rev: Option<u64>,
        cmd: ControlCommand,
    ) -> RequestBody {
        RequestBody::new(id(peer), seq, epoch, rev, cmd).unwrap()
    }

    /// Hand-computed, byte by byte, from the layout in the module documentation. It does not call the
    /// encoder to build its expectation.
    #[test]
    fn a_relative_member_volume_encodes_to_the_documented_bytes() {
        let b = body("ctl-a", 7, 3, Some(12), adjust("kitchen", -5));
        let expected: Vec<u8> = vec![
            0x46, 0x46, 0x43, 0x50, // "FFCP"
            1,    // version
            5, 0x63, 0x74, 0x6c, 0x2d, 0x61, // peer: length 5, "ctl-a"
            0, 0, 0, 0, 0, 0, 0, 7, // seq
            0, 0, 0, 0, 0, 0, 0, 3, // epoch
            1, 0, 0, 0, 0, 0, 0, 0, 12, // expected revision present = 12
            3,  // command tag: adjust member volume
            7, 0x6b, 0x69, 0x74, 0x63, 0x68, 0x65, 0x6e, // member: length 7, "kitchen"
            0xfb, // delta -5
        ];
        assert_eq!(b.signing_bytes(), expected);
    }

    #[test]
    fn a_stop_without_a_revision_encodes_to_the_documented_bytes() {
        let b = body(
            "panel",
            1,
            10,
            None,
            ControlCommand::StopGroupPlayback {
                now_ns: 256,
                irrevocable_dma_tail_ns: 65_535,
            },
        );
        let expected: Vec<u8> = vec![
            0x46, 0x46, 0x43, 0x50, 1, // magic, version
            5, 0x70, 0x61, 0x6e, 0x65, 0x6c, // peer: length 5, "panel"
            0, 0, 0, 0, 0, 0, 0, 1, // seq
            0, 0, 0, 0, 0, 0, 0, 10, // epoch
            0,  // no expected revision
            6,  // command tag: stop
            0, 0, 0, 0, 0, 0, 1, 0, // now_ns = 256
            0, 0, 0, 0, 0, 0, 0xff, 0xff, // tail = 65535
        ];
        assert_eq!(b.signing_bytes(), expected);
    }

    #[test]
    fn every_command_has_its_own_tag_byte() {
        let tag_of = |cmd: ControlCommand| {
            let bytes = body("p", 2, 1, Some(1), cmd).signing_bytes();
            // magic(4) + version(1) + peer(1 + 1) + seq(8) + epoch(8) + rev(1 + 8) = 32
            bytes[32]
        };
        assert_eq!(
            tag_of(ControlCommand::SetMemberVolume {
                member_id: "m".into(),
                volume: 1
            }),
            1
        );
        assert_eq!(tag_of(ControlCommand::SetGroupVolume { volume: 1 }), 2);
        assert_eq!(tag_of(adjust("m", 1)), 3);
        assert_eq!(tag_of(ControlCommand::AdjustGroupVolume { delta: 1 }), 4);
        assert_eq!(
            tag_of(ControlCommand::SetMemberMute {
                member_id: "m".into(),
                muted: true
            }),
            5
        );
        assert_eq!(
            tag_of(ControlCommand::StopGroupPlayback {
                now_ns: 0,
                irrevocable_dma_tail_ns: 0
            }),
            6
        );
        assert_eq!(tag_of(ControlCommand::Cancel { target_seq: 1 }), 7);
    }

    /// Change one field at a time and the signed bytes must change, so the proof covers it.
    #[test]
    fn every_field_is_covered_by_the_signed_bytes() {
        let base = body("ctl-a", 7, 3, Some(12), adjust("kitchen", -5));
        let variants = [
            ("peer", body("ctl-b", 7, 3, Some(12), adjust("kitchen", -5))),
            ("seq", body("ctl-a", 8, 3, Some(12), adjust("kitchen", -5))),
            (
                "epoch",
                body("ctl-a", 7, 4, Some(12), adjust("kitchen", -5)),
            ),
            (
                "revision value",
                body("ctl-a", 7, 3, Some(13), adjust("kitchen", -5)),
            ),
            ("member", body("ctl-a", 7, 3, Some(12), adjust("den", -5))),
            ("delta", body("ctl-a", 7, 3, Some(12), adjust("kitchen", 5))),
            (
                "command kind",
                body(
                    "ctl-a",
                    7,
                    3,
                    Some(12),
                    ControlCommand::AdjustGroupVolume { delta: -5 },
                ),
            ),
        ];
        let base_bytes = base.signing_bytes();
        let mut seen = vec![base_bytes.clone()];
        for (field, variant) in &variants {
            let bytes = variant.signing_bytes();
            assert_ne!(bytes, base_bytes, "{field} is not covered");
            assert!(
                !seen.contains(&bytes),
                "{field} collides with another variant"
            );
            seen.push(bytes);
        }
    }

    #[test]
    fn the_presence_of_a_revision_and_its_value_are_both_covered() {
        let cmd = || ControlCommand::SetGroupVolume { volume: 40 };
        let none = body("ctl-a", 1, 1, None, cmd()).signing_bytes();
        let zero = body("ctl-a", 1, 1, Some(0), cmd()).signing_bytes();
        let one = body("ctl-a", 1, 1, Some(1), cmd()).signing_bytes();
        assert_ne!(none, zero, "no revision must differ from revision 0");
        assert_ne!(zero, one);
        assert_ne!(none, one);
    }

    #[test]
    fn set_command_fields_are_covered_too() {
        let set = |m: &str, v: u8| ControlCommand::SetMemberVolume {
            member_id: m.into(),
            volume: v,
        };
        let a = body("p", 1, 1, None, set("kitchen", 30)).signing_bytes();
        assert_ne!(a, body("p", 1, 1, None, set("kitchen", 31)).signing_bytes());
        assert_ne!(
            a,
            body("p", 1, 1, None, set("kitchen2", 30)).signing_bytes()
        );
        let mute = |m: &str, on: bool| ControlCommand::SetMemberMute {
            member_id: m.into(),
            muted: on,
        };
        assert_ne!(
            body("p", 1, 1, None, mute("m", true)).signing_bytes(),
            body("p", 1, 1, None, mute("m", false)).signing_bytes()
        );
        let stop = |now: u64, tail: u64| ControlCommand::StopGroupPlayback {
            now_ns: now,
            irrevocable_dma_tail_ns: tail,
        };
        let s = body("p", 1, 1, None, stop(5, 6)).signing_bytes();
        assert_ne!(s, body("p", 1, 1, None, stop(6, 6)).signing_bytes());
        assert_ne!(s, body("p", 1, 1, None, stop(5, 7)).signing_bytes());
        assert_ne!(
            body("p", 5, 1, None, ControlCommand::Cancel { target_seq: 2 }).signing_bytes(),
            body("p", 5, 1, None, ControlCommand::Cancel { target_seq: 3 }).signing_bytes()
        );
    }

    #[test]
    fn lanes_put_stop_mute_and_cancel_in_the_priority_lane_only() {
        let lane = |c: ControlCommand| c.lane();
        assert_eq!(
            lane(ControlCommand::StopGroupPlayback {
                now_ns: 0,
                irrevocable_dma_tail_ns: 0
            }),
            Lane::Priority
        );
        assert_eq!(
            lane(ControlCommand::SetMemberMute {
                member_id: "m".into(),
                muted: true
            }),
            Lane::Priority
        );
        assert_eq!(
            lane(ControlCommand::Cancel { target_seq: 1 }),
            Lane::Priority
        );
        for ordinary in [
            ControlCommand::SetGroupVolume { volume: 1 },
            ControlCommand::AdjustGroupVolume { delta: 1 },
            adjust("m", 1),
            ControlCommand::SetMemberVolume {
                member_id: "m".into(),
                volume: 1,
            },
        ] {
            assert_eq!(ordinary.lane(), Lane::Ordinary, "{}", ordinary.label());
        }
    }

    #[test]
    fn only_the_adjust_commands_are_relative() {
        assert!(adjust("m", 1).is_relative());
        assert!(ControlCommand::AdjustGroupVolume { delta: 1 }.is_relative());
        assert!(!ControlCommand::SetGroupVolume { volume: 1 }.is_relative());
        assert!(!ControlCommand::Cancel { target_seq: 1 }.is_relative());
    }

    #[test]
    fn only_volume_and_mute_setters_need_an_observed_revision_besides_the_relative_ones() {
        let needs = |c: ControlCommand| c.needs_observed_revision();
        assert!(needs(ControlCommand::SetGroupVolume { volume: 1 }));
        assert!(needs(ControlCommand::SetMemberVolume {
            member_id: "m".into(),
            volume: 1
        }));
        assert!(needs(ControlCommand::SetMemberMute {
            member_id: "m".into(),
            muted: true
        }));
        // A stop only silences and a cancel only withdraws the sender's own waiting work.
        assert!(!needs(ControlCommand::StopGroupPlayback {
            now_ns: 1,
            irrevocable_dma_tail_ns: 1
        }));
        assert!(!needs(ControlCommand::Cancel { target_seq: 1 }));
        // The relative commands are held to a revision by the body constructor instead.
        assert!(!needs(adjust("m", 1)) && adjust("m", 1).is_relative());
    }

    #[test]
    fn a_body_refuses_what_cannot_be_a_valid_request() {
        let ok = |seq, rev, cmd| RequestBody::new(id("p"), seq, 1, rev, cmd);
        assert_eq!(
            ok(0, None, ControlCommand::SetGroupVolume { volume: 1 }).unwrap_err(),
            RequestError::ZeroSequence
        );
        assert_eq!(
            ok(1, None, ControlCommand::SetGroupVolume { volume: 101 }).unwrap_err(),
            RequestError::VolumeOutOfRange { volume: 101 }
        );
        for delta in [0, 101, -101, i8::MIN, i8::MAX] {
            assert_eq!(
                ok(1, Some(1), adjust("m", delta)).unwrap_err(),
                RequestError::DeltaOutOfRange { delta },
                "delta {delta}"
            );
        }
        assert!(ok(1, Some(1), adjust("m", 100)).is_ok());
        assert!(ok(1, Some(1), adjust("m", -100)).is_ok());
        assert_eq!(
            ok(1, None, adjust("m", 5)).unwrap_err(),
            RequestError::RelativeNeedsExpectedRevision {
                command: "adjust-member-volume"
            }
        );
        assert_eq!(
            ok(1, None, ControlCommand::AdjustGroupVolume { delta: 5 }).unwrap_err(),
            RequestError::RelativeNeedsExpectedRevision {
                command: "adjust-group-volume"
            }
        );
        assert_eq!(
            ok(5, None, ControlCommand::Cancel { target_seq: 5 }).unwrap_err(),
            RequestError::CancelsItself
        );
        assert_eq!(
            ok(5, None, ControlCommand::Cancel { target_seq: 0 }).unwrap_err(),
            RequestError::ZeroSequence
        );
    }

    #[test]
    fn member_ids_are_bounded_lowercase_labels() {
        let longest = "m".repeat(MAX_MEMBER_ID_LEN);
        let set = |m: &str| {
            RequestBody::new(
                id("p"),
                1,
                1,
                None,
                ControlCommand::SetMemberMute {
                    member_id: m.to_string(),
                    muted: true,
                },
            )
        };
        for good in ["kitchen", "spk-s5.office_2", longest.as_str()] {
            assert!(set(good).is_ok(), "{good:?}");
        }
        let too_long = "m".repeat(MAX_MEMBER_ID_LEN + 1);
        for bad in [
            "",
            "Kitchen",
            "has space",
            "user@example.com",
            "caf\u{e9}",
            too_long.as_str(),
        ] {
            assert!(
                matches!(set(bad), Err(RequestError::InvalidMemberId { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_request_error_names_the_rule_and_not_the_input() {
        let err = RequestBody::new(
            id("p"),
            1,
            1,
            None,
            ControlCommand::SetMemberMute {
                member_id: "tok-SECRET-9f3a".to_string(),
                muted: true,
            },
        )
        .unwrap_err();
        assert!(!format!("{err} {err:?}").contains("SECRET"));
    }

    #[test]
    fn a_request_pairs_a_body_with_its_proof() {
        let b = body(
            "p",
            1,
            1,
            None,
            ControlCommand::SetGroupVolume { volume: 9 },
        );
        let proof = AuthProof::new(vec![1, 2, 3]).unwrap();
        let r = ControlRequest::new(b.clone(), proof.clone());
        assert_eq!(r.body(), &b);
        assert_eq!(r.proof(), &proof);
        assert_eq!(
            (b.peer().as_str(), b.seq(), b.epoch(), b.expected_revision()),
            ("p", 1, 1, None)
        );
        assert_eq!(b.command(), &ControlCommand::SetGroupVolume { volume: 9 });
    }
}
