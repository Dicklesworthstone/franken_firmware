//! The request and the acknowledgement on the wire (N02 / `ffw-ugf`, section 9.3).
//!
//! A request had a canonical signed encoding ([`RequestBody::signing_bytes`]) and no way to arrive: nothing turned bytes
//! into a [`ControlRequest`], so no datagram could reach the channel and the authenticated replies of section 9.1 had
//! nothing to answer. This module is that way in, and the way out for a client.
//!
//! # The wire form
//!
//! The signed bytes the proof already covers, then the proof, exactly 32 bytes:
//!
//! ```text
//! request:  "FFCP" | version 1 | peer | seq | epoch | revision | command | tag
//! ack:      "FFCA" | version 1 | peer | seq | epoch | tag
//! ```
//!
//! with the fields as [`RequestBody::signing_bytes`] and [`AckBody::signing_bytes`] write them (big-endian integers, a
//! length byte before each label, a presence byte before the revision). The tag is the proof:
//! `HMAC-SHA256(key, "FFCP-v1-auth" || signed bytes)`. Nothing is added: there is no length prefix, no checksum and no
//! second copy of any field, so a datagram has one meaning and a decoder has nothing to reconcile.
//!
//! # What a decoder refuses, and in what order
//!
//! Every refusal has a stable name ([`WireError::code`]) and nothing is allocated for a datagram that is refused for its
//! length. The order is part of the specification, because it decides what an attacker learns from a refusal and what a
//! test can pin:
//!
//! 1. **the length**, before a byte is read ([`MAX_DATAGRAM_LEN`], `too_long`);
//! 2. the **magic** (`bad_magic`) and the **version** (`bad_version`);
//! 3. the **peer**: a length byte, then that many bytes, which must be a peer id (`invalid_peer`; a datagram that ends
//!    first is `truncated`, not judged);
//! 4. the **sequence number**, refused as soon as it and the epoch are read (`zero_sequence`);
//! 5. the **shape**: the revision flag (`bad_revision_flag`), the command tag (`unknown_command`), the command's own bytes
//!    (`bad_bool`), then the tag, where too few bytes are `truncated` and too many `trailing_bytes`;
//! 6. only then the **values**, in the order [`RequestBody::new`] judges them: the command's own (`invalid_member_id`,
//!    `volume_out_of_range`, `delta_out_of_range`, `zero_target`), a relative step that names no revision
//!    (`relative_needs_revision`), a cancel of itself (`cancels_itself`).
//!
//! A datagram that is the wrong shape is therefore refused as such before its values are judged, and one that parses is a
//! request the constructor would have built. Decoding proves nothing about who sent it: the proof is checked by the channel,
//! first, as for any request.
//!
//! # What this does not do
//!
//! It opens no socket and reads no clock. It does not frame a stream (a datagram is one message), fragment, or encrypt. It
//! says nothing about acknowledgements it cannot decode, which are dropped by the caller.

use super::peer::{AuthProof, MAX_PEER_ID_LEN, PROOF_LEN, PeerId};
use super::request::{
    ACK_MAGIC, AckBody, AckRequest, ControlCommand, ControlRequest, MAX_MEMBER_ID_LEN, RequestBody,
    RequestError, WIRE_MAGIC, WIRE_VERSION,
};

/// The longest request: magic and version, the longest peer id, both numbers, a present revision, the widest command
/// (a member id of the longest length and a one-byte value) and the tag.
pub const MAX_REQUEST_LEN: usize =
    4 + 1 + (1 + MAX_PEER_ID_LEN) + 8 + 8 + (1 + 8) + (1 + (1 + MAX_MEMBER_ID_LEN) + 1) + PROOF_LEN;
/// The longest acknowledgement.
pub const MAX_ACK_LEN: usize = 4 + 1 + (1 + MAX_PEER_ID_LEN) + 8 + 8 + PROOF_LEN;
/// The longest datagram the channel reads at all. A longer one is refused unread. (The request is the longer kind.)
pub const MAX_DATAGRAM_LEN: usize = MAX_REQUEST_LEN;

/// Why a datagram was not decoded, or an item could not be encoded. No variant carries a byte the sender supplied beyond a
/// number that names the fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Longer than [`MAX_DATAGRAM_LEN`]. Refused before anything was read.
    TooLong {
        len: usize,
    },
    /// The datagram ends before a field does, or before the tag does.
    Truncated,
    /// Neither the request magic nor the acknowledgement magic.
    BadMagic,
    BadVersion {
        version: u8,
    },
    /// The peer id is empty, too long, or not made of the characters a peer id may have.
    InvalidPeer,
    /// The sequence number is zero.
    ZeroSequence,
    /// The revision presence byte is neither 0 nor 1.
    BadRevisionFlag {
        flag: u8,
    },
    UnknownCommand {
        tag: u8,
    },
    /// A mute byte that is neither 0 nor 1.
    BadBool {
        value: u8,
    },
    /// Bytes after the tag.
    TrailingBytes,
    /// The command's values are not a request the constructor would build.
    Invalid(RequestError),
    /// Encoding only: the proof is not exactly [`PROOF_LEN`] bytes, so it could never authenticate.
    BadProofLength {
        len: usize,
    },
}

impl WireError {
    /// The stable name of the refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLong { .. } => "too_long",
            Self::Truncated => "truncated",
            Self::BadMagic => "bad_magic",
            Self::BadVersion { .. } => "bad_version",
            Self::InvalidPeer => "invalid_peer",
            Self::ZeroSequence => "zero_sequence",
            Self::BadRevisionFlag { .. } => "bad_revision_flag",
            Self::UnknownCommand { .. } => "unknown_command",
            Self::BadBool { .. } => "bad_bool",
            Self::TrailingBytes => "trailing_bytes",
            Self::BadProofLength { .. } => "bad_proof_length",
            Self::Invalid(error) => match error {
                RequestError::ZeroSequence => "zero_target",
                RequestError::InvalidMemberId { .. } => "invalid_member_id",
                RequestError::VolumeOutOfRange { .. } => "volume_out_of_range",
                RequestError::DeltaOutOfRange { .. } => "delta_out_of_range",
                RequestError::RelativeNeedsExpectedRevision { .. } => "relative_needs_revision",
                RequestError::CancelsItself => "cancels_itself",
            },
        }
    }
}

/// What a datagram decoded to. Neither is trusted: only the channel's check of the proof says who sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datagram {
    Request(ControlRequest),
    Ack(AckRequest),
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        let slice = self.bytes.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(raw))
    }

    /// A length byte and that many bytes.
    fn label(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    /// The tag: exactly [`PROOF_LEN`] bytes are left. Fewer is `truncated` and more is `trailing_bytes`.
    fn tag(&mut self) -> Result<AuthProof, WireError> {
        let left = self.bytes.len() - self.pos;
        if left < PROOF_LEN {
            return Err(WireError::Truncated);
        }
        if left > PROOF_LEN {
            return Err(WireError::TrailingBytes);
        }
        AuthProof::new(self.take(PROOF_LEN)?.to_vec()).map_err(|_| WireError::Truncated)
    }
}

fn read_peer(cursor: &mut Cursor<'_>) -> Result<PeerId, WireError> {
    let raw = cursor.label()?;
    std::str::from_utf8(raw)
        .ok()
        .and_then(|text| PeerId::parse(text).ok())
        .ok_or(WireError::InvalidPeer)
}

/// A member id as the sender wrote it. Bytes that are not text become a replacement character, which no member id may
/// contain, so the value check refuses them as `invalid_member_id` after the shape has been judged.
fn read_member(cursor: &mut Cursor<'_>) -> Result<String, WireError> {
    Ok(String::from_utf8_lossy(cursor.label()?).into_owned())
}

fn read_command(cursor: &mut Cursor<'_>) -> Result<ControlCommand, WireError> {
    Ok(match cursor.u8()? {
        1 => ControlCommand::SetMemberVolume {
            member_id: read_member(cursor)?,
            volume: cursor.u8()?,
        },
        2 => ControlCommand::SetGroupVolume {
            volume: cursor.u8()?,
        },
        3 => ControlCommand::AdjustMemberVolume {
            member_id: read_member(cursor)?,
            delta: i8::from_be_bytes([cursor.u8()?]),
        },
        4 => ControlCommand::AdjustGroupVolume {
            delta: i8::from_be_bytes([cursor.u8()?]),
        },
        5 => {
            let member_id = read_member(cursor)?;
            let muted = match cursor.u8()? {
                0 => false,
                1 => true,
                value => return Err(WireError::BadBool { value }),
            };
            ControlCommand::SetMemberMute { member_id, muted }
        }
        6 => ControlCommand::StopGroupPlayback {
            now_ns: cursor.u64()?,
            irrevocable_dma_tail_ns: cursor.u64()?,
        },
        7 => ControlCommand::Cancel {
            target_seq: cursor.u64()?,
        },
        tag => return Err(WireError::UnknownCommand { tag }),
    })
}

fn read_request(cursor: &mut Cursor<'_>) -> Result<ControlRequest, WireError> {
    let peer = read_peer(cursor)?;
    let seq = cursor.u64()?;
    let epoch = cursor.u64()?;
    if seq == 0 {
        return Err(WireError::ZeroSequence);
    }
    let revision = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.u64()?),
        flag => return Err(WireError::BadRevisionFlag { flag }),
    };
    let command = read_command(cursor)?;
    let proof = cursor.tag()?;
    let body = RequestBody::new(peer, seq, epoch, revision, command).map_err(WireError::Invalid)?;
    Ok(ControlRequest::new(body, proof))
}

fn read_ack(cursor: &mut Cursor<'_>) -> Result<AckRequest, WireError> {
    let peer = read_peer(cursor)?;
    let seq = cursor.u64()?;
    let epoch = cursor.u64()?;
    if seq == 0 {
        return Err(WireError::ZeroSequence);
    }
    let proof = cursor.tag()?;
    let body = AckBody::new(peer, seq, epoch).map_err(WireError::Invalid)?;
    Ok(AckRequest::new(body, proof))
}

/// Decode one datagram, in the order the module documentation gives. A datagram longer than [`MAX_DATAGRAM_LEN`] is
/// refused before a byte of it is read.
///
/// # Errors
/// The first [`WireError`] in that order.
pub fn decode_datagram(bytes: &[u8]) -> Result<Datagram, WireError> {
    if bytes.len() > MAX_DATAGRAM_LEN {
        return Err(WireError::TooLong { len: bytes.len() });
    }
    let mut cursor = Cursor { bytes, pos: 0 };
    let magic = cursor.take(4)?;
    let is_request = magic == WIRE_MAGIC.as_slice();
    if !is_request && magic != ACK_MAGIC.as_slice() {
        return Err(WireError::BadMagic);
    }
    let version = cursor.u8()?;
    if version != WIRE_VERSION {
        return Err(WireError::BadVersion { version });
    }
    if is_request {
        read_request(&mut cursor).map(Datagram::Request)
    } else {
        read_ack(&mut cursor).map(Datagram::Ack)
    }
}

/// Decode a datagram that must be a request. An acknowledgement is refused as `bad_magic`.
///
/// # Errors
/// As [`decode_datagram`].
pub fn decode_request(bytes: &[u8]) -> Result<ControlRequest, WireError> {
    match decode_datagram(bytes)? {
        Datagram::Request(request) => Ok(request),
        Datagram::Ack(_) => Err(WireError::BadMagic),
    }
}

/// Decode a datagram that must be an acknowledgement. A request is refused as `bad_magic`.
///
/// # Errors
/// As [`decode_datagram`].
pub fn decode_ack(bytes: &[u8]) -> Result<AckRequest, WireError> {
    match decode_datagram(bytes)? {
        Datagram::Ack(ack) => Ok(ack),
        Datagram::Request(_) => Err(WireError::BadMagic),
    }
}

fn check_proof(proof: &AuthProof) -> Result<&[u8], WireError> {
    let bytes = proof.as_bytes();
    if bytes.len() == PROOF_LEN {
        Ok(bytes)
    } else {
        Err(WireError::BadProofLength { len: bytes.len() })
    }
}

/// The wire form of a request: its signed bytes, then its proof.
///
/// # Errors
/// [`WireError::BadProofLength`] if the proof is not exactly [`PROOF_LEN`] bytes: such a proof can never authenticate.
pub fn encode_request(request: &ControlRequest) -> Result<Vec<u8>, WireError> {
    let proof = check_proof(request.proof())?;
    let mut out = request.body().signing_bytes();
    out.extend_from_slice(proof);
    Ok(out)
}

/// The wire form of an acknowledgement: its signed bytes, then its proof.
///
/// # Errors
/// As [`encode_request`].
pub fn encode_ack(ack: &AckRequest) -> Result<Vec<u8>, WireError> {
    let proof = check_proof(ack.proof())?;
    let mut out = ack.body().signing_bytes();
    out.extend_from_slice(proof);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::channel::peer::compute_proof;

    const VECTORS_JSON: &str = include_str!("../../tests/vectors/n02_request_wire_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS_JSON).expect("the request wire vectors are valid JSON")
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn command_from(v: &Value) -> ControlCommand {
        let member = || v["member"].as_str().expect("a member").to_string();
        let number = |key: &str| v[key].as_u64().expect("a number");
        let step = || i8::try_from(v["delta"].as_i64().expect("a step")).expect("a step in range");
        let volume = || u8::try_from(number("volume")).expect("a volume in range");
        match v["kind"].as_str().expect("a command kind") {
            "set_member_volume" => ControlCommand::SetMemberVolume {
                member_id: member(),
                volume: volume(),
            },
            "set_group_volume" => ControlCommand::SetGroupVolume { volume: volume() },
            "adjust_member_volume" => ControlCommand::AdjustMemberVolume {
                member_id: member(),
                delta: step(),
            },
            "adjust_group_volume" => ControlCommand::AdjustGroupVolume { delta: step() },
            "set_member_mute" => ControlCommand::SetMemberMute {
                member_id: member(),
                muted: v["muted"].as_bool().expect("a flag"),
            },
            "stop" => ControlCommand::StopGroupPlayback {
                now_ns: number("now_ns"),
                irrevocable_dma_tail_ns: number("tail_ns"),
            },
            "cancel" => ControlCommand::Cancel {
                target_seq: number("target_seq"),
            },
            other => panic!("command kind {other}"),
        }
    }

    fn request_of(v: &Value) -> ControlRequest {
        let body = RequestBody::new(
            id(v["peer"].as_str().unwrap()),
            v["seq"].as_u64().unwrap(),
            v["epoch"].as_u64().unwrap(),
            v["rev"].as_u64(),
            command_from(&v["cmd"]),
        )
        .expect("a vector request is well formed");
        let proof = AuthProof::new(unhex(v["tag_hex"].as_str().unwrap())).unwrap();
        ControlRequest::new(body, proof)
    }

    #[test]
    fn every_vector_request_encodes_to_the_independent_bytes_and_decodes_back() {
        let v = vectors();
        let requests = v["requests"].as_array().unwrap();
        assert_eq!(requests.len(), 10);
        for item in requests {
            let name = item["id"].as_str().unwrap();
            let want = unhex(item["wire_hex"].as_str().unwrap());
            let request = request_of(item);
            assert_eq!(encode_request(&request).unwrap(), want, "{name}: encoded");
            assert_eq!(
                decode_request(&want),
                Ok(request.clone()),
                "{name}: decoded"
            );
            assert_eq!(
                decode_datagram(&want),
                Ok(Datagram::Request(request.clone())),
                "{name}: as a datagram"
            );
            assert_eq!(
                decode_ack(&want),
                Err(WireError::BadMagic),
                "{name}: a request is not an acknowledgement"
            );
            // The proof on the wire is the one the key makes over the signed bytes: the decoder keeps it as it came.
            let key = item["key"].as_str().unwrap().as_bytes();
            assert_eq!(
                request.proof(),
                &compute_proof(key, &request.body().signing_bytes()),
                "{name}: the vector tag is the request's own proof"
            );
        }
        // The vectors cover every command kind.
        let kinds: std::collections::BTreeSet<&str> = requests
            .iter()
            .map(|r| r["cmd"]["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds.len(), 7);
    }

    #[test]
    fn every_malformed_datagram_fails_with_the_named_error() {
        let v = vectors();
        let cases = v["malformed"].as_array().unwrap();
        assert_eq!(cases.len(), 46);
        for case in cases {
            let name = format!("{} ({})", case["id"], case["what"]);
            let wire = unhex(case["wire_hex"].as_str().unwrap());
            let want = case["error"].as_str().unwrap();
            let got = decode_datagram(&wire);
            assert_eq!(
                got.as_ref().err().map(WireError::code),
                Some(want),
                "{name}: {got:?}"
            );
        }
    }

    #[test]
    fn every_shorter_datagram_is_truncated_and_one_byte_more_is_trailing_or_too_long() {
        let v = vectors();
        let items: Vec<&Value> = v["requests"]
            .as_array()
            .unwrap()
            .iter()
            .chain(v["acks"].as_array().unwrap())
            .collect();
        for item in items {
            let name = item["id"].as_str().unwrap();
            let wire = unhex(item["wire_hex"].as_str().unwrap());
            for cut in 0..wire.len() {
                assert_eq!(
                    decode_datagram(&wire[..cut]).err(),
                    Some(WireError::Truncated),
                    "{name} cut to {cut}"
                );
            }
            let mut longer = wire.clone();
            longer.push(0);
            let want = if longer.len() > MAX_DATAGRAM_LEN {
                "too_long"
            } else {
                "trailing_bytes"
            };
            assert_eq!(
                decode_datagram(&longer).err().as_ref().map(WireError::code),
                Some(want),
                "{name} with one more byte"
            );
        }
    }

    #[test]
    fn the_bounds_are_the_sums_the_specification_gives_and_the_longest_vector_meets_them() {
        let v = vectors();
        assert_eq!(MAX_REQUEST_LEN, 162);
        assert_eq!(MAX_ACK_LEN, 86);
        assert_eq!(MAX_DATAGRAM_LEN, 162);
        const { assert!(MAX_ACK_LEN <= MAX_REQUEST_LEN) };
        assert_eq!(
            v["max_request_len"].as_u64(),
            u64::try_from(MAX_REQUEST_LEN).ok()
        );
        assert_eq!(v["max_ack_len"].as_u64(), u64::try_from(MAX_ACK_LEN).ok());
        let longest = v["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| unhex(r["wire_hex"].as_str().unwrap()).len())
            .max();
        assert_eq!(longest, Some(MAX_REQUEST_LEN));
        // A datagram over the bound is refused as too long whatever it holds, without being read.
        for filler in [0u8, 0xff, b'F'] {
            assert_eq!(
                decode_datagram(&[filler; MAX_DATAGRAM_LEN + 1]),
                Err(WireError::TooLong {
                    len: MAX_DATAGRAM_LEN + 1
                })
            );
        }
        let big: Vec<u8> = std::iter::repeat_n(0u8, 1 << 16).collect();
        assert_eq!(
            decode_datagram(&big),
            Err(WireError::TooLong { len: 1 << 16 })
        );
    }

    #[test]
    fn an_acknowledgement_round_trips_and_neither_kind_decodes_as_the_other() {
        let v = vectors();
        let acks = v["acks"].as_array().unwrap();
        assert_eq!(acks.len(), 3);
        for item in acks {
            let name = item["id"].as_str().unwrap();
            let wire = unhex(item["wire_hex"].as_str().unwrap());
            let body = AckBody::new(
                id(item["peer"].as_str().unwrap()),
                item["seq"].as_u64().unwrap(),
                item["epoch"].as_u64().unwrap(),
            )
            .unwrap();
            let proof = AuthProof::new(unhex(item["tag_hex"].as_str().unwrap())).unwrap();
            let ack = AckRequest::new(body, proof);
            assert_eq!(encode_ack(&ack).unwrap(), wire, "{name}: encoded");
            assert_eq!(decode_ack(&wire), Ok(ack.clone()), "{name}: decoded");
            assert_eq!(decode_datagram(&wire), Ok(Datagram::Ack(ack)), "{name}");
            assert_eq!(
                decode_request(&wire),
                Err(WireError::BadMagic),
                "{name}: an acknowledgement is not a request"
            );
        }
    }

    #[test]
    fn the_encoder_refuses_a_proof_that_is_not_exactly_the_tag_length() {
        let body = RequestBody::new(
            id("ctl-a"),
            1,
            10,
            Some(2),
            ControlCommand::SetGroupVolume { volume: 70 },
        )
        .unwrap();
        for len in [1usize, 31, 33, 64] {
            let request =
                ControlRequest::new(body.clone(), AuthProof::new(vec![7u8; len]).unwrap());
            assert_eq!(
                encode_request(&request),
                Err(WireError::BadProofLength { len })
            );
        }
        let ack_body = AckBody::new(id("ctl-a"), 1, 10).unwrap();
        let ack = AckRequest::new(ack_body, AuthProof::new(vec![7u8; 33]).unwrap());
        assert_eq!(encode_ack(&ack), Err(WireError::BadProofLength { len: 33 }));
        let good = ControlRequest::new(body, AuthProof::new(vec![7u8; PROOF_LEN]).unwrap());
        // magic and version 5, peer 6, seq 8, epoch 8, revision 9, command 2, then the tag.
        assert_eq!(
            encode_request(&good).map(|w| w.len()),
            Ok(5 + 6 + 8 + 8 + 9 + 2 + PROOF_LEN)
        );
    }

    #[test]
    fn every_error_has_a_distinct_stable_name() {
        let errors = [
            WireError::TooLong { len: 163 },
            WireError::Truncated,
            WireError::BadMagic,
            WireError::BadVersion { version: 2 },
            WireError::InvalidPeer,
            WireError::ZeroSequence,
            WireError::BadRevisionFlag { flag: 2 },
            WireError::UnknownCommand { tag: 8 },
            WireError::BadBool { value: 2 },
            WireError::TrailingBytes,
            WireError::BadProofLength { len: 3 },
            WireError::Invalid(RequestError::ZeroSequence),
            WireError::Invalid(RequestError::InvalidMemberId { reason: "empty" }),
            WireError::Invalid(RequestError::VolumeOutOfRange { volume: 101 }),
            WireError::Invalid(RequestError::DeltaOutOfRange { delta: 0 }),
            WireError::Invalid(RequestError::RelativeNeedsExpectedRevision { command: "x" }),
            WireError::Invalid(RequestError::CancelsItself),
        ];
        let names: std::collections::BTreeSet<&str> = errors.iter().map(WireError::code).collect();
        assert_eq!(names.len(), errors.len(), "two errors share a name");
        let expected = [
            "too_long",
            "truncated",
            "bad_magic",
            "bad_version",
            "invalid_peer",
            "zero_sequence",
            "bad_revision_flag",
            "unknown_command",
            "bad_bool",
            "trailing_bytes",
            "bad_proof_length",
            "zero_target",
            "invalid_member_id",
            "volume_out_of_range",
            "delta_out_of_range",
            "relative_needs_revision",
            "cancels_itself",
        ];
        assert_eq!(
            errors.iter().map(WireError::code).collect::<Vec<_>>(),
            expected
        );
    }
}
