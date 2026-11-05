//! The N01 vector replay (`ffw-ey5`, contract section 7): every committed wire and negotiation vector goes through the
//! real decoder, encoder, receiver and negotiation code, and one line per result is rendered.
//!
//! It is shared by the guest binary (`main.rs`, which a big-endian QEMU guest runs) and by
//! `tests/n01_wire_replay.rs` (which the central host runs), so there is one copy of the logic. It uses only the
//! package's normal dependencies, which is why the guest is a `[[bin]]` and not an example: an example would also
//! see the dev-dependencies, including `franken-test-support`.
//!
//! The line grammar is judged by `tests/n01/guest_transcript.py`, which re-derives every expectation from the
//! vector files and the independent Python reference and trusts nothing printed here but the verdicts themselves.

use franken_stream::{
    AuthenticatedStreamPacket, Capabilities, Initiator, OutboundFrame, PacketKind, StreamFormat,
    StreamId, StreamKey, StreamReceiver, StreamSender, respond,
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;

pub const WIRE_JSON: &str = include_str!("../../../tests/vectors/n01_wire_vectors.json");
pub const NEGOTIATION_JSON: &str =
    include_str!("../../../tests/vectors/n01_negotiation_vectors.json");

/// Read back through `to_ne_bytes` / `to_be_bytes` / `to_le_bytes`: on a big-endian target the first equals the second.
const PROBE: u64 = 0x0102_0304_0506_0708;
const PLANT_BASE: &str = "N01-GV-001";
const HEADER_BYTES: usize = 64;
const TAG_BYTES: usize = 16;
const FRAME_COUNT_OFFSET: usize = 60;

/// The planted datagrams and the verdict the contract requires of each, written by hand. The rejections are paired
/// with the permitted positives (`untouched`, and `resigned_untouched`, which proves the re-signing below is sound).
const PLANTS: [(&str, &str); 5] = [
    ("untouched", "ACCEPT"),
    ("resigned_untouched", "ACCEPT"),
    ("payload_bit_flipped", "AUTH_FAILED"),
    ("tag_bit_flipped", "AUTH_FAILED"),
    ("frame_count_little_endian_resigned", "FRAME_COUNT_MISMATCH"),
];

pub struct Transcript {
    pub lines: Vec<String>,
    /// Comparisons the replay itself found failing; each is also written as an `N01-MISMATCH` line before `N01-DONE`.
    pub mismatches: u64,
    notes: Vec<String>,
}

impl Transcript {
    fn push(&mut self, line: String) {
        self.lines.push(line);
    }

    fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        if !ok {
            self.mismatches += 1;
            self.notes.push(format!("N01-MISMATCH {}", what()));
        }
    }
}

/// FNV-1a, 64 bit. Checked against the published test vectors by the integration test.
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn nibble(digit: u8) -> Result<u8, String> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        other => Err(format!("`{}` is not a hex digit", char::from(other))),
    }
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() & 1 == 1 {
        return Err("hex text has an odd length".to_string());
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| -> Result<u8, String> { Ok((nibble(pair[0])? << 4) | nibble(pair[1])?) })
        .collect()
}

fn flag(ok: bool) -> &'static str {
    if ok { "ok" } else { "differ" }
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, String> {
    value.get(key).ok_or_else(|| format!("missing `{key}`"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| format!("`{key}` is not text"))
}

fn num(value: &Value, key: &str) -> Result<u64, String> {
    field(value, key)?
        .as_u64()
        .ok_or_else(|| format!("`{key}` is not an unsigned number"))
}

fn small<T: TryFrom<u64>>(value: &Value, key: &str) -> Result<T, String> {
    T::try_from(num(value, key)?).map_err(|_| format!("`{key}` is out of range"))
}

fn list<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    field(value, key)?
        .as_array()
        .ok_or_else(|| format!("`{key}` is not a list"))
}

fn key_bytes(doc: &Value) -> Result<[u8; 32], String> {
    let raw = unhex(text(doc, "key_hex")?)?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| "the key is not 32 bytes".to_string())
}

fn nonce_of(value: &Value, key: &str) -> Result<[u8; 16], String> {
    let raw = unhex(text(value, key)?)?;
    <[u8; 16]>::try_from(raw.as_slice()).map_err(|_| format!("`{key}` is not 16 bytes"))
}

fn stream_id(raw: u64) -> Result<StreamId, String> {
    StreamId::new(raw).map_err(|error| error.to_string())
}

fn packet_of(fields: &Value) -> Result<AuthenticatedStreamPacket, String> {
    Ok(AuthenticatedStreamPacket {
        stream_id: stream_id(num(fields, "stream_id")?)?,
        session_epoch: num(fields, "epoch")?,
        seq: num(fields, "seq")?,
        kind: match text(fields, "kind")? {
            "media" => PacketKind::Media,
            "repair" => PacketKind::Repair,
            other => return Err(format!("unknown packet kind `{other}`")),
        },
        format: StreamFormat::Pcm16BeStereo48k,
        flags: small(fields, "flags")?,
        start_frame: num(fields, "start_frame")?,
        presentation_time_ns: num(fields, "presentation_time_ns")?,
        consume_by_ns: num(fields, "consume_by_ns")?,
        fec_group_id: small(fields, "fec_group_id")?,
        fec_index: small(fields, "fec_index")?,
        fec_group_size: small(fields, "fec_group_size")?,
        payload: unhex(text(fields, "payload_hex")?)?,
    })
}

fn caps_of(value: &Value) -> Result<Capabilities, String> {
    Ok(Capabilities {
        wire_min: small(value, "wire_min")?,
        wire_max: small(value, "wire_max")?,
        formats: small(value, "formats")?,
        max_payload_bytes: small(value, "max_payload_bytes")?,
        mandatory_features: small(value, "mandatory_features")?,
        optional_features: small(value, "optional_features")?,
    })
}

fn guest_line() -> String {
    let endian = if cfg!(target_endian = "big") {
        "big"
    } else {
        "little"
    };
    format!(
        "N01-GUEST v=1 endian={endian} pointer_bits={} probe_native={} probe_be={} probe_le={}",
        usize::BITS,
        hex(&PROBE.to_ne_bytes()),
        hex(&PROBE.to_be_bytes()),
        hex(&PROBE.to_le_bytes())
    )
}

/// One line per wire vector: the real decoder's verdict, whether the decoded fields are the reference's, and whether
/// the real encoder reproduces the datagram byte for byte (MAC included).
fn replay_wire(doc: &Value, out: &mut Transcript) -> Result<u64, String> {
    let key = StreamKey::from_bytes(key_bytes(doc)?);
    let mut count = 0;
    for vector in list(doc, "vectors")? {
        let id = text(vector, "id")?;
        let expect = text(vector, "expect")?;
        let wire = unhex(text(vector, "wire_hex")?)?;
        let fnv = fnv1a64(&wire);
        let (verdict, fields, reencode) =
            match AuthenticatedStreamPacket::decode_and_verify(&wire, &key) {
                Ok(packet) => {
                    let fields = match vector.get("fields") {
                        Some(expected) => flag(packet == packet_of(expected)?),
                        None => "na",
                    };
                    let reencode =
                        flag(packet.encode_signed(&key).is_ok_and(|bytes| bytes == wire));
                    ("ACCEPT".to_string(), fields, reencode)
                }
                Err(error) => (error.code().to_string(), "na", "na"),
            };
        out.check(verdict == expect, || {
            format!("wire vector {id}: wanted {expect}, got {verdict}")
        });
        out.check(fields != "differ" && reencode != "differ", || {
            format!("wire vector {id}: fields={fields} reencode={reencode}")
        });
        out.push(format!(
            "N01-WIRE {id} verdict={verdict} fields={fields} reencode={reencode} fnv={fnv:016x}"
        ));
        count += 1;
    }
    Ok(count)
}

/// One line per scenario: every datagram step goes through a real `StreamReceiver`, and the outcomes of all of them
/// are folded into one fingerprint that the judge recomputes from the hand-written expectations.
fn replay_scenarios(doc: &Value, out: &mut Transcript) -> Result<u64, String> {
    let raw = key_bytes(doc)?;
    let mut count = 0;
    for scenario in list(doc, "scenarios")? {
        let id = text(scenario, "id")?;
        let mut receiver = StreamReceiver::new(
            StreamKey::from_bytes(raw),
            stream_id(num(scenario, "stream_id")?)?,
            num(scenario, "epoch")?,
        );
        let mut got: Vec<String> = Vec::new();
        let mut wanted: Vec<String> = Vec::new();
        for step in list(scenario, "steps")? {
            match text(step, "op")? {
                "advance_epoch" => receiver.advance_epoch(num(step, "epoch")?),
                "bind" => {
                    receiver.bind_stream(stream_id(num(step, "stream_id")?)?, num(step, "epoch")?);
                }
                "datagram" => {
                    let wire = unhex(text(step, "wire_hex")?)?;
                    wanted.push(text(step, "expect")?.to_string());
                    got.push(match receiver.accept(&wire) {
                        Ok(_) => "OK".to_string(),
                        Err(error) => error.code().to_string(),
                    });
                }
                other => return Err(format!("scenario {id}: unknown op `{other}`")),
            }
        }
        let expect_accepted = num(scenario, "expect_accepted")?;
        let counters = receiver.counters();
        let rejected = counters.rejected_structure
            + counters.rejected_unsupported_version
            + counters.rejected_authentication
            + counters.rejected_malformed_fields
            + counters.rejected_wrong_stream
            + counters.rejected_stale_epoch
            + counters.rejected_future_epoch
            + counters.rejected_replay
            + counters.rejected_future_sequence
            + counters.rejected_not_negotiated;
        out.check(
            counters.datagrams_seen == counters.accepted + rejected,
            || format!("scenario {id}: the receiver's counters do not add up"),
        );
        out.check(counters.accepted == expect_accepted, || {
            format!(
                "scenario {id}: accepted {}, wanted {expect_accepted}",
                counters.accepted
            )
        });
        let wrong = got.iter().zip(&wanted).filter(|(a, b)| a != b).count();
        out.check(wrong == 0, || {
            format!("scenario {id}: {wrong} step outcomes differ")
        });
        out.push(format!(
            "N01-SCEN {id} steps={} accepted={} outcomes_fnv={:016x} mismatches={wrong}",
            got.len(),
            counters.accepted,
            fnv1a64(got.join("\n").as_bytes())
        ));
        count += 1;
    }
    Ok(count)
}

enum Negotiated {
    /// offer bytes, answer bytes, transcript digest, selection, sender-to-receiver round trip
    Checks([bool; 5]),
    Refused(String),
}

fn negotiate(psk: &StreamKey, case: &Value) -> Result<Negotiated, String> {
    let stream = stream_id(num(case, "stream_id")?)?;
    let (initiator, offer) = match Initiator::offer(
        psk,
        caps_of(field(case, "sender_caps")?)?,
        num(case, "sender_peer")?,
        stream,
        num(case, "epoch")?,
        nonce_of(case, "offer_nonce_hex")?,
    ) {
        Ok(pair) => pair,
        Err(error) => return Ok(Negotiated::Refused(error.code().to_string())),
    };
    let (responder, answer) = match respond(
        psk,
        caps_of(field(case, "receiver_caps")?)?,
        num(case, "receiver_peer")?,
        num(case, "min_epoch")?,
        nonce_of(case, "answer_nonce_hex")?,
        &offer,
    ) {
        Ok(pair) => pair,
        Err(error) => return Ok(Negotiated::Refused(error.code().to_string())),
    };
    let initiator_session = match initiator.finish(&answer) {
        Ok(session) => session,
        Err(error) => return Ok(Negotiated::Refused(error.code().to_string())),
    };
    let digest = unhex(text(case, "transcript_hex")?)?;
    let wanted = field(case, "selection")?;
    let selection_ok = [&initiator_session, &responder].iter().all(|session| {
        let chosen = session.selection();
        [
            ("wire_version", u64::from(chosen.wire_version)),
            ("format", u64::from(chosen.format)),
            ("max_payload_bytes", u64::from(chosen.max_payload_bytes)),
            ("features", u64::from(chosen.features)),
        ]
        .iter()
        .all(|(key, value)| num(wanted, key).is_ok_and(|expected| expected == *value))
    });
    // The media key is not exposed by the crate, by design. Both ends deriving the same one is checked by using it.
    let roundtrip_ok = match (
        StreamSender::from_negotiated(&initiator_session),
        StreamReceiver::from_negotiated(&responder),
    ) {
        (Ok(mut sender), Ok(mut receiver)) => sender
            .send(OutboundFrame::media(0, 1_000_000, 500_000, vec![0u8; 1024]))
            .is_ok_and(|wire| receiver.accept(&wire).is_ok()),
        _ => false,
    };
    Ok(Negotiated::Checks([
        hex(&offer) == text(case, "offer_hex")?,
        hex(&answer) == text(case, "answer_hex")?,
        initiator_session.transcript_digest().as_slice() == digest.as_slice()
            && responder.transcript_digest().as_slice() == digest.as_slice(),
        selection_ok,
        roundtrip_ok,
    ]))
}

fn replay_negotiations(doc: &Value, out: &mut Transcript) -> Result<u64, String> {
    let raw = key_bytes(doc)?;
    let mut count = 0;
    for case in list(doc, "negotiations")? {
        let id = text(case, "id")?;
        match negotiate(&StreamKey::from_bytes(raw), case)? {
            Negotiated::Checks(checks) => {
                out.check(checks.iter().all(|ok| *ok), || {
                    format!("negotiation {id}: {checks:?}")
                });
                out.push(format!(
                    "N01-NEG {id} offer={} answer={} transcript={} selection={} roundtrip={}",
                    flag(checks[0]),
                    flag(checks[1]),
                    flag(checks[2]),
                    flag(checks[3]),
                    flag(checks[4])
                ));
            }
            Negotiated::Refused(code) => {
                out.check(false, || format!("negotiation {id} was refused: {code}"));
                out.push(format!(
                    "N01-NEG {id} offer=differ answer=differ transcript=differ selection=differ roundtrip=differ"
                ));
            }
        }
        count += 1;
    }
    Ok(count)
}

fn replay_rejections(doc: &Value, out: &mut Transcript) -> Result<u64, String> {
    let raw = key_bytes(doc)?;
    let mut count = 0;
    for case in list(doc, "rejections")? {
        let id = text(case, "id")?;
        let op = text(case, "op")?;
        let expect = text(case, "expect")?;
        let psk = StreamKey::from_bytes(raw);
        let verdict = match op {
            "respond" => {
                let offer = unhex(text(case, "offer_hex")?)?;
                match respond(
                    &psk,
                    caps_of(field(case, "local_caps")?)?,
                    num(case, "local_peer")?,
                    num(case, "min_epoch")?,
                    nonce_of(case, "nonce_hex")?,
                    &offer,
                ) {
                    Ok(_) => "ACCEPT".to_string(),
                    Err(error) => error.code().to_string(),
                }
            }
            "finish" => {
                let (initiator, _) = Initiator::offer(
                    &psk,
                    caps_of(field(case, "sender_caps")?)?,
                    num(case, "sender_peer")?,
                    stream_id(num(case, "stream_id")?)?,
                    num(case, "epoch")?,
                    nonce_of(case, "offer_nonce_hex")?,
                )
                .map_err(|error| format!("{id}: its own offer was refused: {}", error.code()))?;
                match initiator.finish(&unhex(text(case, "answer_hex")?)?) {
                    Ok(_) => "ACCEPT".to_string(),
                    Err(error) => error.code().to_string(),
                }
            }
            other => return Err(format!("{id}: unknown op `{other}`")),
        };
        out.check(verdict == expect, || {
            format!("rejection {id}: wanted {expect}, got {verdict}")
        });
        out.push(format!("N01-NEGREJ {id} op={op} verdict={verdict}"));
        count += 1;
    }
    Ok(count)
}

/// `body || HMAC-SHA256(key, context || body)[..16]`, where `data` is a datagram whose own tag is discarded. Written
/// out here, from the contract, so the planted datagrams do not depend on the code under test to be signed.
fn resign(raw_key: &[u8; 32], context: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let body_len = data
        .len()
        .checked_sub(TAG_BYTES)
        .ok_or("a datagram shorter than its tag")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(raw_key).map_err(|error| error.to_string())?;
    mac.update(context);
    mac.update(&data[..body_len]);
    let full = mac.finalize().into_bytes();
    let mut signed = data[..body_len].to_vec();
    signed.extend_from_slice(&full[..TAG_BYTES]);
    Ok(signed)
}

/// Five datagrams built from one genuine one: a rejection of each kind that does not depend on byte order and one that
/// does, each paired with the permitted positives. The last is authentic (the MAC is valid) and fails on structure
/// alone: its frame count was written the way a little-endian native-struct serializer would write it.
fn replay_plants(doc: &Value, out: &mut Transcript) -> Result<u64, String> {
    let raw = key_bytes(doc)?;
    let key = StreamKey::from_bytes(raw);
    let context = text(field(doc, "constants")?, "auth_context")?.as_bytes();
    let base = list(doc, "vectors")?
        .iter()
        .find(|vector| vector["id"] == PLANT_BASE)
        .ok_or_else(|| format!("the plant base {PLANT_BASE} is not in the vector file"))?;
    let wire = unhex(text(base, "wire_hex")?)?;
    if wire.len() < HEADER_BYTES + TAG_BYTES + 4 {
        return Err(format!("the plant base {PLANT_BASE} is too short"));
    }
    let resigned = resign(&raw, context, &wire)?;
    out.check(resigned == wire, || {
        "re-signing a genuine datagram changed it".to_string()
    });
    let mut payload_flipped = wire.clone();
    payload_flipped[HEADER_BYTES] ^= 0x01;
    let mut tag_flipped = wire.clone();
    let last = tag_flipped.len() - 1;
    tag_flipped[last] ^= 0x01;
    let mut swapped = wire.clone();
    swapped.swap(FRAME_COUNT_OFFSET, FRAME_COUNT_OFFSET + 1);
    let swapped = resign(&raw, context, &swapped)?;
    let datagrams = [wire, resigned, payload_flipped, tag_flipped, swapped];
    for ((name, wanted), datagram) in PLANTS.iter().zip(&datagrams) {
        let verdict = match AuthenticatedStreamPacket::decode_and_verify(datagram, &key) {
            Ok(_) => "ACCEPT".to_string(),
            Err(error) => error.code().to_string(),
        };
        out.check(verdict == *wanted, || {
            format!("planted {name}: wanted {wanted}, got {verdict}")
        });
        out.push(format!("N01-PLANT {name} verdict={verdict}"));
    }
    Ok(PLANTS.len() as u64)
}

/// Replay the two vector documents. `Err` means a document could not be read at all (no `N01-DONE` is produced).
pub fn transcript_of(wire_json: &str, negotiation_json: &str) -> Result<Transcript, String> {
    let wire_doc: Value = serde_json::from_str(wire_json)
        .map_err(|error| format!("the wire vectors do not parse: {error}"))?;
    let negotiation_doc: Value = serde_json::from_str(negotiation_json)
        .map_err(|error| format!("the negotiation vectors do not parse: {error}"))?;
    let mut out = Transcript {
        lines: vec![guest_line()],
        mismatches: 0,
        notes: Vec::new(),
    };
    let wire = replay_wire(&wire_doc, &mut out)?;
    let scenarios = replay_scenarios(&wire_doc, &mut out)?;
    let negotiated = replay_negotiations(&negotiation_doc, &mut out)?;
    let rejections = replay_rejections(&negotiation_doc, &mut out)?;
    let plants = replay_plants(&wire_doc, &mut out)?;
    let notes = std::mem::take(&mut out.notes);
    out.lines.extend(notes);
    out.lines.push(format!(
        "N01-DONE wire={wire} scen={scenarios} neg={negotiated} negrej={rejections} plant={plants} mismatches={}",
        out.mismatches
    ));
    Ok(out)
}

/// The committed vectors.
pub fn transcript() -> Result<Transcript, String> {
    transcript_of(WIRE_JSON, NEGOTIATION_JSON)
}
