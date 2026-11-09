//! T01-X02 phase `CRYPTO_KAT` (ffw-32a, assignment 15376, DarkPeak): known-answer tests of the cryptography the pinned tailscale-rs core
//! crates call, run inside the probe on the target.
//!
//! Why it exists. The probe's `noise_ik` phase runs a random-ephemeral handshake and asserts that both ends agree. Two ends that share
//! the same byte-order fault agree with each other, so that check cannot see a big-endian bug in X25519, BLAKE2s, HKDF or
//! ChaCha20-Poly1305. A known answer can: it compares what the crates produce with fixed expected bytes.
//!
//! What is exercised, and where the pinned code (tailscale-rs `d34658bb`, v0.6.1) calls it. Every primitive is driven through the same
//! crate and the same API shape as the cited line, not through a different library:
//!
//! * X25519: `x25519_dalek::StaticSecret::diffie_hellman` (`ts_noise/src/core.rs:119`), reached here through `ts_keys`
//!   (`NodePublicKey::from_bytes` `ts_keys/src/macros.rs:53`, `to_x25519_dalek` `:44` and `:150`, `public_key` `:132`, and
//!   `Export::from_bytes` / `import` `ts_keys/src/lib.rs:75` / `:70`).
//! * ChaCha20-Poly1305: `ChaCha20Poly1305::new` (`core.rs:24`), `encrypt_in_place_detached` (`core.rs:206`) and
//!   `decrypt_in_place_detached` (`core.rs:230`); the same cipher carries the transport (`ts_tunnel/src/session.rs:166,224,318`) and
//!   the control channel (`ts_control_noise/src/codec.rs:87`).
//! * XChaCha20-Poly1305: `ts_tunnel/src/macs.rs:8` and `:103` (cookie replies).
//! * BLAKE2s-256: `Blake2s256::digest` (`core.rs:71`) and `new_with_prefix` / `update` / `finalize_into` (`core.rs:87-91`);
//!   `ts_tunnel/src/macs.rs:35-45` (MAC keys).
//! * Keyed BLAKE2s MAC: `Blake2sMac<U16>` (`ts_tunnel/src/macs.rs:18,79,139`).
//! * HKDF over BLAKE2s-256: `SimpleHkdf::<Blake2s256>` (`core.rs:33-35`).
//! * The Noise IK handshake, in the call order of `ts_noise/src/ik.rs:119-126` (initiator), `:72-77` (responder), `:37-44` (responder
//!   opens) and `:147-153` (initiator finishes), through the public `ts_noise::core::State`.
//!
//! Where each expected value comes from (recorded per vector in the constants below):
//! * PUBLISHED: RFC 7748 section 5.2 and 6.1; RFC 8439 section 2.8.2; RFC 7693 appendix B (appendix A is BLAKE2b, not BLAKE2s);
//!   draft-irtf-cfrg-xchacha-03 appendix A.3.1; the BLAKE2 reference `blake2s-kat.txt` keyed entry 0; and the two Noise IK packets the
//!   tailscale-rs authors put in `ik.rs:186-187` after checking them against the third-party `noise-protocol` crate.
//! * DERIVED: values with no published table (BLAKE2s of the empty string and of longer inputs, the keyed MAC, HKDF over BLAKE2s, and
//!   the Noise session keys) come from CPython's `hashlib` / `hmac` and from an independent Python model of the ts_noise call order. That
//!   model reproduces both published Noise packets byte for byte, which is what ties the derived session keys to the real code.
//!
//! Not exercised: `crypto_box` (NaCl box, `ts_keys` and `ts_packet`), the Noise transport nonce layouts of `ts_tunnel` and
//! `ts_control_noise` (they sit behind packet types outside the seven crates), the 1000- and 1000000-iteration X25519 results (too slow
//! on an emulated guest), HKDF-SHA256, and WireGuard interoperability. A pass proves these primitives and this call order are
//! byte-correct on the target. It does not prove a tunnel, a Tailscale protocol exchange or any fit.
//!
//! Self-check. `run_kat` also flips one byte of one expected value in a copy of the table and requires the verdict to name exactly that
//! vector (`plant=caught`), so a comparison that can no longer fail cannot print `ok`. The unflipped table is the control.

use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, XChaCha20Poly1305};
use hkdf::SimpleHkdf;
use ts_keys::{Export, NodePrivateKey, NodePublicKey};
use ts_noise::core::{Role, State};

type Mac16 = Blake2sMac<chacha20poly1305::consts::U16>;
type Mac32 = Blake2sMac<chacha20poly1305::consts::U32>;

// ---- X25519: RFC 7748 section 5.2 (test vectors) and section 6.1 (Diffie-Hellman example) ----
const X25519_V1_SCALAR: &str = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
const X25519_V1_U: &str = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
const X25519_V1_OUT: &str = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
const X25519_V2_SCALAR: &str = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";
// the top bit of this u-coordinate is set: the implementation must mask it
const X25519_V2_U: &str = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
const X25519_V2_OUT: &str = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";
// section 5.2 iteration: k = u = 9, after one iteration (the 1000 and 1000000 iteration results are not run)
const X25519_NINE: &str = "0900000000000000000000000000000000000000000000000000000000000000";
const X25519_ITER1_OUT: &str = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079";
const X25519_ALICE_PRIV: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const X25519_ALICE_PUB: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const X25519_BOB_PRIV: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const X25519_BOB_PUB: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const X25519_SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

// ---- ChaCha20-Poly1305: RFC 8439 section 2.8.2; XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 appendix A.3.1 ----
const AEAD_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const AEAD_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
const CHACHA_NONCE: &str = "070000004041424344454647";
// ciphertext (114 bytes) then the 16-byte tag
const CHACHA_SEALED: &str = concat!(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
    "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060",
    "0691",
);
const XCHACHA_NONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
// ciphertext (114 bytes) then the 16-byte tag
const XCHACHA_SEALED: &str = concat!(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
    "21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780a",
    "cf49",
);
/// The plaintext of both AEAD vectors, as printed in RFC 8439 section 2.8.2.
const AEAD_PLAINTEXT: &str = concat!(
    "Ladies and Gentlemen of the class of '99: ",
    "If I could offer you only one tip for the future, ",
    "sunscreen would be it.",
);

// ---- BLAKE2s: RFC 7693 appendix B; BLAKE2 reference blake2s-kat.txt; the rest derived ----
// RFC 7693 appendix B: BLAKE2s-256("abc")
const BLAKE2S_ABC: &str = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
// derived, CPython hashlib
const BLAKE2S_EMPTY: &str = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";
// derived, CPython hashlib: input 00 01 .. ff (four blocks)
const BLAKE2S_SEQ256: &str = "5fdeb59f681d975f52c8e69c5502e02a12a3afcc5836ba58f42784c439228781";
// derived, CPython hashlib: prefix 00..1f, then two updates of 100 and 200 bytes
const BLAKE2S_PREFIXED: &str = "faad4ddf6edcc94c14fcad2bcf3877c0a6a919a89edf072826c7bd5747922808";
// BLAKE2 reference blake2s-kat.txt, keyed entry 0: key 00..1f, empty input, 32-byte digest
const BLAKE2S_KEYED_KAT0: &str = "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49";
const MAC1_PEER_PUBLIC: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
// derived, CPython hashlib: WireGuard-style mac1 = Blake2sMac<U16>(BLAKE2s-256("mac1----" || peer), 116-byte packet)
const BLAKE2S_MAC16: &str = "47ad980296e60a66095b0fef8b92863d";
/// The label `ts_tunnel/src/macs.rs:14` prefixes to the peer key.
const MAC1_LABEL: &[u8] = b"mac1----";

// ---- HKDF over BLAKE2s-256: derived (the model is validated on RFC 5869 appendix A.1; there is no published BLAKE2s vector) ----
const HKDF_SALT: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const HKDF_IKM: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const HKDF_2X32: &str = concat!(
    "6a96444e20e8d4c1cee974416acae1c10b3c92886010e54ed94dafb2c3b80ea0",
    "57af120b0de7acbe7907ec149c5ae870a2dbb74232b65777ba4123f1f7f888f5",
);
const HKDF_3X32: &str = concat!(
    "6a96444e20e8d4c1cee974416acae1c10b3c92886010e54ed94dafb2c3b80ea0",
    "57af120b0de7acbe7907ec149c5ae870a2dbb74232b65777ba4123f1f7f888f5",
    "0926c7caabb6e8d73beda759e6f4f0d324ce5b5000bcf8cd784b26db3049faa9",
);
const HKDF_EMPTY_IKM_2X32: &str = concat!(
    "7a38c34bf2b8738d7374ca77c44ecb309a11d2b2528304fa86052c365e722624",
    "1a17621f346abdc520746a9fb64d8eb03231d674fc15687537b0780fd9c060fd",
);

// ---- Noise IK (ts_noise/src/ik.rs test_handshake, lines 167-220): the two packets are the tailscale-rs authors' reference values ----
// ik.rs:186 expected_init_packet (96 bytes), checked by its authors against the third-party noise-protocol crate
const NOISE_INIT_PACKET: &str = concat!(
    "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254",
    "ad5b8febedeb97415be53612205e6bfab385e34cb127dd8854c4f9afb10f9b0e",
    "49075a6f14f9d5bc61412f096ae4950589aef8286944be93ca02ab76a5483b51",
);
// ik.rs:187 expected_resp_packet (48 bytes), same provenance
const NOISE_RESP_PACKET: &str = concat!(
    "675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f",
    "5ef5508032efff8066fc858410f411e8",
);
// X25519 of private key 00 01 .. 1f against the base point (derived)
const NOISE_STATIC_PUB: &str = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
// derived, independent Python model of the ts_noise call order; no published value exists
const NOISE_SESSION_I2R: &str = "1ffa520b7b784b83355f4ca5754d333f51f53ff31d9d98f697c22e8f79b66e22";
const NOISE_SESSION_R2I: &str = "1657d025486888648386e46e37e6722a42c605d3f1b0ec24454190a645355089";
/// The prologue of `ik.rs:182`.
const NOISE_PROLOGUE: &[u8] = b"TEST HANDSHAKE";
/// The protocol name of `ik.rs:14`.
const NOISE_PROTOCOL: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

// ---- the table ----------------------------------------------------------------------------------------------------------------------

/// The vector whose expected value the self-check flips.
const PLANT_ID: &str = "rfc7748_6_1_shared_ab";

const FAMILIES: usize = 6;

/// The facts key of each family, in the order of [`Family`].
const FAMILY_KEYS: [&str; FAMILIES] = [
    "x25519",
    "chacha20poly1305",
    "xchacha20poly1305",
    "blake2s",
    "hkdf_blake2s",
    "noise_ik",
];

/// How many vectors each family has. A table that lost or gained one prints `fail`, never a smaller `ok`.
const FAMILY_COUNTS: [usize; FAMILIES] = [7, 4, 2, 6, 3, 8];

#[derive(Clone, Copy)]
enum Family {
    Dh,
    Chacha,
    Xchacha,
    Blake2s,
    Hkdf,
    Noise,
}

/// One known-answer check: what the crates produced and what the reference says. An empty `actual` means the primitive refused;
/// a `None` expected value means its hex did not decode. Neither can pass.
#[derive(Clone)]
struct Case {
    id: &'static str,
    family: Family,
    actual: Vec<u8>,
    expected: Option<Vec<u8>>,
}

impl Case {
    fn hex(id: &'static str, family: Family, actual: Vec<u8>, expected: &str) -> Self {
        Self {
            id,
            family,
            actual,
            expected: unhex(expected),
        }
    }

    fn raw(id: &'static str, family: Family, actual: Vec<u8>, expected: &[u8]) -> Self {
        let expected = if expected.is_empty() {
            None
        } else {
            Some(expected.to_vec())
        };
        Self {
            id,
            family,
            actual,
            expected,
        }
    }

    fn matches(&self) -> bool {
        match &self.expected {
            Some(expected) => !self.actual.is_empty() && *expected == self.actual,
            None => false,
        }
    }
}

struct Verdict {
    passed: [usize; FAMILIES],
    total: [usize; FAMILIES],
    failed: usize,
    first_failed: Option<&'static str>,
}

fn judge(cases: &[Case]) -> Verdict {
    let mut verdict = Verdict {
        passed: [0; FAMILIES],
        total: [0; FAMILIES],
        failed: 0,
        first_failed: None,
    };
    for case in cases {
        let slot = case.family as usize;
        verdict.total[slot] += 1;
        if case.matches() {
            verdict.passed[slot] += 1;
        } else {
            verdict.failed += 1;
            if verdict.first_failed.is_none() {
                verdict.first_failed = Some(case.id);
            }
        }
    }
    verdict
}

/// Flip one bit of the first expected byte of the case called `id`. False when there is no such case or it has no expected bytes.
fn plant(cases: &mut [Case], id: &str) -> bool {
    for case in cases.iter_mut() {
        if case.id == id {
            if let Some(first) = case.expected.as_mut().and_then(|bytes| bytes.first_mut()) {
                *first ^= 0x01;
                return true;
            }
            return false;
        }
    }
    false
}

/// The comparison must be able to fail: with one expected byte flipped, the verdict names that vector and no other.
fn plant_is_caught(cases: &[Case]) -> bool {
    let mut planted = cases.to_vec();
    if !plant(&mut planted, PLANT_ID) {
        return false;
    }
    let verdict = judge(&planted);
    verdict.failed == 1 && verdict.first_failed == Some(PLANT_ID)
}

fn facts(verdict: &Verdict) -> String {
    let mut text = String::new();
    for (index, key) in FAMILY_KEYS.iter().enumerate() {
        text.push_str(&format!(
            "{key}={}/{} ",
            verdict.passed[index], verdict.total[index]
        ));
    }
    text.push_str("plant=caught");
    text
}

/// The phase, in the type `main.rs` gives every phase (`crate::PhaseResult = Result<String, String>`). `Ok` carries the facts for
/// `T01X02 PHASE CRYPTO_KAT ok <facts>`. `Err` is itself a facts string the judge accepts: `reason=<id of the first failing vector>`, or
/// `reason=case_count` / `reason=plant_not_caught`, printed as `T01X02 PHASE CRYPTO_KAT fail reason=<id>`.
pub fn run_kat() -> crate::PhaseResult {
    judge_table(&build_cases())
}

/// The verdict of a table as a phase result. Split from [`run_kat`] so a test can hand it a table with a planted fault.
fn judge_table(cases: &[Case]) -> crate::PhaseResult {
    let verdict = judge(cases);
    if let Some(id) = verdict.first_failed {
        return Err(format!("reason={id}"));
    }
    if verdict.total != FAMILY_COUNTS {
        return Err(String::from("reason=case_count"));
    }
    if !plant_is_caught(cases) {
        return Err(String::from("reason=plant_not_caught"));
    }
    Ok(facts(&verdict))
}

fn build_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    cases.extend(x25519_cases());
    cases.extend(chacha_cases());
    cases.extend(xchacha_cases());
    cases.extend(blake2s_cases());
    cases.extend(hkdf_cases());
    cases.extend(noise_cases());
    cases
}

// ---- small helpers ------------------------------------------------------------------------------------------------------------------

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Lower-case hex to bytes; `None` for an empty string, an odd length or any other character.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    if out.is_empty() || out.len() * 2 != bytes.len() {
        return None;
    }
    Some(out)
}

fn arr<const N: usize>(text: &str) -> Option<[u8; N]> {
    unhex(text)?.try_into().ok()
}

fn flag(value: bool) -> Vec<u8> {
    vec![u8::from(value)]
}

/// 32 bytes counting up from `first`.
fn key_run(first: u8) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = first.wrapping_add(index as u8);
    }
    out
}

// ---- X25519 -------------------------------------------------------------------------------------------------------------------------

/// `scalar * u` through the same `x25519_dalek` call `ts_noise/src/core.rs:119` makes. An undecodable input gives an empty result.
fn dh(scalar_hex: &str, u_hex: &str) -> Vec<u8> {
    let (Some(scalar), Some(u)) = (arr::<32>(scalar_hex), arr::<32>(u_hex)) else {
        return Vec::new();
    };
    let secret = Export::<NodePrivateKey>::from_bytes(scalar)
        .import()
        .to_x25519_dalek();
    let public = NodePublicKey::from_bytes(u).to_x25519_dalek();
    secret.diffie_hellman(&public).to_bytes().to_vec()
}

/// The public key of a private key (`scalar * 9`) through `ts_keys`' own `public_key`.
fn base_public(scalar_hex: &str) -> Vec<u8> {
    let Some(scalar) = arr::<32>(scalar_hex) else {
        return Vec::new();
    };
    let private = Export::<NodePrivateKey>::from_bytes(scalar).import();
    private.public_key().to_x25519_dalek().to_bytes().to_vec()
}

fn x25519_cases() -> Vec<Case> {
    let dh_family = Family::Dh;
    vec![
        Case::hex(
            "rfc7748_5_2_v1",
            dh_family,
            dh(X25519_V1_SCALAR, X25519_V1_U),
            X25519_V1_OUT,
        ),
        Case::hex(
            "rfc7748_5_2_v2",
            dh_family,
            dh(X25519_V2_SCALAR, X25519_V2_U),
            X25519_V2_OUT,
        ),
        Case::hex(
            "rfc7748_5_2_iter1",
            dh_family,
            dh(X25519_NINE, X25519_NINE),
            X25519_ITER1_OUT,
        ),
        Case::hex(
            "rfc7748_6_1_alice_pub",
            dh_family,
            base_public(X25519_ALICE_PRIV),
            X25519_ALICE_PUB,
        ),
        Case::hex(
            "rfc7748_6_1_bob_pub",
            dh_family,
            base_public(X25519_BOB_PRIV),
            X25519_BOB_PUB,
        ),
        Case::hex(
            "rfc7748_6_1_shared_ab",
            dh_family,
            dh(X25519_ALICE_PRIV, X25519_BOB_PUB),
            X25519_SHARED,
        ),
        Case::hex(
            "rfc7748_6_1_shared_ba",
            dh_family,
            dh(X25519_BOB_PRIV, X25519_ALICE_PUB),
            X25519_SHARED,
        ),
    ]
}

// ---- ChaCha20-Poly1305 and XChaCha20-Poly1305 ----------------------------------------------------------------------------------------

/// Ciphertext followed by the tag, through `encrypt_in_place_detached` as `ts_noise/src/core.rs:206` calls it. Empty on refusal.
fn chacha_seal(key: [u8; 32], nonce: [u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&key.into());
    let mut buffer = plain.to_vec();
    match cipher.encrypt_in_place_detached(&nonce.into(), aad, &mut buffer) {
        Ok(tag) => {
            buffer.extend_from_slice(tag.as_slice());
            buffer
        }
        Err(_) => Vec::new(),
    }
}

/// The plaintext, through `decrypt_in_place_detached` as `core.rs:230` calls it; `None` when authentication fails.
fn chacha_open(key: [u8; 32], nonce: [u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let split = sealed.len().checked_sub(16)?;
    let (body, tag_bytes) = sealed.split_at(split);
    let tag: [u8; 16] = tag_bytes.try_into().ok()?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    let mut buffer = body.to_vec();
    cipher
        .decrypt_in_place_detached(&nonce.into(), aad, &mut buffer, &tag.into())
        .ok()?;
    Some(buffer)
}

fn xchacha_seal(key: [u8; 32], nonce: [u8; 24], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&key.into());
    let mut buffer = plain.to_vec();
    match cipher.encrypt_in_place_detached(&nonce.into(), aad, &mut buffer) {
        Ok(tag) => {
            buffer.extend_from_slice(tag.as_slice());
            buffer
        }
        Err(_) => Vec::new(),
    }
}

fn xchacha_open(key: [u8; 32], nonce: [u8; 24], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let split = sealed.len().checked_sub(16)?;
    let (body, tag_bytes) = sealed.split_at(split);
    let tag: [u8; 16] = tag_bytes.try_into().ok()?;
    let cipher = XChaCha20Poly1305::new(&key.into());
    let mut buffer = body.to_vec();
    cipher
        .decrypt_in_place_detached(&nonce.into(), aad, &mut buffer, &tag.into())
        .ok()?;
    Some(buffer)
}

fn chacha_cases() -> Vec<Case> {
    let key = arr::<32>(AEAD_KEY).unwrap_or([0; 32]);
    let nonce = arr::<12>(CHACHA_NONCE).unwrap_or([0; 12]);
    let aad = unhex(AEAD_AAD).unwrap_or_default();
    let plain = AEAD_PLAINTEXT.as_bytes();
    let sealed = chacha_seal(key, nonce, &aad, plain);
    let opened = chacha_open(key, nonce, &aad, &sealed).unwrap_or_default();

    let mut damaged_tag = sealed.clone();
    if let Some(last) = damaged_tag.last_mut() {
        *last ^= 0x01;
    }
    let mut damaged_aad = aad.clone();
    if let Some(first) = damaged_aad.first_mut() {
        *first ^= 0x01;
    }
    let tag_accepted = chacha_open(key, nonce, &aad, &damaged_tag).is_some();
    let aad_accepted = chacha_open(key, nonce, &damaged_aad, &sealed).is_some();

    let family = Family::Chacha;
    vec![
        Case::hex("rfc8439_2_8_2_seal", family, sealed, CHACHA_SEALED),
        Case::raw("rfc8439_2_8_2_open", family, opened, plain),
        Case::hex(
            "rfc8439_2_8_2_tag_flip_rejected",
            family,
            flag(tag_accepted),
            "00",
        ),
        Case::hex(
            "rfc8439_2_8_2_aad_flip_rejected",
            family,
            flag(aad_accepted),
            "00",
        ),
    ]
}

fn xchacha_cases() -> Vec<Case> {
    let key = arr::<32>(AEAD_KEY).unwrap_or([0; 32]);
    let nonce = arr::<24>(XCHACHA_NONCE).unwrap_or([0; 24]);
    let aad = unhex(AEAD_AAD).unwrap_or_default();
    let plain = AEAD_PLAINTEXT.as_bytes();
    let sealed = xchacha_seal(key, nonce, &aad, plain);
    let opened = xchacha_open(key, nonce, &aad, &sealed).unwrap_or_default();

    let family = Family::Xchacha;
    vec![
        Case::hex("xchacha_a_3_1_seal", family, sealed, XCHACHA_SEALED),
        Case::raw("xchacha_a_3_1_open", family, opened, plain),
    ]
}

// ---- BLAKE2s ------------------------------------------------------------------------------------------------------------------------

/// `Blake2s256::digest`, the call of `ts_noise/src/core.rs:71`.
fn blake2s_digest(data: &[u8]) -> Vec<u8> {
    Blake2s256::digest(data).to_vec()
}

/// `new_with_prefix` then two updates, the shape of `core.rs:87-91`.
fn blake2s_prefixed(prefix: &[u8], first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s256::new_with_prefix(prefix);
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().to_vec()
}

/// Keyed BLAKE2s with a 32-byte digest, built as `ts_tunnel/src/macs.rs:79` builds its 16-byte one.
fn mac32(key: [u8; 32], data: &[u8]) -> Vec<u8> {
    let mut mac: Mac32 = blake2::digest::Mac::new(&key.into());
    blake2::digest::Mac::update(&mut mac, data);
    blake2::digest::Mac::finalize(mac).into_bytes().to_vec()
}

fn mac16(key: [u8; 32], data: &[u8]) -> Vec<u8> {
    let mut mac: Mac16 = blake2::digest::Mac::new(&key.into());
    blake2::digest::Mac::update(&mut mac, data);
    blake2::digest::Mac::finalize(mac).into_bytes().to_vec()
}

/// The mac1 of `ts_tunnel/src/macs.rs:35-39` and `:79-81`: `Blake2sMac<U16>` keyed with `BLAKE2s-256("mac1----" || peer)`.
fn wireguard_mac1(peer_public: &[u8], packet: &[u8]) -> Vec<u8> {
    let mut key_hash = Blake2s256::new_with_prefix(MAC1_LABEL);
    key_hash.update(peer_public);
    let key: [u8; 32] = key_hash.finalize().into();
    mac16(key, packet)
}

fn blake2s_cases() -> Vec<Case> {
    let sequence: Vec<u8> = (0..=255_u8).collect();
    let prefix: Vec<u8> = (0..32_u8).collect();
    let first: Vec<u8> = (0..100_u32).map(|i| ((7 * i + 1) & 0xff) as u8).collect();
    let second: Vec<u8> = (0..200_u32).map(|i| ((11 * i + 5) & 0xff) as u8).collect();
    let packet: Vec<u8> = (0..116_u32).map(|i| ((5 * i + 3) & 0xff) as u8).collect();
    let peer = unhex(MAC1_PEER_PUBLIC).unwrap_or_default();
    let reference_key = key_run(0);

    let family = Family::Blake2s;
    vec![
        Case::hex("rfc7693_b_abc", family, blake2s_digest(b"abc"), BLAKE2S_ABC),
        Case::hex("blake2s_empty", family, blake2s_digest(b""), BLAKE2S_EMPTY),
        Case::hex(
            "blake2s_seq256",
            family,
            blake2s_digest(&sequence),
            BLAKE2S_SEQ256,
        ),
        Case::hex(
            "blake2s_prefixed",
            family,
            blake2s_prefixed(&prefix, &first, &second),
            BLAKE2S_PREFIXED,
        ),
        Case::hex(
            "blake2_kat_keyed_entry0",
            family,
            mac32(reference_key, b""),
            BLAKE2S_KEYED_KAT0,
        ),
        Case::hex(
            "blake2s_mac16_mac1",
            family,
            wireguard_mac1(&peer, &packet),
            BLAKE2S_MAC16,
        ),
    ]
}

// ---- HKDF over BLAKE2s-256 ----------------------------------------------------------------------------------------------------------

/// `SimpleHkdf::<Blake2s256>` with the salt as the chaining key and empty `info`, the call of `ts_noise/src/core.rs:33-35`.
fn hkdf_blake2s(salt: &[u8], ikm: &[u8], len: usize) -> Vec<u8> {
    let kdf = SimpleHkdf::<Blake2s256>::new(Some(salt), ikm);
    let mut out = vec![0_u8; len];
    match kdf.expand(&[], &mut out) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

fn hkdf_cases() -> Vec<Case> {
    let salt = unhex(HKDF_SALT).unwrap_or_default();
    let ikm = unhex(HKDF_IKM).unwrap_or_default();
    let family = Family::Hkdf;
    vec![
        Case::hex(
            "hkdf_blake2s_2x32",
            family,
            hkdf_blake2s(&salt, &ikm, 64),
            HKDF_2X32,
        ),
        Case::hex(
            "hkdf_blake2s_3x32",
            family,
            hkdf_blake2s(&salt, &ikm, 96),
            HKDF_3X32,
        ),
        Case::hex(
            "hkdf_blake2s_empty_ikm",
            family,
            hkdf_blake2s(&salt, &[], 64),
            HKDF_EMPTY_IKM_2X32,
        ),
    ]
}

// ---- Noise IK -----------------------------------------------------------------------------------------------------------------------

fn private_key(first: u8) -> NodePrivateKey {
    Export::<NodePrivateKey>::from_bytes(key_run(first)).import()
}

/// The initiator of `ts_noise/src/ik.rs:119-126`: the 96-byte first message and the handshake state after it.
fn initiator_first(
    init_static: &NodePrivateKey,
    init_ephemeral: &NodePrivateKey,
    resp_static_pub: &NodePublicKey,
) -> (Vec<u8>, State) {
    let ephemeral_pub = init_ephemeral.public_key().to_x25519_dalek().to_bytes();
    let mut static_ct = init_static.public_key().to_x25519_dalek().to_bytes();
    let mut static_tag = [0_u8; 16];
    let mut payload_tag = [0_u8; 16];
    let peer = resp_static_pub.to_x25519_dalek();
    let peer_bytes = peer.to_bytes();
    let state = State::new(NOISE_PROTOCOL)
        .mix_hash(NOISE_PROLOGUE)
        .mix_hash(&peer_bytes)
        .mix_hash(&ephemeral_pub)
        .mix_dh(&init_ephemeral.to_x25519_dalek(), &peer)
        .seal(&mut static_ct, &mut static_tag)
        .mix_dh(&init_static.to_x25519_dalek(), &peer)
        .seal(&mut [], &mut payload_tag);
    let mut packet = Vec::with_capacity(96);
    packet.extend_from_slice(&ephemeral_pub);
    packet.extend_from_slice(&static_ct);
    packet.extend_from_slice(&static_tag);
    packet.extend_from_slice(&payload_tag);
    (packet, state)
}

/// The responder of `ik.rs:37-44`: decrypt the sender's static key and authenticate the payload tag. `None` when either tag fails.
fn responder_open(packet: &[u8], resp_static: &NodePrivateKey) -> Option<[u8; 32]> {
    let ephemeral: [u8; 32] = packet.get(0..32)?.try_into().ok()?;
    let mut static_ct: [u8; 32] = packet.get(32..64)?.try_into().ok()?;
    let static_tag: [u8; 16] = packet.get(64..80)?.try_into().ok()?;
    let payload_tag: [u8; 16] = packet.get(80..96)?.try_into().ok()?;
    let secret = resp_static.to_x25519_dalek();
    let own_public = resp_static.public_key().to_x25519_dalek().to_bytes();
    let peer_ephemeral = NodePublicKey::from_bytes(ephemeral).to_x25519_dalek();
    let state = State::new(NOISE_PROTOCOL)
        .mix_hash(NOISE_PROLOGUE)
        .mix_hash(&own_public)
        .mix_hash(&ephemeral)
        .mix_dh(&secret, &peer_ephemeral)
        .open(&mut static_ct, &static_tag)?;
    let peer_static = NodePublicKey::from_bytes(static_ct).to_x25519_dalek();
    state
        .mix_dh(&secret, &peer_static)
        .open(&mut [], &payload_tag)
        .map(|_| static_ct)
}

/// What the responder sends back and the two session keys it derives (`ik.rs:72-77`).
struct Reply {
    packet: Vec<u8>,
    initiator_to_responder: Vec<u8>,
    responder_to_initiator: Vec<u8>,
}

fn responder_reply(
    state: State,
    resp_ephemeral: &NodePrivateKey,
    init_ephemeral_pub: &NodePublicKey,
    init_static_pub: &NodePublicKey,
) -> Reply {
    let ephemeral_pub = resp_ephemeral.public_key().to_x25519_dalek().to_bytes();
    let secret = resp_ephemeral.to_x25519_dalek();
    let mut tag = [0_u8; 16];
    let session = state
        .mix_hash(&ephemeral_pub)
        .mix_dh(&secret, &init_ephemeral_pub.to_x25519_dalek())
        .mix_dh(&secret, &init_static_pub.to_x25519_dalek())
        .seal(&mut [], &mut tag)
        .finish(Role::Responder);
    let mut packet = Vec::with_capacity(48);
    packet.extend_from_slice(&ephemeral_pub);
    packet.extend_from_slice(&tag);
    Reply {
        packet,
        initiator_to_responder: session.initiator_to_responder.as_slice().to_vec(),
        responder_to_initiator: session.responder_to_initiator.as_slice().to_vec(),
    }
}

/// The initiator finishing (`ik.rs:147-153`): authenticate the reply and derive the two session keys. `None` when the tag fails.
fn initiator_finish(
    state: State,
    init_ephemeral: &NodePrivateKey,
    init_static: &NodePrivateKey,
    reply: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let ephemeral: [u8; 32] = reply.get(0..32)?.try_into().ok()?;
    let tag: [u8; 16] = reply.get(32..48)?.try_into().ok()?;
    let peer_ephemeral = NodePublicKey::from_bytes(ephemeral).to_x25519_dalek();
    let session = state
        .mix_hash(&ephemeral)
        .mix_dh(&init_ephemeral.to_x25519_dalek(), &peer_ephemeral)
        .mix_dh(&init_static.to_x25519_dalek(), &peer_ephemeral)
        .open(&mut [], &tag)?
        .finish(Role::Initiator);
    Some((
        session.initiator_to_responder.as_slice().to_vec(),
        session.responder_to_initiator.as_slice().to_vec(),
    ))
}

fn noise_cases() -> Vec<Case> {
    let init_static = private_key(0);
    let init_ephemeral = private_key(32);
    let resp_static = private_key(64);
    let resp_ephemeral = private_key(96);
    let init_static_pub = init_static.public_key();
    let init_ephemeral_pub = init_ephemeral.public_key();
    let resp_static_pub = resp_static.public_key();

    let (first, state) = initiator_first(&init_static, &init_ephemeral, &resp_static_pub);
    let reply = responder_reply(
        state.clone(),
        &resp_ephemeral,
        &init_ephemeral_pub,
        &init_static_pub,
    );
    let finished = initiator_finish(state, &init_ephemeral, &init_static, &reply.packet);
    let (initiator_i2r, initiator_r2i) = finished.unwrap_or_default();

    let opened = responder_open(&first, &resp_static);
    let recovered = opened.map(|key| key.to_vec()).unwrap_or_default();
    let mut damaged = first.clone();
    if let Some(byte) = damaged.get_mut(64) {
        *byte ^= 0x01;
    }
    let tampered = responder_open(&damaged, &resp_static).is_some();

    let mut responder_keys = reply.initiator_to_responder.clone();
    responder_keys.extend_from_slice(&reply.responder_to_initiator);
    let expected_keys = format!("{NOISE_SESSION_I2R}{NOISE_SESSION_R2I}");

    let family = Family::Noise;
    vec![
        Case::hex("noise_ik_init_packet", family, first, NOISE_INIT_PACKET),
        Case::hex(
            "noise_ik_resp_packet",
            family,
            reply.packet,
            NOISE_RESP_PACKET,
        ),
        Case::hex(
            "noise_ik_open_static_pub",
            family,
            recovered,
            NOISE_STATIC_PUB,
        ),
        Case::hex(
            "noise_ik_open_accepts",
            family,
            flag(opened.is_some()),
            "01",
        ),
        Case::hex(
            "noise_ik_open_tamper_rejected",
            family,
            flag(tampered),
            "00",
        ),
        Case::hex(
            "noise_ik_session_i2r",
            family,
            initiator_i2r,
            NOISE_SESSION_I2R,
        ),
        Case::hex(
            "noise_ik_session_r2i",
            family,
            initiator_r2i,
            NOISE_SESSION_R2I,
        ),
        Case::hex(
            "noise_ik_session_responder",
            family,
            responder_keys,
            &expected_keys,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_vector_passes_and_the_table_has_the_expected_shape() {
        let cases = build_cases();
        let verdict = judge(&cases);
        assert_eq!(verdict.first_failed, None);
        assert_eq!(verdict.failed, 0);
        assert_eq!(verdict.total, FAMILY_COUNTS);
        assert_eq!(verdict.passed, FAMILY_COUNTS);
        assert!(cases.iter().all(|case| case.expected.is_some()));
    }

    #[test]
    fn vector_ids_are_unique_lowercase_words() {
        let cases = build_cases();
        let mut ids: Vec<&str> = cases.iter().map(|case| case.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), cases.len());
        for id in ids {
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            );
        }
    }

    #[test]
    fn one_flipped_expected_byte_names_that_vector_and_no_other() {
        let cases = build_cases();
        for case in &cases {
            let mut planted = cases.clone();
            assert!(plant(&mut planted, case.id), "{}", case.id);
            let verdict = judge(&planted);
            assert_eq!(verdict.failed, 1, "{}", case.id);
            assert_eq!(verdict.first_failed, Some(case.id));
        }
    }

    #[test]
    fn an_undecodable_expected_value_and_an_empty_actual_both_fail() {
        let bad_hex = Case::hex("bad_hex", Family::Hkdf, vec![1], "zz");
        let empty = Case::hex("empty_actual", Family::Hkdf, Vec::new(), "01");
        assert!(!bad_hex.matches());
        assert!(!empty.matches());
    }

    #[test]
    fn the_phase_is_ok_and_its_facts_follow_the_judge_grammar() {
        let facts = run_kat().expect("every vector passes");
        assert!(facts.ends_with("plant=caught"));
        assert!(crate::facts_well_formed(&facts), "{facts}");
        let mut keys = Vec::new();
        for token in facts.split(' ') {
            let (key, value) = token.split_once('=').expect("key=value");
            assert!(key.as_bytes()[0].is_ascii_lowercase());
            assert!(
                key.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            );
            assert!(!value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic() && b != b'='));
            keys.push(key);
        }
        let before = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), before);
        assert!(facts.starts_with("x25519=7/7 chacha20poly1305=4/4 xchacha20poly1305=2/2 "));
    }

    #[test]
    fn a_planted_fault_fails_the_phase_with_a_judge_valid_reason() {
        let cases = build_cases();
        for case in &cases {
            let mut planted = cases.clone();
            assert!(plant(&mut planted, case.id), "{}", case.id);
            let reason = judge_table(&planted).expect_err("a flipped expected byte must fail");
            assert_eq!(reason, format!("reason={}", case.id));
            assert!(crate::facts_well_formed(&reason), "{reason}");
        }
    }

    #[test]
    fn a_table_that_lost_a_vector_fails_with_case_count() {
        let mut cases = build_cases();
        cases.pop();
        let outcome = judge_table(&cases);
        assert_eq!(outcome, Err(String::from("reason=case_count")));
        assert!(crate::facts_well_formed("reason=case_count"));
    }
}
