//! The only place this crate touches a signature primitive. Ed25519 verification is `ed25519-dalek`'s `verify_strict`; nothing here
//! implements curve or field arithmetic, signs, generates a key or holds a secret.
//!
//! `VerifyingKey::from_bytes` follows ZIP-215 and accepts encodings and low-order points that RFC 8032 would not, and `verify_strict` alone
//! does not look at the key's torsion component. So a key is only ever used after [`key_admissible`], which requires that its y coordinate is
//! canonical (below p), that it decodes, that it is not of small order and that it is torsion free (it lies in the prime-order subgroup).
//! `verify_strict` then refuses a non-canonical S, a small-order R or key, and any R that is not byte-for-byte what it recomputes. The same
//! rules are written independently in `tests/u02/ed25519_ref.py`, the oracle that produces the signature and key vectors.

use ed25519_dalek::{Signature, VerifyingKey};

/// Length of a public key and of a signature.
pub const PUBLIC_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// A y coordinate is canonical when the low 255 bits, read little endian, are below p = 2^255 - 19.
fn y_is_canonical(bytes: &[u8; PUBLIC_LEN]) -> bool {
    if bytes[31] & 0x7F != 0x7F {
        return true;
    }
    if bytes[1..31].iter().any(|&b| b != 0xFF) {
        return true;
    }
    bytes[0] < 0xED
}

/// Whether `public` may be put in a trust store: canonical, on the curve, not small order, in the prime-order subgroup.
#[must_use]
pub fn key_admissible(public: &[u8; PUBLIC_LEN]) -> bool {
    if !y_is_canonical(public) {
        return false;
    }
    match VerifyingKey::from_bytes(public) {
        Ok(key) => !key.is_weak() && key.to_edwards().is_torsion_free(),
        Err(_) => false,
    }
}

/// Strict Ed25519 verification of `signature` over `message` under `public`. A `public` that is not [`key_admissible`] is the caller's
/// mistake and is not checked again here.
#[must_use]
pub fn verify(public: &[u8; PUBLIC_LEN], message: &[u8], signature: &[u8]) -> bool {
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}
