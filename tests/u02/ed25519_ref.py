"""Ed25519 (RFC 8032, section 5.1) as an independent TEST ORACLE for the U02 vectors. Standard library only, Python integers.

This is not the verifier the firmware ships: `crates/franken-update/src/sig.rs` calls `ed25519-dalek` (`verify_strict`). This module exists so
that the expected result of every signature and key vector is computed by something that shares no code with that crate, and so that the tests
can build signatures from the RFC's published test keys (``sign``). `tests/u02/test_u02.py` checks it against the RFC 8032 section 7.1 vectors
and, when the `cryptography` module is present, against OpenSSL (signatures byte for byte, verdicts on flipped bits).

Verification here is STRICT, and the rules are the ones `sig.rs` enforces on top of dalek: S must be below the group order L, R and A must be
canonical encodings (y below p) of points on the curve, a public key must lie in the prime-order subgroup (so a small-order or mixed-order key is
refused), and the check is the cofactorless equation [S]B = R + [k]A. Nothing here is constant time; it never touches a secret except in `sign`,
which the tests call with the RFC's published test seeds only.
"""
from __future__ import annotations

import functools
import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# ---------------------------------------------------------------------------------------------- integer reference


def _recover_x(y: int, sign: int):
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x2 = u * pow(v, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def decode_point(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def encode_point(pt) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def point_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = t1 * 2 * D * t2 % P
    dd = z1 * 2 * z2 % P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


IDENTITY = (0, 1, 1, 0)
BASE = decode_point(bytes.fromhex("58" + "66" * 31))


def scalar_mult(k: int, pt):
    q = IDENTITY
    for i in range(k.bit_length() - 1, -1, -1):
        q = point_add(q, q)
        if (k >> i) & 1:
            q = point_add(q, pt)
    return q


def point_eq(a, b) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def is_identity(pt) -> bool:
    return pt[0] % P == 0 and (pt[1] - pt[2]) % P == 0


@functools.lru_cache(maxsize=None)
def key_ok(a_bytes: bytes) -> bool:
    """A public key is admitted only if it decodes canonically and lies in the prime-order subgroup (not the identity)."""
    a = decode_point(a_bytes)
    if a is None or is_identity(a):
        return False
    return is_identity(scalar_mult(L, a))


@functools.lru_cache(maxsize=None)
def verify(a_bytes: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(a_bytes) != 32:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    a = decode_point(a_bytes)
    r = decode_point(sig[:32])
    if a is None or r is None or not key_ok(a_bytes):
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + a_bytes + msg).digest(), "little")
    lhs = scalar_mult(s, BASE)
    rhs = point_add(r, scalar_mult(k, a))
    return point_eq(lhs, rhs)


def public_from_seed(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return encode_point(scalar_mult(a, BASE))


def sign(seed: bytes, msg: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = encode_point(scalar_mult(a, BASE))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % L
    rb = encode_point(scalar_mult(r, BASE))
    k = int.from_bytes(hashlib.sha512(rb + pub + msg).digest(), "little") % L
    s = (r + k * a) % L
    return rb + s.to_bytes(32, "little")
