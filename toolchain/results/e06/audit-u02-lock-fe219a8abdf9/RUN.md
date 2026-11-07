# E06 audit of the U02 lock (`ed25519-dalek =3.0.0` added by `franken-update`)

`audit.json` here is the E06 audit (`ffw.e06.audit.v1`) of `Cargo.lock` sha256
`fe219a8abdf919c3a14bade5b9ef686c4bbbdbb547435032f94ca451f3a404ba` (72 entries), the lock root resolved for U02 (`ffw-76j`).
It is purely additive over the landed S02 lock (`audit-s02-lock-e2469ade4d83/`, 61 entries): eight packages enter the resolved graph
(`franken-update`, `ed25519-dalek`, `ed25519`, `signature`, `curve25519-dalek`, `subtle`, and the build-time-only `rustc_version` and
`semver`) and three entries are in the lock but in no resolved platform graph (`curve25519-dalek-derive`, `fiat-crypto`, `syn@2.0.119`).
Nothing was removed or moved. This is the current dependency inventory for admission review of the new chain, not a redo of the historic E06, upstream or codec
evidence.

How it was made (a local job: cargo's resolver reads, the compiler's target specs and the cached dependency sources; no build, no RCH,
no test, no clippy), from a directory outside the repository so that rustup picks the nightly and the target specs are captured:

    python3 -I -B scripts/e06/audit.py audit --manifest-path <repo>/Cargo.toml --jobs 2 \
        --unsafe-allowed franken-platform-linux --json audit.json

`cargo 1.101.0-nightly (15be64aa0 2026-10-20)`, `rustc 1.101.0-nightly (48f4b0553 2026-10-23)`, over the working tree at `55fadb2` with
root's uncommitted U02 integration (the lock above, the `franken-update` member, the crate). The analysis host is `aarch64-apple-darwin`;
the two big-endian targets are `mips-unknown-linux-musl` (soft-float) and `powerpc-unknown-linux-musl`. Exit 3 (review items only):
**0 blockers, 23 review items, 54 info**. The target specs read `captured` here (as in `audit-08d5a00266d4/`; the S02 and wall-time audits read `unavailable`), which
adds one review item (`float-on-soft-float`, about the existing workspace float users, not about U02) and replaces the `float-spec-unavailable`
note. `build_checks` reads `planned=34 pass=0 fail=0 not-run=34`: no build result is folded in, and nothing here says any of those
type-checks passes. The tool's own controls ran from the repository on the same checkout, under `RUSTUP_TOOLCHAIN=nightly`:
`python3 -B -W error -m unittest tests.e06.test_audit tests.e06.test_rustscan tests.e06.test_checks` -> 141 tests, OK (the
contamination, unsupported-target and scan controls).

## What is new, by the tool

* Two new `review` items, both `unsafe-in-dependency` on the two big-endian targets (`info` on the host): `curve25519-dalek@5.0.0` (33 unsafe
  tokens) and `subtle@2.6.1` (2). A parent's `forbid(unsafe_code)` (here `ed25519-dalek` and `franken-update`) does not cover either.
* `info`: the `curve25519-dalek` build script (probes the compiler through `rustc_version`; no native signal), three conditionally gated
  dependencies of it (`cpufeatures` on `x86_64`, `curve25519-dalek-derive` on `x86_64` without `serial`/`fiat`, `fiat-crypto` only for
  backend `fiat`; each **inactive** on host, mips and powerpc), the three lock-only entries, and the existing `no-native-atomic64` note for
  both targets (no `AtomicU64` use was found in the dalek, `subtle` or `signature` paths).
* The other review items that name `block-buffer`, `cmov`, `const-oid`, `hybrid-array`, `sha2`, `memchr`, `serde*`, `itoa`, `zmij` are
  carried over from the earlier audits; the new chain only adds what is listed above.

## The new unsafe, read (a person decides; the tool admits nothing)

**`curve25519-dalek 5.0.0`: none of its 33 tokens is compiled on the expected big-endian build.** They sit in `backend/vector/avx2/field.rs`,
`backend/vector/ifma/field.rs`, `backend/vector/packed_simd.rs` and `constants.rs:85`. `backend.rs` compiles `mod vector` only under
`cfg(curve25519_dalek_backend = "simd")`, and `build.rs` selects `simd` only for `target_arch = "x86_64"` with 64-bit pointers; every other
target gets `serial`, with `curve25519_dalek_bits` taken from `target_pointer_width` (32 on PPC/MIPS). The `serial` directory has no
`unsafe`. `constants.rs:85` is the `RISTRETTO_BASEPOINT_TABLE` cast, behind `precomputed-tables`, which `ed25519-dalek`'s `fast` feature would
turn on and this graph does not. `fiat` is reached only by an explicit `--cfg curve25519_dalek_backend="fiat"`; the lock-only entry is not
evidence of it. **Consequence: an x86_64 host build compiles a SIMD-capable backend, while runtime selection depends on CPU features and may
choose Serial.** Neither outcome establishes the 32-bit serial arithmetic used by a PPC/MIPS build. Host vector agreement is therefore not
target arithmetic evidence.

**`subtle 2.6.1`: two unconditional sites, linked on every target.** `lib.rs:225`, `read_volatile(&input)` in `black_box<T: Copy>` (an
owned, live, aligned `Copy` value; `core_hint_black_box` is not enabled), and `lib.rs:564`, a cast of an `i8` that came from a valid
`Ordering` discriminant back to `Ordering` (`#[repr(i8)]`). Both read as sound as commented; neither depends on byte order.

## Features, licences, build facts (all in `audit.json`)

`ed25519-dalek` with default features off still compiles its signing module and exports `SigningKey`; only key generation from an RNG is
feature-gated. U02 verifies and never signs, generates keys or holds a secret (`crates/franken-update/Cargo.toml`, `docs/contracts/u02.md`
section 4). Enabled: `curve25519-dalek` `digest`; `subtle` and `typenum` `const-generics`; `digest` `alloc`, `block-api`, `default`, `mac`,
`oid` and `sha2` `alloc`, `default`, `oid` (the shared workspace `sha2` default), so **no graph-wide no-allocation claim follows**. Not enabled:
`rand_core`, `batch`, `fast`, `precomputed-tables`, `zeroize`, `pkcs8`, `hazmat`, `legacy_compatibility`. The build script needs the host
compiler (`rustc_version`, `semver`, both host-only), no C toolchain. Declared licences: BSD-3-Clause (`curve25519-dalek`, `ed25519-dalek`,
`subtle`), Apache-2.0 OR MIT (`ed25519`, `signature`).

## Not established, and what closes it

No compile, link, run or resource result for the new chain exists in this record. The actual `cfg` and `RUSTFLAGS` of a build are not
observed here: the repository tracks no `.cargo/config*` or `rustflags` that reach `franken-update` (the only tracked one is
`toolchain/src/ffw-hello-init/.cargo/config.toml`, a separate crate), but only the central logs can show that no `curve25519_dalek_backend`
or `curve25519_dalek_bits` override was in force. Still to come, centrally and strictly remote:

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked --release -p franken-update --target mips-unknown-linux-musl -Z build-std=std,panic_abort -j 2
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked --release -p franken-update --target powerpc-unknown-linux-musl -Z build-std=std,panic_abort -j 2

folded in with `scripts/e06/audit.py ingest` (which checks each result against its raw log and writes a redacted record), plus the U02 lint on both
targets and the host positive and negative vectors at the matching bytes (`scripts/e2e/u02 --tier full --judge u02.log`). A worker
reservation refusal is neither a pass nor a crypto failure.
