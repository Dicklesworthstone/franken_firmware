# Bootstrap regression run, 2026-11-04

Both guest transcripts passed after fresh remote RCH builds. These are
freestanding raw-syscall bootstrap probes on Debian QEMU kernels, **not**
musl/std/Asupersync, stock Sonos kernel, audio driver or speaker qualification.
No physical device or provider service was contacted.

From the repository root, with `FFW_BUILD_DIR` explicitly selecting the local
kernel cache (not recorded as a machine-specific default in source):

```sh
python3 toolchain/src/run-qemu-verification.py --skip-build \
  --target-dir toolchain/src/ffw-hello-init/target \
  --results-dir toolchain/results/runs/20261104-2208-isolated-archives
```

The output directory must be new; use another name when reproducing. The two
boot scripts select Malta/24Kf/Linux 4.19 and g3beige/G3/Linux 4.9. Each uses
64 MiB of emulated RAM. This run makes no 32 MiB resource-fit claim.

`e07-e03-verification-receipt.json` binds kernel, binary, archive and raw
stream digests and records QEMU versions, probe results and exit/timeout
status. `boot-*-stdout.bin` and `boot-*-stderr.bin` preserve exact captured
bytes; `boot-*-serial.log` is their concatenated parser view. The archives
are reproducible build products and are intentionally not committed.

Both target builds and both target Clippy checks ran through strict RCH on
worker `trj`, with successful terminal exits and artifact retrieval for the
builds. Commands in the isolated bootstrap crate were:

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker trj --source-content-receipt -- \
  cargo +nightly build --release --target powerpc-unknown-linux-musl \
  -Z build-std=core,panic_abort
RCH_REQUIRE_REMOTE=1 rch exec --worker trj --source-content-receipt -- \
  cargo +nightly clippy --release --target powerpc-unknown-linux-musl \
  -Z build-std=core,panic_abort -- -D warnings
```

The corresponding MIPS commands replace the target with
`mips-unknown-linux-musl`. Worker topology and linker overrides were passed
per invocation; no local compiler fallback was used. Local `rustc`/linker
versions in the boot receipt describe inspection tools only, **not** the
remote compiler. Full compiler pinning and a portable build-provenance
manifest remain open E07 work; this run does not close that bead.

Host checks: `python3 -B -m unittest discover -s toolchain/tests -v` passed
25 tests, including independent newc fixtures for all sixteen alignment
combinations, malformed archives, strict marker parsing, byte-preserving
capture, timeouts, output caps, child failures and existing-output protection.
Touched Python files passed `py_compile`, shell scripts passed `bash -n`, and
the bootstrap source passed `rustfmt --edition 2021 --check`.

Earlier failures were retained in the session/build logs: serial-parser
false positives, RCH topology/linker admission failures, and Clippy string
literal/safety-documentation diagnostics. Successful reruns do not erase
those failures or establish the still-missing stock-kernel capabilities.
