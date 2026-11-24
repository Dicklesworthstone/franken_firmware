# Building FrankenFirmware

This guide supplies the build instructions requested in
[issue #1](https://github.com/Dicklesworthstone/franken_firmware/issues/1).
Start with the host build; the cross-build and QEMU sections are optional.

| Goal | What you build | Additional requirements |
|---|---|---|
| Explore the Rust workspace | Host `franken-speaker` and workspace binaries | Rust 1.99.0, host C linker |
| Run host checks | Rust tests, Virtual House, localhost PCM checks | Python 3.11+; Linux for the process checks |
| Boot the bootstrap probe in QEMU | Two static `no_std` PID-1 executables and initramfs archives | Dated Rust nightly, `rust-src`, QEMU, two public Debian kernels |
| Cross-link the speaker application | Static BE-MIPS and BE-PowerPC `franken-speaker` executables | Dated nightly, `rust-src`, Zig 0.14.1 |

The host and bootstrap paths use public source and dependencies. Sonos images,
`.aa` archives, `anacapad`, private captures, device credentials, and a sibling
`frankensonos` checkout are not prerequisites. QEMU runs generic machines; it
does not emulate the Sonos boards or produce a speaker discoverable on the LAN.

## Reproduction baseline

This guide was checked against source revision
`151f9ca991e71fb18bf64b565ef5730e5f632440`. The recipes pin these inputs:

| Input | Selection | Source of the pin |
|---|---|---|
| Host Rust/Cargo | `1.99.0` | [`rust-toolchain.toml`](../rust-toolchain.toml) |
| Workspace dependencies | Committed `Cargo.lock`, used with `--locked` | [`Cargo.lock`](../Cargo.lock) |
| Asupersync | `36141e21fd2b47cf931e4c131949dfb1b764875e` | [`franken-speaker/Cargo.toml`](../crates/franken-speaker/Cargo.toml) |
| Cross Rust/Cargo | `nightly-2026-08-31` with matching `rust-src` | [`tests/p01/plan.py`](../tests/p01/plan.py) |
| Hosted cross linker | Zig `0.14.1` | [`toolchain/linker/`](../toolchain/linker/) |
| Bootstrap dependencies | Its separate committed lockfile | [`ffw-hello-init/Cargo.lock`](../toolchain/src/ffw-hello-init/Cargo.lock) |
| Guest kernels | Exact Debian package versions and extracted-file SHA-256 below | [Retained E07 receipt](../toolchain/results/runs/1412ac47120d4e5b865f9de6e05f50fe/e07-e03-verification-receipt.json) |

Use an Ubuntu 24.04 x86_64 host or VM for the package commands below. This is a
concrete setup recipe, not a claim that every Ubuntu package combination has
been tested. The process checks require Linux facilities such as
`waitid`/`WNOWAIT`; native Windows and macOS are not covered by that recipe.

Pinning source, compiler and Cargo resolution makes a build repeatable at those
inputs. Byte-identical executables also require the same host toolchain,
environment and flags. The apt packages below are not an immutable container
image. Record their versions when comparing results. QEMU's version and
firmware also affect guest reproduction.

The Cargo examples describe a human-operated build. Automated agents and
maintainer verification must follow [remote verification](#remote-verification)
and [AGENTS.md](../AGENTS.md).

## Host setup

Install the system prerequisites:

```bash
sudo apt-get update
sudo apt-get install --yes build-essential ca-certificates curl git python3
python3 --version
```

Python must be 3.11 or newer (`tomllib` is used by repository tooling). The
documented Python commands use the standard library; there is no pip install
step. The host Cargo build does not require external codec or audio SDKs.

If rustup is not installed, use the [official installer](https://rust-lang.org/install):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
  sh -s -- -y --profile minimal --default-toolchain 1.99.0
. "$HOME/.cargo/env"
```

Install the exact compiler and development components, including when rustup
was already present:

```bash
rustup toolchain install 1.99.0 --profile minimal --component rustfmt --component clippy
rustc +1.99.0 -vV
cargo +1.99.0 -V
```

Clone a fresh directory and select the reference source. The checkout is
detached so a moving `main` does not change this reproduction. To build current
development instead, omit the checkout command and record the resulting SHA.
The reference revision predates this guide; keep the guide open while following it.

```bash
set -euo pipefail
git clone https://github.com/Dicklesworthstone/franken_firmware.git
cd franken_firmware
git checkout --detach 151f9ca991e71fb18bf64b565ef5730e5f632440
FFW_ROOT="$(pwd -P)"
FFW_RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
FFW_LOG_DIR="$FFW_ROOT/build/build-guide-$FFW_RUN_ID"
mkdir -p "$FFW_LOG_DIR"
git rev-parse HEAD > "$FFW_LOG_DIR/source-revision.txt"
git status --short > "$FFW_LOG_DIR/worktree-status.txt"
rustc +1.99.0 -vV > "$FFW_LOG_DIR/rustc-host.txt"
cargo +1.99.0 -V > "$FFW_LOG_DIR/cargo-host.txt"
dpkg-query -W build-essential gcc libc6-dev binutils python3 git > "$FFW_LOG_DIR/host-packages.txt"
sha256sum Cargo.lock > "$FFW_LOG_DIR/host-lock.sha256"
```

Run subsequent blocks from the repository root in this Bash session. Start
with a clean shell without unrelated Cargo target, linker or `RUSTFLAGS`
overrides; user Cargo configuration can change a build. Logs and generated
artifacts stay in the repository's ignored `build/` and `target/` directories.

## Build and inspect the host executable

The first dependency fetch needs access to crates.io and the pinned GitHub
dependency. Cargo fetches Asupersync itself; no sibling clone is needed.

```bash
cargo +1.99.0 fetch --locked 2>&1 | tee "$FFW_LOG_DIR/fetch.log"
cargo +1.99.0 build --locked --workspace --target-dir target \
  2>&1 | tee "$FFW_LOG_DIR/build-host.log"
./target/debug/franken-speaker --catalog > "$FFW_LOG_DIR/catalog.json"
./target/debug/franken-speaker --services
python3 -m json.tool "$FFW_LOG_DIR/catalog.json"
sha256sum target/debug/franken-speaker > "$FFW_LOG_DIR/speaker-host.sha256"
git diff --exit-code -- Cargo.lock
```

The build should exit zero and produce `target/debug/franken-speaker`.
`--catalog` prints the board catalog as JSON. `--services` prints five
`FFW_SERVICE:` lines; default builds report each optional service as `absent`.
These are useful startup checks. `--help` is not implemented at this revision
and exits with usage status 2.

`--locked` refuses to change dependency resolution. After fetching all inputs
on the machine that executes Cargo, add `--offline` to build and test commands
for a network-free replay. `--frozen` combines `--locked` and `--offline`.
See [Cargo's manifest options](https://doc.rust-lang.org/cargo/commands/cargo.html#manifest-options).
An empty cache is not an offline build environment.

For a release executable:

```bash
cargo +1.99.0 build --locked --release --target-dir target \
  -p franken-speaker --bin franken-speaker \
  2>&1 | tee "$FFW_LOG_DIR/build-release.log"
./target/release/franken-speaker --catalog
sha256sum target/release/franken-speaker > "$FFW_LOG_DIR/speaker-release.sha256"
```

The release profile uses size optimization, LTO, one codegen unit, aborting
panics and stripped symbols. This executable is a host userspace program;
building it does not create a flashable firmware image.

### Features and output paths

| Selection | Effect |
|---|---|
| Default `franken-speaker` | Catalog, service reporting and finite-source process modes; default features are empty |
| `harness` | Adds Virtual House and `--self-test`; links the test-support crate |
| `journal-process` | Adds `franken-journal-worker` and its process integration tests |
| `spotify_connect`, `airplay2`, `tailnet_native`, `alexa_bridge`, `artwork` | Select reporting flags; currently report `selected unimplemented unqualified` |

The provider flags do not enable working provider integrations. Use explicit
features for a test rather than interpreting `--all-features` as a complete
speaker product.

The default workspace build also produces `target/debug/ffw-baseline` and
`target/debug/n01_wire_guest`. The journal worker is only built when its
required feature is selected. Explicit `--target-dir target` in the commands
keeps the host output location predictable.

## Host verification

Run formatting, the workspace tests, and Clippy:

```bash
cargo +1.99.0 fmt --all -- --check
cargo +1.99.0 test --locked --workspace --target-dir target \
  --features franken-speaker/harness,franken-speaker/journal-process \
  -- --test-threads=1 2>&1 | tee "$FFW_LOG_DIR/test-host.log"
cargo +1.99.0 clippy --locked --workspace --all-targets --target-dir target \
  --features franken-speaker/harness,franken-speaker/journal-process \
  -- -D warnings 2>&1 | tee "$FFW_LOG_DIR/clippy-host.log"
```

Use each command's exit status and completed test summaries. A partial log,
a build-only check, or a zero-test run is not a passing test suite. These
commands cover workspace members; separate research workspaces under
`toolchain/` and `tests/g03/fsonos-client/` have their own manifests and pins.

For the deterministic Virtual House CLI, explicitly build its feature variant:

```bash
cargo +1.99.0 build --locked --target-dir target \
  -p franken-speaker --bin franken-speaker --features harness
./target/debug/franken-speaker --virtual-house > "$FFW_LOG_DIR/virtual-house.json"
```

Expect a JSON report and exit zero when its gates pass. Rebuilding is necessary:
`cargo test` alone is not a reliable way to refresh an existing top-level
`target/debug/franken-speaker` with different features. Without `harness`,
`--virtual-house` and its alias `--self-test` exit 2.

Two small checks can run before installing Rust or QEMU:

```bash
python3 -B toolchain/src/mkinitramfs.py --self-test
python3 -B scripts/e2e/q00 --tier smoke
```

The first checks archive alignment, deterministic gzip and rejection of
malformed inputs. The second runs the Q00 host simulation controls and checks
their receipts independently; successful completion prints
`Q00 ACCEPTANCE: PASS`. Neither command compiles Rust or boots a guest.

### Localhost source and group checks

These checks run actual child processes using committed audio fixtures and
compare captured PCM to independent references. Build the default speaker
variant first, then pass its executable to the runners:

```bash
cargo +1.99.0 build --locked --target-dir target \
  -p franken-speaker --bin franken-speaker
FFW_PROCESS_RUN="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
scripts/e2e/run-source-loopback \
  --binary "$FFW_ROOT/target/debug/franken-speaker" \
  --output-dir "$FFW_ROOT/build/source-loopback-$FFW_PROCESS_RUN"
scripts/e2e/run-source-group \
  --binary "$FFW_ROOT/target/debug/franken-speaker" \
  --output-dir "$FFW_ROOT/build/source-group-$FFW_PROCESS_RUN"
```

Both runners need a **new** output directory; do not precreate it. Generate a
new `FFW_PROCESS_RUN` when rerunning. They retain the copied binary, its digest,
input fixtures, process logs, captured PCM and `result.json` files. Each
summary (`FFW_SOURCE_LOOPBACK` or `FFW_SOURCE_GROUP`) must account for three
planned cases, three passes and zero failures. The cases include wrong-key
rejection, so checking only positive playback is insufficient.

The runners never invoke Cargo. Their network traffic stays on IPv4 localhost
and their audio output is a file. They do not discover devices, play through a
speaker driver, or establish synchronization between physical speakers.

## QEMU bootstrap

The standalone [`ffw-hello-init`](../toolchain/src/ffw-hello-init/) crate is an
edition-2021 `no_std` PID-1 probe, excluded from the host workspace. It links
without libc, despite the musl target names. This section needs no Zig or
vendor sysroot.

### Install QEMU and the dated cross compiler

On the Ubuntu host:

```bash
sudo apt-get install --yes qemu-system-mips qemu-system-ppc qemu-system-data dpkg file
qemu-system-mips --version | tee "$FFW_LOG_DIR/qemu-mips-version.txt"
qemu-system-ppc --version | tee "$FFW_LOG_DIR/qemu-ppc-version.txt"
dpkg-query -W qemu-system-mips qemu-system-ppc qemu-system-data > "$FFW_LOG_DIR/qemu-packages.txt"
rustup toolchain install nightly-2026-08-31 --profile minimal --component rust-src
rustc +nightly-2026-08-31 -vV > "$FFW_LOG_DIR/rustc-cross.txt"
FFW_RUST_HOST="$(rustc +nightly-2026-08-31 -vV | sed -n 's/^host: //p')"
FFW_RUST_SYSROOT="$(rustc +nightly-2026-08-31 --print sysroot)"
export PATH="$FFW_RUST_SYSROOT/lib/rustlib/$FFW_RUST_HOST/bin:$PATH"
command -v rust-lld
export FFW_BUILD_DIR="$FFW_ROOT/build"
```

Keep QEMU's firmware/data packages installed: g3beige needs OpenBIOS. Retained
[E07 evidence](../toolchain/results/runs/1412ac47120d4e5b865f9de6e05f50fe/e07-e03-verification-receipt.json)
uses QEMU 11.1.2; a distribution package may provide a different version. Match
that emulator and firmware to replay the recorded environment, or retain your
new version and results as a separate run. Installing the apt packages alone
does not claim the historical QEMU version.

These targets use nightly's
[`-Z build-std`](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std)
and matching `rust-src`. A plain `rustup target add` is not the build recipe
for these tier-3 targets. Do not substitute a floating `nightly`.

### Obtain the two guest kernels

The boot scripts expect exact filenames. Download these public packages from
the [Debian archive](https://archive.debian.org/debian/pool/main/l/linux/) and
extract them as data; there is no host package installation or root step:

```bash
mkdir -p "$FFW_BUILD_DIR/kernels"
curl --fail --location --output "$FFW_BUILD_DIR/kernels/mips.deb" \
  'https://archive.debian.org/debian/pool/main/l/linux/linux-image-4.19.0-21-4kc-malta_4.19.249-2_mips.deb'
curl --fail --location --output "$FFW_BUILD_DIR/kernels/powerpc.deb" \
  'https://archive.debian.org/debian/pool/main/l/linux/linux-image-4.9.0-0.bpo.6-powerpc_4.9.88-1+deb9u1~bpo8+1_powerpc.deb'
dpkg-deb --extract "$FFW_BUILD_DIR/kernels/mips.deb" "$FFW_BUILD_DIR/kernels/xm"
dpkg-deb --extract "$FFW_BUILD_DIR/kernels/powerpc.deb" "$FFW_BUILD_DIR/kernels/x"
sha256sum --check <<'KERNELS'
3803357ef7821dbf691c901105fb9b2b00382abf67fce8a4be2a0d592267dc61  build/kernels/xm/boot/vmlinux-4.19.0-21-4kc-malta
289f40b63ea9aa82743f568ddeaba669a16a859970497dccf7135596da538f98  build/kernels/x/boot/vmlinux-4.9.0-0.bpo.6-powerpc
KERNELS
```

Both checksum lines must report `OK`. These hashes identify the **extracted
kernel bytes**, not the `.deb` archives. They come from the retained E07
receipt linked above. Stop on a mismatch; a matching filename is insufficient.
The MIPS package is `mips` (big-endian), not `mipsel`. The actual boot command
uses Linux 4.19.0-21 even though an older comment in `boot-mips.sh` names a
different kernel.

### Build the probes and boot them

Build both targets with the standalone manifest and its explicit linker
configuration:

```bash
for FFW_TARGET in mips-unknown-linux-musl powerpc-unknown-linux-musl; do
  cargo +nightly-2026-08-31 build --locked --release -j 1 \
    --manifest-path toolchain/src/ffw-hello-init/Cargo.toml \
    --config toolchain/src/ffw-hello-init/.cargo/config.toml \
    --target "$FFW_TARGET" \
    --target-dir "$FFW_BUILD_DIR/hello-init-target" \
    -Z build-std=core,panic_abort \
    2>&1 | tee "$FFW_LOG_DIR/build-init-$FFW_TARGET.log"
  file "$FFW_BUILD_DIR/hello-init-target/$FFW_TARGET/release/ffw-hello-init"
  sha256sum "$FFW_BUILD_DIR/hello-init-target/$FFW_TARGET/release/ffw-hello-init" \
    > "$FFW_LOG_DIR/init-$FFW_TARGET.sha256"
done
sha256sum toolchain/src/ffw-hello-init/Cargo.lock > "$FFW_LOG_DIR/bootstrap-lock.sha256"
git diff --exit-code -- toolchain/src/ffw-hello-init/Cargo.lock
```

`--manifest-path` alone does not load a nested `.cargo/config.toml` when Cargo
starts from the repository root; `--config` supplies it explicitly. Both
executables should be static ELF32, MSB (big-endian), for their respective
architectures. The first `build-std` run may fetch additional compiler-library
dependencies; only use `--offline` once those are cached too.

Now package and boot those exact executable paths:

```bash
FFW_QEMU_RUN="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
python3 -B toolchain/src/run-qemu-verification.py \
  --skip-build \
  --target-dir "$FFW_BUILD_DIR/hello-init-target" \
  --results-dir "$FFW_BUILD_DIR/qemu-$FFW_QEMU_RUN" \
  --timeout 60 > "$FFW_LOG_DIR/qemu-$FFW_QEMU_RUN.json"
```

The results directory must be new. The runner creates deterministic initramfs
archives, boots both guests, captures serial output, checks it, and writes
`e07-e03-verification-receipt.json` in that directory. It uses:

| Guest | QEMU machine/CPU | RAM | Kernel console |
|---|---|---|---|
| Big-endian MIPS | `malta` / `24Kf` | 64 MiB | `ttyS0,38400` |
| Big-endian PowerPC | `g3beige` / `G3` | 64 MiB | `ttyPZ0,38400` |

Require exit zero, overall receipt `status: "PASS"`, and `PASS` for both
guests. The serial logs must include the ordered userspace, success and reboot
markers, plus the full compiler, kernel and probe records the runner checks:

```text
FFW_MARKER:USERSPACE_START
FFW_HELLO arch=mips-be endian=0x01020304 pid=1 ptr_bits=32
...
FFW_MARKER:TEST_SUCCESS failures=0
FFW_MARKER:REBOOT_REQUEST
```

The PowerPC hello line uses `arch=powerpc-be`. Inspect `missing_markers`,
`validation_errors`, `forbidden_hits`, `unsupported_capabilities` and
`unseeded_capabilities` in each guest record. An optional syscall reporting
`ENOSYS`, or an unseeded random pool, is recorded separately from a successful
capability. A timeout, kernel panic, or missing userspace marker is a failure.
The complete serial logs are `boot-mips-serial.log` and `boot-ppc-serial.log`.

We build separately because the verifier's internal build path currently
selects floating `cargo +nightly`, does not pass `--locked`, and requires the
maintainer's RCH infrastructure. `--skip-build` only skips compilation; it
still packages, boots and verifies. Its receipt correctly records
`sources_bound_to_binary: false`: retain the separate build logs, source and
lockfile hashes with the boot receipt. That boot receipt is not compiler
attestation. An agent using RCH should also retain its separate build receipt.
The receipt's legacy `build_manifest.toolchain` description still refers to
floating nightly under `--skip-build`; use the guest's `rustc_identity` and
the separately recorded pinned build command to identify the compiler used.

## Cross-link the speaker application

This is a separate step from the `no_std` bootstrap. The speaker uses hosted
Rust `std` and a musl C runtime supplied through the repository's Zig wrappers.
Complete the dated nightly/`rust-src` setup above first. QEMU and its kernels
are only needed if you subsequently boot the result.

Both linker wrappers enforce Zig **exactly 0.14.1**. For the x86_64 Linux host,
install it under ignored `build/`; the checksum below is from Zig's
[official download index](https://ziglang.org/download/index.json):

```bash
sudo apt-get install --yes xz-utils
mkdir -p "$FFW_BUILD_DIR/tools"
curl --fail --location --output "$FFW_BUILD_DIR/tools/zig-0.14.1.tar.xz" \
  'https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz'
sha256sum --check <<'ZIG'
24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c  build/tools/zig-0.14.1.tar.xz
ZIG
tar -xJf "$FFW_BUILD_DIR/tools/zig-0.14.1.tar.xz" -C "$FFW_BUILD_DIR/tools"
export PATH="$FFW_BUILD_DIR/tools/zig-x86_64-linux-0.14.1:$PATH"
zig version
```

Build the default speaker for both targets from the repository root:

```bash
for FFW_TARGET in mips-unknown-linux-musl powerpc-unknown-linux-musl; do
  case "$FFW_TARGET" in
    mips-*) FFW_LINKER=toolchain/linker/zig-cc-mips-be ;;
    powerpc-*) FFW_LINKER=toolchain/linker/zig-cc-powerpc-be ;;
  esac
  cargo +nightly-2026-08-31 build --locked --release -j 1 \
    -p franken-speaker --bin franken-speaker --no-default-features \
    --target "$FFW_TARGET" --target-dir "$FFW_BUILD_DIR/speaker-target" \
    -Z build-std=core,alloc,std,panic_abort \
    --config "target.$FFW_TARGET.linker=\"$FFW_LINKER\"" \
    --config "target.$FFW_TARGET.rustflags=[\"-C\",\"target-feature=+crt-static\",\"-C\",\"link-self-contained=no\"]" \
    2>&1 | tee "$FFW_LOG_DIR/build-speaker-$FFW_TARGET.log"
  file "$FFW_BUILD_DIR/speaker-target/$FFW_TARGET/release/franken-speaker"
  sha256sum "$FFW_BUILD_DIR/speaker-target/$FFW_TARGET/release/franken-speaker"
done
```

The outputs are under `build/speaker-target/<target>/release/franken-speaker`.
Use the matching wrapper: MIPS is big-endian o32 soft-float
(`mips-linux-musleabi`); PowerPC is big-endian 32-bit hard-float
(`powerpc-linux-musleabihf`). A successful link proves neither the target's
physical-board mapping nor compatibility with its stock kernel or drivers.

For a subsequent guest catalog check, see
[the speaker smoke procedure](../toolchain/SPEAKER_SMOKE.md). It needs an
`ffw-hello-init` build with `speaker-smoke`, both speaker binaries and a host
catalog. The default bootstrap built above does not execute a speaker child.
The existing full build plan can be inspected without compiling:

```bash
scripts/e2e/p01 print-plan
```

## Remote verification

Repository agents must use the centralized strict-remote workflow in
[AGENTS.md](../AGENTS.md). For example, a host build submission is:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- \
  cargo +1.99.0 build --locked --workspace -j 1
```

Apply that wrapper to build, test and Clippy commands used for maintainer
verification. Provision the selected compiler, `rust-src` when needed,
dependencies and linkers **on the execution worker**. For cross builds, run
from the repository root so the relative linker scripts are transferred.
Use the worker's returned artifact paths/receipts: RCH can remap target
directories, and a Linux worker executable cannot run directly on a macOS
operator machine.

A clone contains no configured public worker; `.rch/config.toml` is only a
comment. RCH is maintainer execution infrastructure, not a Rust dependency.
If an agent lacks it, report compilation as not run and request the normal
supervisor verification path. Do not disable the shim or use a local fallback.
Python-only checks and inspection remain available.

The broad `scripts/test/run-workspace-verification.py` workflow also includes
cross checks, QEMU and suites that use a sibling Asupersync checkout. It is not
the introductory host build command. Its cross selector can be set with
`FFW_NIGHTLY_TOOLCHAIN=nightly-2026-08-31`; this variable does not override the
separate QEMU verifier's hardcoded `+nightly`.

## Missing research inputs

`captures/`, `.local-real/`, firmware images and toolchain/kernel build
products are intentionally excluded from Git. Public source cannot recreate
private binary captures. They are unrelated to the host and bootstrap builds
above.

For binary-specific research, the currently published
[`image-evidence.json`](../inventory/image-evidence.json) records:

| Input | Recorded identity | Still missing |
|---|---|---|
| Internal model 16 `anacapad` | Firmware line `57.23`, ELF32 big-endian PowerPC; S5 association inferred from product name | Image digest, exact binary provenance, confirmed board/ABI mapping |
| Internal model 12 `anacapad` | Firmware line `57.23`, ELF32 big-endian MIPS | Image digest, mapped live model, ISA revision and ABI |

The live inventory's fuller software version is not proof of the extracted
binary's identity. Historical Ghidra offsets and image-specific observations
need the exact input and digest; this guide cannot fill those missing facts.
See [inventory provenance](../inventory/INVENTORY.md) for the evidence boundary.

## Troubleshooting

| Symptom | Action |
|---|---|
| `cargo` or `rustup` not found | Load `"$HOME/.cargo/env"` after installing rustup; open a new shell if necessary. |
| Host linker `cc` missing | Install `build-essential` on the Linux build machine. |
| `--locked` says the lockfile must change | Check out the matching manifest and lockfile revision. Do not use `cargo update` to conceal a reproduction mismatch. |
| Offline dependency download failure | Populate the cache online on the actual execution machine. Cross `build-std` may need additional sources. |
| `--virtual-house` exits 2 | Explicitly rebuild `franken-speaker` with `--features harness`; then invoke that executable. |
| Provider says `unimplemented unqualified` | This is the implemented selection report, not a build error or a working provider. |
| Result directory already exists | Generate a new run ID and use a new path. Keep the earlier evidence. |
| `-Z` rejected or `core`/`std` missing for the cross target | Select the dated nightly and install its matching `rust-src`; use the documented `build-std` flags. |
| `rust-lld` missing or bootstrap linker errors | Add that nightly's host `lib/rustlib/<host>/bin` to PATH and pass the bootstrap's explicit `--config`. |
| `ffw-linker: zig 0.14.1 required` | Put the pinned Zig installation on the execution machine's PATH. |
| Missing `vmlinux` or PowerPC firmware | Extract the exact Debian package into the required path; verify its hash and retain QEMU's firmware/data packages. |
| `rch` missing or remote admission refused | Maintainer agents need the configured remote runner. The guide's separate build/boot steps explain the human path; do not bypass agent execution policy. |
| Build terminated for resource pressure | Retry with `-j 1`; record any debug/profile overrides as part of the build environment. |

## Verification of this guide

On 2026-11-24, the manifests, feature names, executable paths, command-line
options, kernel identities and dated toolchain selection were checked against
the reference source. The exact Python-only commands above ran with Python
3.12.14: initramfs self-test passed all 16 alignment cases, deterministic gzip
and three negative checks; Q00 smoke passed 21/21 cases with independent
receipt verification and no failed, blocked or unrun cases.

Rust, RCH and QEMU were unavailable in the guide-preparation environment, so
no new Rust build, Rust test run, cross-link or QEMU boot is claimed here.
Retained historical evidence is linked for comparison; your build logs and
guest receipts establish what your selected environment actually executes.
