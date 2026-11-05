#!/bin/sh
# Build franken-dsp for the soft-float MIPS device target as MACHINE CODE, so that toolchain/src/check-softfloat-symbols.py
# can read it.
#
#   softfloat-build.sh rlib|obj OUTDIR
#
# Run it from the repository root, ON THE WORKER, as an `rch exec --job` command (the job path does not sync build outputs
# back; only the declared --result-dir comes back, so OUTDIR must be repository-relative and the same as --result-dir):
#
#   cd <root> && RCH_CANONICAL_PROJECT_ROOT=<root> RCH_REQUIRE_REMOTE=1 rch exec --job --worker trj \
#       --result-dir build/softfloat/rlib -- sh toolchain/src/softfloat-build.sh rlib build/softfloat/rlib
#   cd <root> && RCH_CANONICAL_PROJECT_ROOT=<root> RCH_REQUIRE_REMOTE=1 rch exec --job --worker trj \
#       --result-dir build/softfloat/obj  -- sh toolchain/src/softfloat-build.sh obj  build/softfloat/obj
#
#   rlib: the library as cargo builds it (`.rlib`, an `ar` archive of the crate's objects and rustc metadata).
#   obj : the same build plus `--emit=obj`, which leaves one object file beside the rlib.
#
# Then, from the same root:  python3 -B -I toolchain/src/check-softfloat-symbols.py build/softfloat/rlib/libfranken_dsp-*.rlib
#
# THE DEVIATION FROM THE SHIPPED BUILD, stated here, in MANIFEST.txt and in the checker's verdict: this builds with
# `profile.release.lto="off"`. The root release profile sets `lto = true` (fat LTO), and under it rustc emits LLVM BITCODE for
# both the rlib's members and `--emit=obj` (measured on trj, 2026-11-05, b50: both were bitcode, and the checker refused
# them). Bitcode has no relocations to read, so no soft-float claim can come from it. LTO off is the one change that makes
# rustc write machine code; opt-level (z), codegen-units (1), panic (abort), the build-std set and the rustflags are kept.
# The price: the shipped speaker ELF is fat-LTO'd and may inline across crates differently, so this judges that object,
# not that ELF. Two more settings change NO generated code and are named in the manifest too: `strip` is set to "none" (it
# acts only at link, which this does not run), and `-C symbol-mangling-version=legacy` is added to the rustflags (it changes
# symbol names only; the checker demangles legacy names and refuses v0). On the worker's nightly (1.101.0-nightly 708c94ef0)
# that flag is UNSTABLE: b54 failed in 6 s with "`-C symbol-mangling-version=legacy` requires `-Z unstable-options`", which
# also means legacy is no longer the default and v0 is. So the list carries `-Z unstable-options` ahead of it. This is
# nightly-only and can disappear when legacy mangling does; the checker's refusal of v0 names is the backstop, and its
# root-not-found message counts the mangling kinds it saw.
#
# The artefact is found from cargo's own JSON (`--message-format=json`, the `compiler-artifact` line of franken_dsp), not by
# a path glob: cargo's build-directory layout changed (the new layout has no `release/deps/`; b50 found the files under
# `release/build/<package>/<hash>/out/`), and a glob breaks again on the next change.
#
# Consumer: the two central lines above and check-softfloat-symbols.py. Defect class: a soft-float claim made without
# reading target code. Deletion condition: the nightly guest lane keeps a device object of franken-dsp that a gate reads,
# or the soft-float row of docs/contracts/d02.md closes. It builds nothing but franken-dsp and records, beside the artefact,
# the compiler (`rustc +nightly -vV`), the CARGO_HOME in use, cargo's JSON messages and the SHA-256 of what it kept.
# Flags otherwise follow toolchain/src/measure-d02-cost.py (target, build-std set, --offline, -j 2, the same rustflags).
set -eu

mode=${1:-}
out=${2:-}
case "$mode" in rlib | obj) ;; *) echo "usage: softfloat-build.sh rlib|obj OUTDIR" >&2; exit 2 ;; esac
[ -n "$out" ] || { echo "usage: softfloat-build.sh rlib|obj OUTDIR" >&2; exit 2; }

target=mips-unknown-linux-musl
mkdir -p "$out"

# `rch exec --job` leaves CARGO_HOME unset, so cargo uses the worker's own ~/.cargo, an OLDER cache than the one compile
# mode sets (/scratch/tmp/rch-cargo-cache-<worker>); an --offline build in a job then misses crates that compile mode has
# (measured on trj for a cc pin, 2026-11-05). Use that cache when it is there, unless CARGO_HOME is already set, and
# record which one ran. FFW_RCH_CARGO_CACHE_GLOB overrides where to look (the tests point it at a temporary directory).
cache=
for d in ${FFW_RCH_CARGO_CACHE_GLOB:-/scratch/tmp/rch-cargo-cache-*}; do
    [ -d "$d" ] && cache=$d
done
if [ -z "${CARGO_HOME:-}" ] && [ -n "$cache" ]; then
    CARGO_HOME=$cache
    export CARGO_HOME
fi

rustc +nightly -vV > "$out/rustc-vV.txt"
cargo +nightly -V >> "$out/rustc-vV.txt"
echo "CARGO_HOME: ${CARGO_HOME:-unset (so the worker default, ~/.cargo)}" >> "$out/rustc-vV.txt"

CARGO_TARGET_DIR="$PWD/build/softfloat-target"
export CARGO_TARGET_DIR
cfg="target.$target.rustflags=[\"-C\",\"target-feature=+crt-static\",\"-C\",\"link-self-contained=no\",\"-Z\",\"unstable-options\",\"-C\",\"symbol-mangling-version=legacy\"]"
lto_cfg='profile.release.lto="off"'
strip_cfg='profile.release.strip="none"'
msgs="$out/cargo-messages.jsonl"

if [ "$mode" = rlib ]; then
    cargo +nightly build --offline --release --target "$target" -Z build-std=core,alloc,std,panic_abort \
        --config "$cfg" --config "$lto_cfg" --config "$strip_cfg" -j 2 -p franken-dsp --lib \
        --message-format=json > "$msgs"
else
    cargo +nightly rustc --offline --release --target "$target" -Z build-std=core,alloc,std,panic_abort \
        --config "$cfg" --config "$lto_cfg" --config "$strip_cfg" -j 2 -p franken-dsp --lib \
        --message-format=json -- --emit=obj > "$msgs"
fi

# The last compiler-artifact message of the franken_dsp library, and the .rlib it names.
line=$(grep '"reason":"compiler-artifact"' "$msgs" | grep '"name":"franken_dsp"' | tail -n 1 || true)
rlib=$(printf '%s\n' "$line" | sed -n 's/.*"filenames":\[\([^]]*\)\].*/\1/p' | tr ',' '\n' | tr -d '"' | grep '\.rlib$' | head -n 1 || true)
if [ -z "$rlib" ] || [ ! -f "$rlib" ]; then
    echo "softfloat-build: cargo reported no franken_dsp rlib that exists (artifact line: ${line:-none}; messages in $msgs)" >&2
    exit 3
fi

if [ "$mode" = rlib ]; then
    artifact=$rlib
else
    # rustc writes the --emit=obj file next to the rlib, under the same hash.
    base=${rlib##*/}
    hash=${base#libfranken_dsp-}
    hash=${hash%.rlib}
    artifact="${rlib%/*}/franken_dsp-$hash.o"
    if [ ! -f "$artifact" ]; then
        echo "softfloat-build: no object $artifact beside the rlib cargo reported" >&2
        exit 3
    fi
fi
cp "$artifact" "$out/"
name=${artifact##*/}

{
    echo "mode: $mode"
    echo "target: $target"
    echo "artifact: $name"
    echo "artifact-found-at: $artifact"
    echo "found-by: cargo --message-format=json (compiler-artifact of franken_dsp), not by a path glob"
    echo "deviation: lto=off. The shipped speaker ELF is built with lto = true (fat LTO) and strip = \"symbols\"; this object was built with $lto_cfg because under lto = true rustc emits LLVM bitcode for the rlib and for --emit=obj, which has no relocations to read. The shipped ELF is fat-LTO'd and may inline differently."
    echo "deviation: strip=none ($strip_cfg). It acts only at link, which is not run; no code-generation effect."
    echo "deviation: symbol-mangling-version=legacy (-C flag in the rustflags, with -Z unstable-options ahead of it: the flag is UNSTABLE, nightly-only, on this toolchain). It changes symbol NAMES only, so that the checker can demangle them (it does not read v0 names); no code-generation effect."
    echo "cargo-config: $lto_cfg $strip_cfg $cfg"
    echo "files: 1"
    if command -v sha256sum > /dev/null 2>&1; then
        (cd "$out" && sha256sum "$name" cargo-messages.jsonl)
    else
        (cd "$out" && shasum -a 256 "$name" cargo-messages.jsonl)
    fi
} > "$out/MANIFEST.txt"
cat "$out/MANIFEST.txt"
