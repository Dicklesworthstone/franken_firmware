# N07: real finite-source fanout to localhost receiver groups — 2026-11-12

The executable now feeds multiple receiver processes from one decoded source.
It uses the existing bounded carrier and source owner, with a common stream
epoch, sample positions and admitted host presentation anchor. This is an
actual localhost process run, with PCM files as its sink. It is not physical
speaker, distributed-clock, retained-radio or native-provider qualification.

Feature commit: `9b288ca7135a0896345f9ebac18e84f2e46d32ea`.
Baseline `ad8c5b26fb8d52c78bc94b8608c74ba820216080` plus six frozen overlays
formed immutable inventory
`123835711f414130531f5457eba3528ab18dc961fa888eed7b7bb2ee06a1b1c2`.
Root independently compared all 1,597 input hashes, lengths and executable
masks and their read-only state, then every one of the 1,595 transferred
receipt entries. The only excluded inputs were two `.beads` metadata files.
The six source-overlay hashes are in [source-inputs.json](source-inputs.json).

## Observed positive behavior and planted negative

| Actual case | Healthy receivers | Complete frames per healthy receiver | Independent PCM error |
|---|---:|---:|---|
| Vorbis two-member group | 2 | 24,000 | peak 1 LSB; RMS 0.0458711965 LSB |
| Long MP3 three-member group | 3 | 72,000 | peak 1 LSB; RMS 0.0457954389 LSB |
| Wrong-key third member | 2 | 24,000 | peak 1 LSB; RMS 0.0458711965 LSB |

Every healthy capture passed full independent scalar PCM, exact frame count,
position and presentation-time assertions, including the partial final block.
Capture bytes were also identical across healthy members of each group.
The wrong-key member actually read and rejected **16** media packets at the
authentication boundary, accepted none and captured zero PCM. It provided no
accepted feedback. The source still published the complete 24,000 frames to
the healthy members, then exited nonzero with a per-peer **summary**, not a
clean completion, because the failed member could not drain. The bounded
wrong-key timeout is expected negative behavior, not a hidden failed run.

Original per-sample tolerances and references were unchanged. Both old and
new process campaigns used the same actual prebuilt executable hash
`ddfb250e868ea039daca43950a1045a25f3ff018ed938eba5c52038afd233e67`.
This hash was observed by the actual runner; artifact retrieval selected zero
files. No local binary or raw per-case temporary capture is claimed to have
been retrieved. Their comparison results and capture hashes remain in the
actual stdout summaries in [observed.txt](observed.txt), which is explicitly
an excerpt, and the machine-readable JSON. These are executed test results,
not synthetic fixtures presented as an external service or hardware run.

## Commands and exact denominators

CyanPike ran the centralized strict-remote batch with Rust 1.99, locked,
offline, default features and `-j1`. The logical source commands below are
shown before RCH's source/target remapping and injected source-identity config.
The exact executed-command hashes and complete private-log hashes are in the
JSON. `RCH_REQUIRE_REMOTE=1` prohibited local fallback. The existing authorized
20 GiB dispatcher floor exception remained; remote reservation floors and
global worker/shim settings were unchanged.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- \
  cargo +1.99.0 test --locked --offline -j1 -p franken-speaker \
  --bin franken-speaker --test source_runtime_cli --test source_group_cli \
  -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- \
  cargo +1.99.0 clippy --locked --offline -j1 -p franken-speaker \
  --all-targets -- -D warnings
```

The host check environment included `CARGO_INCREMENTAL=0`, zero dev/test debug
information and `RUSTFLAGS='-D warnings -C debuginfo=0'`.

- Native `30106308287922178`: **15/15 Rust tests**, zero failed, ignored or
  filtered: 10 CLI unit tests, three group integration tests, two unchanged
  single-peer integration tests. One group wrapper contains three actual
  group cases and one old wrapper contains three actual single-peer cases;
  those are **not six additional Rust tests**.
- Native `30106308287922180`: actual strict all-target speaker Clippy exit
  zero, warnings denied. Root independently checked both terminal ACKs,
  returned status and source/staging/pair release and tree retirement.
- `python3 -B tests/source_runtime/test_group_oracle.py -v`: **5/5** unit
  controls, independently re-executed. They admit full reference captures and
  reject a missing/aliased member, missing tail, shifted timestamp, differing
  in-tolerance member sample and missing/duplicate/inactive peer diagnostics.
  These synthetic controls are not additional audio-process runs.
- Both touched Rust files pass Rustfmt; both new Python scripts pass
  `python3 -m py_compile`; the shell entry point passes `bash -n`; private-index
  `git diff --cached --check` passes. The unrelated 818-test suite was not rerun.

Independent focused source reviews were IvoryCarp for the CLI and Rust process
controls and YellowRabbit for the Python group oracle. Root read every changed
source/test and the actual native output. Original single-peer tests, fixtures,
thresholds and helper were retained unchanged. No suppression, golden refresh,
retry expansion or requirement reduction was used to pass the new campaign.

## Reproduction and remaining acceptance

With an already centrally built executable for the machine running it:

```sh
scripts/e2e/run-source-group --binary target/debug/franken-speaker \
  --output-dir build/source-group-new-run
```

The output directory must be new; the runner never invokes Cargo, discovers
peers or touches a speaker. It retains each created process's bounded logs,
owned input/capture and result files. `--peers` uses explicit
`ID@127.0.0.1:MEDIA_PORT@127.0.0.1:CONTROL_PORT` entries; receiver `--peer-id`
must match. IDs, endpoint aliases and the existing eight-peer interface cap
are validated before source/sockets. Eight is an admission cap, not an
observed eight-member performance result.

N07's original retained-network ownership, link/address/resolver behavior,
full congestion/recovery campaign and physical-radio requirements remain
open. The tracker refused the full N07 claim because E04/P03/N02 are still
unresolved; dependencies and acceptance were not changed to bypass that.
This component uses an explicitly provisioned host fixture mapping and does
not connect finite distributed output grants, SOAP group control, protected
HAL output or native service sessions. Those are still real integration gaps,
not capabilities established by this process check. No Bead is closed here.
