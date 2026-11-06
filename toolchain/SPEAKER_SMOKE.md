# franken-speaker QEMU smoke (E07 runner change)

**Status.** The guest-side code passed centrally (commit `376039d`): hello-init lib tests, the `speaker-smoke` build for both
triples, clippy with no warnings, and the feature-off A/B, which is byte-identical to the committed E07 digests. The smoke
itself has one committed result: `toolchain/results/runs/22637af083874c1a8c2204a7620838e2/` (2026-11-05), both guests PASS.
The device speakers in that run were built from `1688a75` (MIPS `476a2d1c…`, PowerPC `f05bcbc6…`) and judged against that
revision's host catalog (FNV-1a64 `920a91647ae4af73`); hello-init was built from this file's commit, with the console-level
step below. The command was the one under Command plus `--target-dir`; all six controls were caught. The E07 digests
committed earlier describe the hello-init before the console-level change; this run's receipt carries the new ones
(speaker-smoke builds only; no feature-off digest was taken).

A pass would show a linked, static `franken-speaker` starting as a userspace process under the E07 guests (MIPS Malta, Linux
4.19; PowerPC g3beige, Linux 4.9) and printing the catalog the Rust source defines. It would not show anything about Sonos
silicon, the float ABI (the catalog has no floats), networking, audio, timing or memory pressure.

## Command

`FFW_BUILD_DIR` (the Debian guest-kernel cache, not in the repo) must be set in the environment.

```sh
RCH_WORKER=ts1,hz3,hz4 python3 toolchain/src/run-qemu-verification.py --timeout 60 --jobs 2 \
  --speaker-mips build/p01-target/mips-unknown-linux-musl/release/franken-speaker \
  --speaker-ppc  build/p01-target/powerpc-unknown-linux-musl/release/franken-speaker \
  --speaker-host-catalog host-catalog.json --speaker-controls
```

`python3 toolchain/src/run-qemu-verification.py --check-catalog host-catalog.json` judges the HOST build's `--catalog` output
alone; run it first. It validates the checker (including its SHA-256 replication) before a guest is held to it.

Before **each** guest build the runner takes a fresh capacity sample (`rch workers capabilities --refresh --json`) and asks
`rch admit --json -- <that exact cargo argv>` (read-only) with the build's own environment and directory; it builds only on
`offload`/`observed` from a worker in the requested set (`RCH_WORKERS` or `RCH_WORKER`) or `queue`/`observed`/`all_workers_busy`
(rch's own queued wait). After 8 tries, 15 s apart, it stops with `AdmissionRefused` naming the guest and the last answer, and builds
nothing. Back-to-back builds used to meet `RCH-I001` on the second guest. The receipt's `build_admission` keeps the recommendation,
observation, worker id and reason, never a host address; `--skip-build` asks for nothing.

## Markers (fixed before any run)

```
...every existing E07/E03 line, unchanged...
FFW_SPEAKER_BEGIN path=/franken-speaker argv=--catalog
<the child's stdout: the pretty-printed catalog>
FFW_SPEAKER_EXIT status=0 stdout_bytes=<N> stdout_fnv1a64=<16 hex>
FFW_MARKER:TEST_SUCCESS failures=0
FFW_MARKER:REBOOT_REQUEST
```

The only success form is status 0 with at least one byte of stdout. Every other form is a named failure
(`speaker_failed:<the guest's words>`). The console text between BEGIN and EXIT must match the guest's own count and FNV, and
must be the catalog the Rust source defines (`speaker_expect.py` parses the nine rows out of `canonical_board_catalog()`).
Without the speaker flags any `FFW_SPEAKER_*` line fails the guest.

**Console quiet (every guest run, with or without the speaker flags).** `hello-init`'s first action is
`klogctl(SYSLOG_ACTION_CONSOLE_LEVEL, NULL, 1)`, so only `KERN_EMERG` reaches the serial console and a kernel `printk`
cannot land inside a marker; one did on the first PowerPC smoke (`FFW_MARKER:TEST_SUCCESS fai[ ... random: crng init done`
then `lures=0`). The guest prints `FFW_GUEST:CONSOLE_LEVEL status=PASS rc=0` after `USERSPACE_START`; the verifier requires
that exact line, names a refused call (`console_level_refused:<what the kernel answered>`), and stays strict about partial
lines on purpose. The line is guest setup, not an E03 capability probe, so it never reaches the capability matrix.

## Controls (`--speaker-controls`)

One extra boot each, from the same hello-init binary. Each must fail for exactly the planted reason, and only counts if the
unplanted run of that guest passed.

| plant | the guest must print | errno |
|---|---|---|
| no `/franken-speaker` | `FFW_SPEAKER_EXIT spawn=exec errno=2` | ENOENT |
| mode 0644 | `FFW_SPEAKER_EXIT spawn=exec errno=13` | EACCES |
| the other ISA's speaker | `FFW_SPEAKER_EXIT spawn=exec errno=8` | ENOEXEC |

## Platform step (P02 `ffw-jub`): `--speaker-platform`

**Status.** Written and tested on the host against synthetic transcripts and the committed marker examples; **no guest has run
it.** It needs the device `franken-speaker` that carries the platform layer (built centrally from the P01 plan after
`device.patch` lands): a host build has no kernel backend, exits 2 and prints no markers. A pass would show what the harness
guest's kernel answered to the platform layer's clock, entropy and wake probes in one start of the device speaker. It would not
show anything about Sonos silicon, a stock kernel, what a board's `kernel=` string is, or whether an unseeded pool later seeds.

### Command

The command under Command above, plus the two flags. The guests are then built with the `speaker-platform` feature (which
implies `speaker-smoke`) into their own default target directory, `hello-init-platform-target`:

```sh
RCH_WORKER=ts1,hz3,hz4 python3 toolchain/src/run-qemu-verification.py --timeout 60 --jobs 2 \
  --speaker-mips <MIPS device speaker with the platform layer> \
  --speaker-ppc  <PowerPC device speaker with the platform layer> \
  --speaker-host-catalog host-catalog.json --speaker-platform --platform-controls
```

### Markers (fixed before any run)

```
...the catalog step above, unchanged...
FFW_PLATFORM_STEP_BEGIN path=/franken-speaker argv=--platform-startup
FFW_PLATFORM:BEGIN abi=<mips32|powerpc32> evidence=<harness-mips-4.19|harness-ppc-4.9> backend=kernel kernel=<release>
FFW_PLATFORM:KERNEL status=PASS
FFW_PLATFORM:CLOCK status=PASS provenance=kernel
FFW_PLATFORM:ENTROPY status=PASS provenance=kernel
FFW_PLATFORM:WAKE status=PASS provenance=kernel mechanism=eventfd
FFW_PLATFORM:END started=1
FFW_PLATFORM_STEP_EXIT status=0 stdout_bytes=<N> stdout_fnv1a64=<16 hex>
FFW_MARKER:TEST_SUCCESS failures=0
```

The six `FFW_PLATFORM:*` lines are the speaker's. Their grammar is in `docs/contracts/p02.md` and
`crates/franken-speaker/tests/vectors/p02_platform_markers.json`, which the judge reads (the receipt records its SHA-256). The two
`FFW_PLATFORM_STEP_*` lines are the guest's, with their own names so the catalog step's lines and digests are untouched. The
guest accepts exit status 0 (started) and 3 (refused) as "the step ran"; every other form is `platform_step_failed:<the guest's
words>`. The console text between the two wrapper lines must match the guest's own byte count and FNV-1a-64. Without
`--speaker-platform`, any `FFW_PLATFORM*` line is an unknown marker and fails the guest.

### Verdicts (`toolchain/src/platform_expect.py`)

| verdict | what it is | the run |
|---|---|---|
| green | KERNEL, CLOCK, ENTROPY and WAKE all `PASS` with `provenance=kernel`; `backend=kernel`; the guest's own ABI and evidence names; `END started=1`; exit 0 | passes |
| degraded | MIPS only: `ENTROPY` `REFUSED provenance=kernel reason=not_seeded`, `END started=0 refused=entropy:not_seeded`, exit 3, the other three `PASS`. E03's own verdict for an unseeded pool: neither green nor red | passes; the receipt says `degraded` in `platform_step.verdicts` and it is not green |
| red | everything else, each with a named problem (below) | fails the guest |

Red problems are named, never a bare failure: `platform_value:<LINE>:<key>=<value>` (a value outside the closed set, for example
`provenance=double`), `platform_fields:`, `platform_malformed:`, `platform_missing:<LINE>`, `platform_duplicate:<LINE>`,
`platform_order:<LINE>`, `platform_truncated:after:<LINE>`, `platform_after_end`, `platform_simulated:<LINE>`,
`platform_backend_simulated`, `platform_abi:`, `platform_not_run_unexplained:<LINE>`, `platform_ran_after_kernel_refusal:<LINE>`,
`platform_end_disagrees:`, `platform_exit_status_disagrees:`, `platform_stdout_mismatch:`, `platform_outside_step`, and
`platform_not_started:<capability>:<reason>` for a well-formed refusal that does not show the positive path. The `kernel=` value is
recorded and never compared. The degraded cell is exactly one cell (`DEGRADED` in `platform_expect.py`): `not_seeded` on PowerPC,
or any other refusal on either guest, is red.

### Controls (`--platform-controls`)

No extra boot. Each plant is the guest's OWN transcript changed in one way and re-sealed (the step's byte count and FNV are
recomputed over the changed bytes), so the only fault is the plant. It counts only against an unplanted run of the same guest that
was not red, and only if the verifier reports exactly the named problem and nothing else.

| plant | the verifier must report exactly |
|---|---|
| the CLOCK line says `provenance=double` (not a value of the grammar) | `platform_value:CLOCK:provenance=double` |
| the CLOCK line says `provenance=simulated` (the value a test double prints) | `platform_simulated:CLOCK` |
| the BEGIN line says `backend=simulated` with every capability still passing | `platform_backend_simulated` |
| the ENTROPY line is missing | `platform_missing:ENTROPY` |
| the run stops after the CLOCK line | `platform_truncated:after:CLOCK` |

### The explicit legacy provider (`--entropy-provider legacy-dev-random-test-environment`)

With `--speaker-platform --entropy-provider legacy-dev-random-test-environment` the guests are built with one more feature
(`speaker-platform-legacy-test-env`, target directory `hello-init-platform-legacy-target`), the child gets one more argument
(`--entropy-provider=legacy-dev-random-test-environment`, printed on the BEGIN line), and the judge holds the run to what
`docs/contracts/p02.md` ("The legacy provider") says: the ENTROPY line, and only it, carries `provider=legacy_dev_random_test_environment`
between `provenance=` and `reason=` on PASS, REFUSED and NOT_RUN alike. The default run is untouched: it still rejects the token
(`platform_fields:ENTROPY:...`), and a provider run rejects its absence (`platform_provider_missing:ENTROPY`), so neither passes as the other.

| run | verdict |
|---|---|
| `ENTROPY PASS` with the provider, `END started=1`, exit 0 | green: the real adapter read a credited pool in a harness guest. Not a device or stock-kernel claim |
| `ENTROPY REFUSED ... reason=not_seeded` with the provider, `END started=0`, exit 3, the other three `PASS` | degraded on **both** guests: no seeded `/dev/random` read has been observed in any guest, so a pool that has not credited yet is the information, and it shows no positive |
| any other reason (`absent` = no `/dev/random` node, `unavailable`, `failed`, ...), a wrong or unknown `provider=` value, a missing token | red, each named (`platform_not_started:entropy:<reason>`, `platform_value:ENTROPY:provider=<v>`, `platform_provider_missing:ENTROPY`) |

Plants (`--platform-controls` adds these to the five above): the token removed, `provider=legacy_dev_random`, `provider=urandom`.
The runner also refuses a provider run when one of the two boot scripts names an RNG device or a `random.*=` kernel parameter, and
records the scripts' SHA-256 in the receipt. This is a static text check of those two scripts: it does not show that the pool was not
credited some other way, and the contract forbids a pre-seed, an injected backend and `/dev/urandom` as substitutes.
**Not shown by any of this:** a `PASS` needs a guest whose pool credits by itself (the 4.19 MIPS guest did so only after 76 to 258 s in
single scratch runs); until a transcript shows one, the positive path of the legacy provider is unproven and the refusal earns no credit.

### Tests

`python3 -B -m unittest discover -s toolchain/tests -p 'test_platform_smoke.py'` (stdlib only; it needs the P02 marker vectors and
`tests/p02/test_platform_markers.py`, so it runs only once `device.patch` has landed). It checks the committed examples per
guest, the drop/duplicate/swap of every line and the other planted faults, the verifier on full transcripts, the controls
(including that a judge that accepts everything is not credited), the runner end to end with patched guests, and the guest source
against the grammar. It cross-checks this judge against the reference judge in `tests/p02`; they disagree on two cases, both named
in the test: the reference judge accepts a `REFUSED` line whose provenance is `simulated` or `none`.

## Where the spec is

The runner (`toolchain/src/run-qemu-verification.py`), `toolchain/src/speaker_expect.py`, the guest step
(`toolchain/src/ffw-hello-init/src/speaker_smoke.rs`, cargo feature `speaker-smoke`, off by default; its platform step is
`run_platform`, cargo feature `speaker-platform`, off by default) and `toolchain/tests/test_speaker_smoke.py`. The platform step's
judge is `toolchain/src/platform_expect.py` and its tests are `toolchain/tests/test_platform_smoke.py`.
