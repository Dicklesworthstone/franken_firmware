# P05 admitted-job byte accounting and asynchronous stdio

## Current source status

The frozen source identified by [lint-fixed-code-inputs.sha256](lint-fixed-code-inputs.sha256)
has the following results. Upstream Rust changes remain uncommitted until the
required native runs finish.

| Required check | Observed result | Scope |
| --- | --- | --- |
| Default all-target compiler check, build `30099060530610804` | Exit 0; no warnings or errors | Corrected 21-input source epoch |
| Strict primary all-target Clippy, build `30099060530610813` | Exit 0; no diagnostics | Same corrected source epoch |
| 98 focused native cases, build `30099060530610821` | 98/98 observed PASS; RCH wrapper failed 137 after tests | Disk monitor unavailable; not a clean qualification |
| Cached combined 122-case run, build `30099060530610825` | Exit 103 before execution; zero tests run | Owned source-closure freshness proof timed out |
| TS1 retry | Exit 103 at admission; zero tests run | Critical memory pressure; disk fitting was insufficient |
| HZ2 retry, build `30099060530610826` | Cancelled during compilation; zero tests run | Measured compiler swap thrashing; wrapper 137, recovered delivery 120 |
| Higher-memory worker retry, build `30099060530610835` | Exit 101; 121/122 PASS, one test failed | Immediate whole-runtime quiescence assertion after scoped timeout |
| Remote formatting, jobs `30099060530610829` and `30099060530610830` | Exit 0 for 13 files; hashes matched before and after | Four other modified files retain baseline formatter debt |

The latest native run executed all 122 predeclared cases (0 ignored, 27,259
filtered out) in 1.38 seconds after 42 minutes 7 seconds of compilation. The
failure is `scoped_timeout_strict_authority_uses_checked_parent_target_without_placement_escape`,
at its immediate `runtime.is_quiescent()` assertion after `block_on`.
The failing runtime flavor and remaining lifecycle component were not logged.
The same case passed in the earlier 98-case capture; that does not dismiss this
failure. Independent source reviews found that multithreaded `block_on` does not
promise immediate whole-runtime quiescence. A transient dispatch-retirement
window and a persistent leak remain distinct hypotheses pending observation;
no test assertion or timeout has been weakened.

All **20,911/20,911** captured source files matched the current bytes, sizes and
executable modes after this failure. Content root:
`e6c971b79e11f75659f53460715994b245840b8a57c9abdb7a7ea1211140cd1e`;
receipt root:
`25acd51f4a6d8d5f4b2d044a6c41bcc358222c3ba555f1acb08b4c794289adc0`.
Terminal acknowledgment, dead wrapper, absent owner and four source/tree/pair/
recovery releases were verified. The project output phase remained false on
exit 101. [lint-fixed-native.txt](lint-fixed-native.txt) preserves the observed
122 names and failing summary alongside the earlier 98-case excerpt.

The implementation reserves byte credit and a queue slot before the stdio
input copy, and retires closure storage before completion returns that credit.
Double-panic payloads retain their original charge. Default admission semantics
remain unchanged; destructor-panic containment, stranded-work retirement order,
and completion-waker tracking intentionally improve behavior across policies.
This is an admitted-pool bound, not a whole-process memory limit.

The earlier public consumer passed 15/15 and the cancellation contracts passed
50/50 on separately identified source epochs. The required global unsafe ledger
remains **4/5, failing** on inherited locator drift. Those results are preserved
below; they do not qualify the current source by substitution. Original P05/P03
feature, resource-census, big-endian and guest requirements remain open.

## Historical captures and source epochs

The following sections preserve the commands, failures and subsequent corrections
in capture order. A pending statement describes that section's epoch; the current
status table above takes precedence. No old witness or failed result is replaced.

The strict-remote native consumer executed **10 passed, 0 failed, 0 ignored**:
four allocator/reservation tests and six public-runtime stdio/completion tests.
[native.txt](native.txt) retains the observed names and terminal test summaries.
This is a selected excerpt; the complete operational capture is retained
privately with SHA-256
`2b7e43ae64c61ae0bf58920dfcf78b1b6e3f3fa8596950dc443673d069a2dc4f`.

From the sibling Asupersync root:

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 \
rch exec --source-content-receipt --worker vmi1149989 -- \
  env CARGO_TARGET_DIR=/tmp/rch-target-asup-byte-final \
  cargo +nightly-2026-08-31 test --locked \
  --manifest-path tests/lightweight/byte-admission/Cargo.toml \
  --no-fail-fast -j1 -- --show-output --test-threads=1
```

Build `30099060530610734` returned 0. The command took 540.254 seconds;
the complete remote invocation took 624.9 seconds. The allocator target took
0.09 seconds and the stdio target 0.27 seconds. All **20,911/20,911** captured
input files matched the source before subsequent baseline-test repairs.
Terminal acknowledgment, wrapper termination, absent owner and all five
source/tree/pair/staging/recovery releases were verified.

The base was Asupersync `8e1cb881587894d5980c4ad8e2ea6d49bda00e6f` plus
the uncommitted bounded-byte/completion/quarantine changes. This is execution
evidence for those captured bytes, not a claim that the upstream changes
have landed or that the base commit alone implements them.
[code-inputs.sha256](code-inputs.sha256) retains fourteen relevant relative-path
input hashes from the worker's source-content receipt. Content root:
`14acd45071fddf3b5ce5322a3892323070435218b84a12e5272bb208c6ee438b`;
receipt root:
`20e9b9543ebea3e22607e8365ce55186d22de43d2af3ad17687a65375ff94f13`.

The lightweight package reuses the original allocator test source and the
public stdio test source; the root targets remain. It uses normal default
runtime features, not test-internals. Its locked graph has 181 packages versus
477 in the root graph, reducing development-test dependencies; this is not a
runtime-footprint measurement or a substitute for root qualification.

The positive cases exercise a real bounded runtime and actual asynchronous
stderr writes/flushes. A wake recorder checks that completion follows closure
allocation retirement and returned byte credit. Tests retain cancelled and
panicking jobs, wake-starvation and late-Ready falsifiers, and a panic-payload
transfer that keeps the original heap charged while allowing smaller work.
The expected panic diagnostics belong to those passing planted tests; the
complete capture retains them.

## Boundaries and outstanding qualification

The byte ledger covers admitted queued/running jobs and quarantined
reservations: measured closure storage plus trusted declared exclusive heap.
It does **not** cover closure captures retained by parked or unpolled
`submit_charged` futures, caller-owned rejected work, arbitrary shared heap,
new allocations inside jobs, allocator overhead or an unbounded waiter count.
The original P05/P03 pending-job byte and thread/stack/cancellation/cleanup
requirements remain open. A bounded pre-materialization admission mechanism
and real consumer census are still required; no follow-up substitutes for them.

This was host-native execution with unwinding. It proves no panic recovery
under an aborting firmware profile and no big-endian, legacy-kernel, QEMU,
hardware, rendering-deadline or whole-process memory qualification.

The initial required root all-target check subsequently returned 101 with
four errors in unchanged scoped quorum/timeout tests and one unused
timer-count warning. Their minimal assertion-preserving repairs were checked
separately below. The earlier thin-consumer Clippy passed but reported one
dependency deprecation; that call was corrected to the pinned nightly API
before this native run. Thin-consumer Clippy is not strict primary-library
Clippy.

## Earlier all-target compiler check, before the factory wave

The earlier compiler run, build `30099060530610752`, returned **0 with no
compiler warnings or errors** after repairing three integer-inference sites,
one test context's type-level authority and five deliberately ignored
timer-count returns in three existing test files. All behavior assertions
remain, including the foreign-timer count oracle. An intermediate compiler
run passed with four latent warnings; it is not described as warning-clean.

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=2 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 \
rch exec --source-content-receipt --worker ts1 -- \
  env CARGO_TARGET_DIR=/tmp/rch-target-asup-byte-final-default \
  cargo +nightly-2026-08-31 check --locked --all-targets --keep-going -j2
```

Observed: ``Finished `dev` profile [unoptimized] target(s) in 7m 24s``, remote
command exit 0 in 449.900 seconds, total invocation 482.8 seconds. All
20,911/20,911 captured inputs matched; terminal acknowledgment, wrapper
termination, absent owner and all five releases were verified. Content root:
`f8deef6599bc7d119b104f0b1bd9bc67a3605a7f2b148d166adecd23862f5af5`.
Complete private capture SHA-256:
`11f66cff3b3929b884376390b95847c6fff32905f9c95f0a3bb639bfd1af9e55`.

For that compiler run, the fourteen native-code input hashes above were identical. The compiler's
three additional repaired test-file digests were:

```text
f1fdda5596b49b483b4d9edcd2639d04817c5d5a5b6e7cc815d061a596f3bef8  src/cx/scoped_quorum_inline_tests.rs
712668a0abcf6c787b1e0d72709d8639e24f819fe7defe1b5de483ee0a857584  src/cx/scoped_timeout_inline_tests.rs
82484a83eb53b24a50af8448db22cae955fd554452f0def134608e9419572a81  tests/scope_timeout_e2e.rs
```

This is default-feature host compilation, not execution of those repaired
tests, strict Clippy, all-feature, big-endian or guest qualification.

## Reservation before materializing input: native consumer

The subsequent additive `try_spawn_charged_with` API reserves the measured
closure storage, trusted declared heap and a queue slot before invoking a
bounded factory outside pool locks. The actual pool-backed stdio path copies
its input inside that factory. A full queue or byte budget therefore refuses
before the copy. Ordinary completion retires payload storage before returning
credit; unresolved panic payloads keep the whole reservation pinned. Shutdown
destroys an already constructed job without running it. The factory runs on
the calling thread and must itself be bounded and nonblocking.

Build `30099060530610767` executed **15 passed, 0 failed, 0 ignored**: the
original four allocator and six public stdio cases plus five new public
factory/copy cases. All fifteen required source names matched the executed
names. [factory-native.txt](factory-native.txt) preserves selected observed
output; no synthetic result has been substituted. Command:

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 \
rch exec --source-content-receipt -- \
  env CARGO_TARGET_DIR=/tmp/rch-target-asup-byte-final \
  cargo +nightly-2026-08-31 test --locked \
  --manifest-path tests/lightweight/byte-admission/Cargo.toml \
  --no-fail-fast -j1 -- --show-output --test-threads=1
```

The selected worker executed the command with exit 0; the invocation took
769.2 seconds, compilation 11m 35s, allocator tests 0.11s and stdio tests 0.61s.
All **20,911/20,911** captured files matched the frozen source. Terminal
acknowledgment, dead wrapper, absent owner and all five custody releases were
verified. Full private capture SHA-256:
`646f8df7edc10902ad9db309ea7d0cb4e7456220223d705f6ce36e1b78df2a37`.
Content root:
`a2f6599ba661c67c57611f317b3ff6008185bd4221e3bc01055cac45f5248e4d`;
receipt root:
`f5480bb3db57117e1b143ccf5eee8b4641c8953bfa9140384c36a2f33217e0e9`.
[factory-code-inputs.sha256](factory-code-inputs.sha256) records the twenty
owned input hashes. These are a later source epoch than the original ten-case
run above; its historical witnesses are preserved.

This is host-native unwind-profile evidence for the bounded pool path.
Fixed-size completion allocation still precedes admission. No-pool stdio
fallbacks, caller-owned heap and parked `submit_charged` payloads are outside
this guarantee. A factory still in progress is not covered by
`shutdown_and_wait`'s worker drain. Original P05/P03 requirements remain open.
The subsequent default all-target compiler check, build `30099060530610768`,
returned 101: seven E0515 errors at four call sites in the inline test target.
Two helpers clone their `Arc` inputs but their opaque return types implicitly
capture the argument lifetimes under Rust 2024. The production library and
public consumer pass above do not compile those `cfg(test)` helpers.
All 20,911 captured inputs matched; the full failed capture has SHA-256
`a668947189af53e7a816cb08815014c3b37ef76a369a78c7fac1371636f06f7a`.
This is a failed required check, not a qualified landing.

Strict primary Clippy, current-source cancellation/unsafe-boundary contracts
and 71 focused internal cases remain outstanding. Two internal requests
timed out before admission with exit 103 and executed zero tests; the second
was refused while that worker already had an active build for this project.
They are not failed test runs. No upstream landing, big-endian, legacy-kernel,
guest or physical qualification is claimed here.

## Mandatory cancellation and unsafe-boundary contracts

On the same pre-helper-repair source, build `30099060530610775` executed
the complete native cancellation contract: **50 passed, 0 failed, 0 ignored,
0 filtered**, with all fifty predeclared names observed, including the two
stream-submodule cases. The unsafe-boundary target returned **4 passed,
1 failed**, so the combined command returned **101**, not a green suite.
[factory-contracts.txt](factory-contracts.txt) preserves observed name markers
and summaries. With `--nocapture`, panic diagnostics interleave some individual
statuses; the complete binary summaries above are authoritative.

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 \
rch exec --source-content-receipt -- \
  env CARGO_TARGET_DIR=/tmp/rch-target-asup-byte-final-contracts \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo +nightly-2026-08-31 test --locked -p asupersync \
  --test runtime_abort_vs_cancel_semantics_audit \
  --test unsafe_boundary_ledger_contract --no-fail-fast -j1 \
  -- --nocapture --test-threads=1
```

The ledger failure reports 194 unledgered locations and 194 stale locators.
Static parent comparison establishes inherited drift: all 39 affected source
files match parent `8e1cb881` byte for byte, and all 102 existing ledger rows
are unchanged. The only added row covers the six allocator-test sites; none
of those sites is diagnosed. This comparison is not a baseline native rerun
or a waiver of the failed global ledger check. The ledger was not regenerated.

Compilation took 13m 48s, cancellation tests 6.11s, ledger tests 24.03s and the
remote command 862.680s. All 20,911 captured source files matched, with terminal
acknowledgment, dead wrapper, absent owner and source/tree/pair/recovery
releases verified. Project staging did not complete on this failed command.
Full private capture SHA-256:
`5bada27f11eaab3e64d36c7f05d4aea7b996e0e409f4d714fcce4c3509040103`;
content root:
`7790bb06f3aea929369ed522cb0891dcbbaaae5b1e15de2ecc48b3bb887dd2ed`.

After those captures retired, the reviewed helper repair added precise
`use<>` capture bounds to two inline-test return types. No helper body,
call site or assertion changed. The repaired file's SHA-256 is
`814ba0a9a74cc7bdcc39001869d79fd41fb1f252be9a478f3618031f07f389cb`.
Its default all-target compiler and strict Clippy checks remain pending; the
focused internal execution is recorded below.
The earlier strict Clippy invocation exposed the same seven E0515 errors
before an operator-requested stop: the original wrapper returned 137 and
same-job recovery recorded worker result 120 (`monitor_unavailable`). Neither
is treated as a pass or as evidence of an out-of-memory or disk-full event.

## Corrected internal cases: 71 executed passes

Build `30099060530610778` executed **71 passed, 0 failed, 0 ignored** on
the repaired source: all 51 admission and 20 stdio names matched the
predeclared census and explicit `ok` statuses. The harness filtered out
27,310 unrelated cases; this is not execution of the complete library suite.
[factory-internal.txt](factory-internal.txt) preserves the observed names and
summary, including whitespace written by the actual stdio tests.

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 \
RCH_CONFIG_DIR=/tmp/ffw-rch-bulk-20261107 \
rch exec --source-content-receipt --worker trj -- \
  env CARGO_TARGET_DIR=/tmp/rch-target-asup-byte-final-units \
  cargo +nightly-2026-08-31 test --locked --lib --no-fail-fast -j1 \
  -- runtime::blocking_pool::admission::tests:: io::stdio::tests:: \
  --show-output --test-threads=1
```

The observed task-local RCH profile is a private copy of the operator's
configuration and worker mappings. Only `transfer.remote_base` and
`remediation.pooled_target.store_base` change, respectively to
`/bulk/rch-franken-firmware-20261107` and its `targets/` subdirectory on an
existing bulk volume. Reproduction can use the operator's normal strict
remote placement instead; no runtime behavior depends on that storage path.
Remote enforcement, admission budgets and protected free-space floors remain
in force. Compilation took 36m 09s, the tests 0.88s and the
complete invocation 2,230.1s. All **20,911/20,911** captured inputs matched
the source frozen for that run. Terminal acknowledgment, dead wrapper, absent owner and
all five releases were verified. Full private capture SHA-256:
`4e3b1090cf17912720829c57677b108873443e9841cb3fab64bac708bcf556e0`.
Content root:
`5a23dd86791533d9297c6536c103369e88a4ad858a3a23a692ec089f2a64b256`;
receipt root:
`b5b691faef849e559a9d354aec117a147a6df1bf1fc85bb2c7756d68af14587d`.

[current-code-inputs.sha256](current-code-inputs.sha256) records the twenty
owned inputs at this epoch. Only the repaired inline-test file differs from
the fifteen-case public consumer's input witness; production and public-test
bytes are unchanged. This focused host-native evidence completes the formerly
unexecuted internal cases. It leaves default/all-target compiler and strict
Clippy qualification, inherited global ledger drift, the full P05/P03 contract,
big-endian, guest and physical qualification distinct and outstanding.

## Corrected default all-target compiler check

Build `30099060530610779` returned **0 with no compiler warnings or errors**
on the repaired source. Observed: ``Finished `dev` profile [unoptimized]
target(s) in 47m 58s``; command 2,906.468s and total invocation 3,002.2s.

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 \
rch exec --source-content-receipt --worker vmi1149989 -- \
  env CARGO_TARGET_DIR=/tmp/rch-target-asup-byte-fixed-check \
  cargo +nightly-2026-08-31 check --locked --all-targets --keep-going -j1
```

All **20,911/20,911** captured inputs matched the source frozen for that run, including
the twenty owned digests in `current-code-inputs.sha256`. Terminal
acknowledgment, dead wrapper, absent owner and all five releases were verified.
Full private capture SHA-256:
`c8fbe7779815036861c0e13fb1d9a3cd651cfc628c717fc286d124bea3174f12`;
content root:
`7be70d42da648cb2b69859740994377b3a666a1a8e04f78f2c53f1ecf1b58031`;
receipt root:
`d40e13f2fbee1e17cd33f950069978794410cf91440d030f35317909755180fc`.

This is default-feature host compilation. Strict primary all-target Clippy
remains pending. The inherited global ledger failure and the wider P05/P03,
all-feature, big-endian, guest and physical boundaries remain as stated above.

## Strict Clippy: three test-only diagnostics

Build `30099060530610793` returned **101**, after 1,750.630 seconds, for
exactly three test-only diagnostics. Two inherited scoped-race/timeout arms
match the remaining `Poll` case through a wildcard. The third flags the new
stdio test's manually constructed waker. That waker intentionally carries an
`Arc`: its strong-count assertions detect retained ownership after abandoning
a wait. Replacing it with `Waker::noop()` would discard that oracle.

All **20,911/20,911** captured inputs matched the frozen source. Terminal
acknowledgment, dead wrapper, absent owner and source/tree/pair/recovery
retirement were verified; the project output phase is false on this failing
invocation. No Clippy pass is claimed. Content root:
`9a5acb1ca2aaa8500b2d09bd3188aa245de69fad23f406200edabbb73afd3f8b`;
receipt root:
`dd5a2cd0bdac37864d52857a7bafe43613d0590d29f888a37bc412ebc5d6cb16`;
full private capture SHA-256:
`88693589a8d53c56bb35b470cf9faf75abad22e78c154561bca3ef46185e8780`.
The embedded source-content-receipt JSON payload has the distinct SHA-256
`2e0ce826a334f0ec7cf4ba520114ecaa54027501674ce38f9710c46628e8625e`.

A minimal correction preserves both finalizer-error assertions and the
strong-count oracle, and adds an assertion that the abandoned wait is never
woken. Its separate compiler, native and strict Clippy qualification must be
recorded before the corrected source is described as qualified. The earlier
71-case and compiler receipts above describe their captured input epoch;
`current-code-inputs.sha256` remains that epoch's immutable witness.

## Final test-lint correction: default compiler check

After the independently reviewed test-only correction, build
`30099060530610804` returned **0 with zero compiler warnings or errors**.
The failure arms now explicitly match `Poll::Ready(Err(_))`. The counted
waker retains its Arc ownership assertions and records wakes; the added
assertion requires that abandoning the wait never wakes it. No assertion was
removed and no lint suppression was added.

The default all-target command above was repeated on `trj`, with the same
task-local bulk profile, `-j2` and
`CARGO_TARGET_DIR=/tmp/rch-target-asup-byte-fixed-clippy`. The compiler took
19m 09s, the command 1,160.499s and the full invocation 1,210.0s.
All **20,911/20,911** captured inputs match this corrected source.
[lint-fixed-code-inputs.sha256](lint-fixed-code-inputs.sha256) records its
21 owned inputs; it does not replace the earlier epoch's witness.
Full private capture SHA-256:
`cae64e5dadc0860c4d302f3c7fbe8a6452446a696ece71f6fbc596134074eff3`;
content root:
`4fc9c4c563e2e7255dce71143102aa9fbc45d8fb70f79e7cf97772a4ae1307c9`;
receipt root:
`d53d5388398677cb90347367606c8d1168eed21101313cc56503b2db6e1049d2`.

Strict primary Clippy and the 98-case native rerun remain pending for this
source. The latter includes the earlier 71 plus all ten scoped-race and
seventeen scoped-timeout tests. None is inferred from this compiler pass.

## Final strict primary Clippy

Build `30099060530610813` returned **0 with no compiler or Clippy diagnostics**
for `cargo +nightly-2026-08-31 clippy --locked --all-targets --keep-going -j2 -- -D warnings`.
It used the same task-local bulk profile and target request as the corrected
default check. Compilation took 50m 48s and the command 3,061.009s.
All **20,911/20,911** captured inputs match the corrected source, including
all 21 digests in `lint-fixed-code-inputs.sha256`.

Full private capture SHA-256:
`4bd5fee2b054e22e6ccbad86a5c75c683edd2079c56e1cedf96f69d89885cd86`;
content root:
`06e6577a20df5a2a8ddd4fb13529b678e5c0266f2e020f9566923c15088c1596`;
receipt root:
`6edf4324832481a002eb72ee9fd57afaa4ccd7aa2c98fa7d5c97243cac423434`.

The earlier three-diagnostic invocation remains recorded as failed. This is
default-feature host lint/compilation evidence; it does not run the tests or
qualify big-endian targets, guest kernels, physical outputs or the complete
P05/P03 resource contract. The final 98-case native run remains pending.

## Native 98: actual test success, failed operational completion

Build `30099060530610821` executed all 98 predeclared case names successfully:
**98 passed, 0 failed, 0 ignored, 27,283 filtered**, in 4.19 seconds after
51m 45s of compilation. [lint-fixed-native.txt](lint-fixed-native.txt) retains
the actual status lines and test summary. Full private capture SHA-256:
`2484d15c2ed984f8ac75ac1d83c88b33c3d9ab473c1dae55d610b5977296e620`.

After that test summary, the unchanged RCH disk guard failed with
`monitor_unavailable`: its disk probe or scan deadline was reached. The wrapper
returned **137**. Same-ID recovery confirmed that result. Terminal acknowledgment,
dead wrapper, absent owner and source/tree/pair/recovery retirement were observed;
the project output phase was false. No clean final source-content receipt or
whole-invocation success is claimed for this run. The failure's zero-valued free
space is an unavailable measurement, not evidence of an empty disk.

One cached strict-remote rerun combines the same 98 cases with the 24 originally
planned first-ok/quorum cases. Its 122 expected names were fixed before execution;
two first-ok names were corrected to include their source's nested `native`
module, with the original private registry preserved and the denominator unchanged.
Source, worker, target pool, compiler flags and disk guards remain unchanged.

The cached combined attempt, build `30099060530610825`, subsequently returned
**103 before command execution**: proving owned source-closure freshness
exceeded its deadline after the transfer. It executed zero tests. All four
custody retirement flags were true, with terminal acknowledgment, dead wrapper
and absent owner; the project output phase was false. The wrapper and test
result are distinct from the earlier 98-case run. Full failed private capture
SHA-256: `830a9e0ff89d7170fe3c75775dd18e3ad632551117eb14e90e7e32628d041837`.
No disk limit, probe or source-integrity requirement was disabled or relaxed.
A further build will wait for diagnosis rather than repeat this failure blindly.

The subsequent exact-worker TS1 attempt was refused at admission for critical
memory pressure, with exit **103**, before any transfer or execution. Disk
capacity alone had fit; it was insufficient for full worker eligibility. Failed
private capture SHA-256: `76b200fcbc762efe8080474e76c41eeffad6dd3ef087be766986fae9d292f44b`.

Read-only worker diagnosis then found a timed-out metadata walk on TRJ's bulk
filesystem and identified local-SSD alternatives. Current RCH admission selected
HZ2, where the same frozen 122-case command subsequently began execution. No
pressure threshold, disk guard, source-integrity check or local-fallback policy
was relaxed. Its result remains pending.

## Owned-file formatting

Two remote non-compilation jobs, `30099060530610829` and `30099060530610830`,
returned **0**, checking ten and three files respectively. Both verified their
explicit input SHA-256 values before and after invoking the pinned formatter.
[owned-format.txt](owned-format.txt) retains selected actual output and the two
complete private capture hashes. Terminal acknowledgment, dead wrappers, absent
owners and all four source/tree/pair/recovery retirement flags were observed.
These generic jobs have no Cargo artifact-output phase and provide no Cargo
source-closure receipt. The runtime/check/Clippy receipts are separate.

The literal formatter step was `rustfmt --edition 2024 --config
skip_children=true --check`, with `RUSTUP_TOOLCHAIN=nightly-2026-08-31` and
explicit repository-relative paths. The thirteen checked files were:

```text
src/cx/scoped_first_ok.rs
src/io/stdio.rs
src/runtime/blocking_admission.rs
src/runtime/blocking_pool.rs
src/runtime/blocking_pool/priority.rs
src/runtime/legacy_profile.rs
src/runtime/mod.rs
src/runtime/spawn_blocking.rs
tests/blocking_byte_reservation_allocator.rs
tests/blocking_stdio_byte_completion.rs
src/cx/scoped_first_ok_inline_tests.rs
src/cx/scoped_quorum_inline_tests.rs
src/runtime/blocking_admission_inline_tests.rs
```

Four other modified files retain formatter differences already present at
`HEAD`: `scoped_race_inline_tests.rs`, `scoped_timeout_inline_tests.rs`,
`blocking_pool_inline_tests.rs` and `scope_timeout_e2e.rs`. Baseline/current
formatter comparisons and the narrow source changes were reviewed; these files
were not broadly reformatted. No whole-repository formatting pass is claimed.
An initial unsupported `--job --source-content-receipt` combination was rejected
with CLI exit 2 before execution; the supported jobs above supersede that attempt.

## HZ2 cancellation and memory headroom

The HZ2 run was stopped during compilation after an owned-process probe found
about 14 GB swapped out, only about 0.56 GB resident, and minimal CPU progress.
Passing admission had not provided sufficient headroom for this large compiler.
Only this exact RCH job was cancelled; no peer was signalled. The original wrapper
returned **137**, while supported same-ID recovery reported delivery **120**
and terminal acknowledgment. Both outcomes are retained rather than normalized
to success. Dead wrapper, absent owner and all four source/tree/pair/recovery
retirement flags were subsequently verified. It ran zero tests. Full failed
private capture SHA-256:
`bf26b7b20a961db26ea390db3c2a40248efc50faaa6b55dd98c92707625b6a30`.

The same frozen 122-case command was then submitted to a worker freshly measured
with about 53 GiB of available memory and no memory pressure. All disk, pressure,
source-integrity and strict-remote requirements remain unchanged. No final test
result or new upstream Rust commit is claimed yet.
