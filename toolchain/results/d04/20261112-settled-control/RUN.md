# Owned control, membership and protected render integration

Code: fce5014d54c85a56dafd777e83432c3f4e95c24b, in three logical commits on
fd68130a2a1abb6cfccc5e3146cdd18358efa110. The complete 1,615-file code tree
matches the immutable final-source inventory. All 19 changed files are hashed
in [receipt.json](receipt.json). This is a host prototype, not installed speaker
firmware.

## Behavior

SettledRender owns the durable controller, SOAP endpoint, group membership,
session, local policy and protected network renderer. Fresh group construction
is one-shot and cannot bless a caller-reconstructed session. The owner rechecks
its actual epoch, clock and held leases at the future membership cutover; local
readiness requires the HAL, silence priming and protection contract.

Group/member/local gain and independent mute intent feed the protected output
path. Actual stop/flush acknowledgment governs completion; a missing
acknowledgment retains readable DMA custody. Startup HAL faults remain reachable
for cleanup. Natural finite EOF preserves the scheduled tail with an explicit
Finishing result; changed intent is not falsely reported as applied to future
PCM. Local mute/stop still interrupts that tail. Control/membership GENA producer
events run outside the render hot path; event production is not delivery.

Sequence exhaustion never wraps. Authenticated current local stop/mute-on can
reduce live output; applied and already-silent results are distinct. Durable
exhaustion is reported only after its marker write succeeds. Failed-write local
silence is not crash-persistence proof. Reserved reply status 9/refusal 16 stay
invalid; new outcomes use 10/17 without rewriting the malformed corpus.

The carrier packs a validated datagram length and clock flag into one private
word, removing queue padding under the unchanged original N07 memory limits.
Stable owner identity is allocated lazily. Real allocator tests account for its
first use and retained selection identities; this does not prove global caller
admission accounting or a legacy speaker's RAM fit.

## Actual execution

All compiler/test jobs ran through strict remote RCH, pinned Rust 1.99,
locked/offline dependencies, one build job and one runtime test thread. Profiles
used CARGO_INCREMENTAL=0, CARGO_PROFILE_DEV_DEBUG=0, and
RUSTFLAGS=-D warnings -C debuginfo=0. Actual payloads/hashes and selected Cargo
output are retained in receipt.json and [observed.txt](observed.txt).

| Gate | Native job | Observed result |
| --- | --- | --- |
| Final19 v1 complete workspace | 30106308287922620 | 2,888 passed / 0 failed / 2 existing ignored |
| Final19 v1 strict all-target Clippy | 30106308287922638 | Failed exit 101: two test syntax lints |
| Final19 v2 strict workspace all-target Clippy | 30107136981729281 | Exit 0, warnings denied |
| Final19 v2 complete speaker package | 30107136981729282 | 616 passed / 0 failed / 1 existing ignored |

The full-workspace result belongs to its exact predecessor bytes. The final
revision changes only two equivalent expressions in the controller test file;
all production and other test files are identical. Both assertions are retained.
The affected speaker package and strict workspace all-target Clippy were then
rerun on the final source. Do not add these overlapping test totals. All 23
controller-event tests individually passed in both runtime jobs. The ignored
campaigns are the existing exhaustive 2^32 float conversion and D03 soak
spanning 25.5 virtual hours; neither ran. Pinned Rustfmt passed for all 19 changed files.

Reproduction Cargo payloads, inside the authorized strict RCH lane:

    cargo +1.99.0 test --locked --offline --workspace -j1 -- --show-output --test-threads=1
    cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
    cargo +1.99.0 test --locked --offline -p franken-speaker -j1 -- --show-output --test-threads=1

Twenty-three integration controls exercise actual owned control/session/
membership code and protected PCM over localhost with a retained FakeBackend.
They cover permitted join/gain/recovery, direct/signed stop and mute,
duplicate/exhausted commands, failed persistence and authority boundaries,
actual EOF frame/timing oracles, and stop ACK versus quarantined retention.
They do not replace a real driver, distributed clock or provider.

## Failures and custody retained

Earlier actual failures remain in the receipt and output: original workspace
25/6, clean baseline heap 1/6, focused control 672/1 (reserved wire tag), combined
workspace 30/4 (queue padding), and control/render 1,523/1 (EOF). None is relabeled
an expected RED. The packed carrier diagnostic 331/0 is a subset, not a full
workspace run. Its eleven heap cases include all seven old cases plus four
causal additions; no original assertion or allowance was widened.

Root matched every transferred path/hash/size/executable bit to the bound
inventory for each final gate, checked terminal ACK, dead wrappers and released
staging/source/pair custody with retired trees. Historical null staging fields
remain unknown. The code commit's entire 1,615-file tree was compared, not only
the changed files. Review by multiple agents shares the native logs and is not
an independent second execution.

An unrelated local service's port cleanup repeatedly terminated the shared
RCH daemon, so final jobs initially were not admitted. The final two used an
unmodified native RCH process on a private Unix socket, with TCP listeners,
file-cache cleanup and reaping disabled. No camera process, shared configuration,
protected floor or test gate was changed. Native guarded shutdown subsequently
refused while unrelated peer leases remained. One authorized 300-second guarded
drain then timed out with RCH-E325 and exit 1; it did not stop the helper. The
helper remains intact under the verifier's ownership. No force, signal or peer
cancellation was used. Both of our jobs had already released their custody.

## Remaining qualification

Existing-media/reconstructed-session recovery, all channel-role PCM wiring,
persisted local intent, warmed co-owner allocation bounds, caller-retained
identity/global admission accounting, actual GENA delivery, native service and
tailnet integration, legacy kernel/32 MiB resource fit and physical audio remain
required and open. These component results close no original full bead. This
record is consumed by the operator/supervisor for this exact code qualification;
it ceases to qualify changed source/profile, while retaining historical evidence.
