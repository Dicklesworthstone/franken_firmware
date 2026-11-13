# Connect HTTP control to protected playback

Code 750126d4237e09c2c7b44998c007a99bfeda3a0a, tree 7c36638dbbbdc1d36aeb5153dd5ad8397ce461dc, based on published 53b94a4a29acafac741e8c9b08b9ad6f02ccc81c. All 1,635 committed source blobs, lengths and executable bits match the qualified candidate. Six changed paths and both exact native commands are in [receipt.json](receipt.json).

The default library now provides a bounded single queued-or-executing request handoff and an explicit SettledRender::service_http entry point. The existing isolated TCP custom factory can forward SOAP requests to that same protected-playback owner rather than mutating a separate session. The caller services the mailbox outside its render callback. Socket reads/writes and the bounded reply wait remain on the transport side; the owner never waits for mailbox capacity.

Requests and headers are capped before copying. Cancelled or expired queued requests can be reclaimed without an owner poll; an executing handler retains its permit. A timeout or lost reply reports outcome unknown rather than claiming rollback. A committed SOAP response survives a subsequent render-policy error, preserving relative-command retry semantics. The transport session mirror is only the last actual owner response and can be stale; it does not confer membership or recovery authority.

This custom adapter has no event-delivery outbox. It explicitly refuses discovery/event extras at startup and subscription methods before owner admission, avoiding a successful SID with silently lost notifications. Existing control planes are preserved. LocalLink event methods return405 with Allow:POST; tailnet event methods remain401 without disclosing subscription state. Permitted actual owner-serviced SOAP is tested alongside these refusals.

Twelve new cases cover copied transport fields, queued/executing capacity, cancellation/reclaim, expiry, reply loss, caps, owner disconnect, committed response preservation, startup policy, and actual localhost TCP. Signed set65 then relative+10 and identical retry reach revision3/volume75 exactly once and change actual nonzero protected PCM compared with the same input at its original volume. Busy and expired TCP requests preserve local mute intent and an acknowledged stop while an exact nonzero program token remains retained until the test backend's real flush ACK. These are host retained-HAL observations, not physical DMA or audible-output proof.

| Gate | Native execution | Observed result |
| --- | --- | --- |
| Complete speaker package | 30107136981729295 | 656 passed /0 failed /1 existing ignored;10 footers;0 filtered;12/12 new cases |
| Workspace all-target Clippy | 30107136981729296 | Exit0, warnings denied |
| Pinned formatting | Rust1.99.0 | Six changed Rust inputs pass edition2024 rustfmt check |

The existing ignored D03 25.5 virtual-hour soak did not run. Both remote source receipts independently match all1,633 transferred path/hash/length/exec tuples; only two .beads metadata files were excluded. Both wrappers exited0, terminal ACK is true, wrapper processes are absent, and staging/source/pair/tree/record release was checked. Independent review inspects these same executions, not a second run. [observed.txt](observed.txt) retains all12 required actual result lines and all10 speaker footers. No Python, gate configuration, golden, vector, tolerance or existing assertion changed.

Exact commands, through ordinary strict-remote RCH admission and source-content capture:

~~~sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 test --locked --offline -p franken-speaker -j1 -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
rustup run 1.99.0 rustfmt --check --edition 2024 --config skip_children=true crates/franken-speaker/src/settled_http.rs crates/franken-speaker/src/lib.rs crates/franken-speaker/src/fsonos_loopback.rs crates/franken-speaker/src/settled_render.rs crates/franken-speaker/src/network_render/tests/controller_events.rs crates/franken-speaker/src/network_render/tests/controller_events/http_integration.rs
~~~

The initial source draft was rejected before native execution because LocalLink SUBSCRIBE could create a SID despite having no event-delivery transport. That failure remains recorded; the reviewed successor adds pre-admission refusals and paired permitted SOAP. Initial test coverage was strengthened from non200 and priming-only observations to exact401 and an actual nonzero retained token before execution. No native test failure was relabeled as success.

This capsule serves supervisor/operator review of the exact HTTP-to-owner host integration. Its authorization retires when source/profile changes. The TCP adapter remains test/harness-gated; the mailbox and owner method are in the default library. There is no complete production HTTP service or external fsonos-client discover/subscribe/group/volume/reconnect qualification here. Original G03 stays open. No device, provider, native-tailnet, legacy-target memory/latency or physical-audio qualification is claimed; all requested features remain required.
