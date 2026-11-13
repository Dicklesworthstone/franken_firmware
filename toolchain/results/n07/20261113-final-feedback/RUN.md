# Bounded final feedback after natural finite EOF

Source revision: `7d841bfe2c86628d29564cb7ceb7c75d195fe5bf`, baseline `1a759f5c02d3f6f41d9a697dd00961e4e399d169`. The six changed source paths match the frozen v3 overlays in receipt.json. Public evidence files are appended after testing; they do not change tested Rust.

The new opt-in API retransmits actual final consumption credit after natural EOF. It does not admit new media, replay PCM, acknowledge HAL drain, or extend clock/control authority. A single bounded clock sample gates both transport and canonical control permission. Grace uses the initial conservative lower bound and subsequent upper bounds. N03 buffer expiry is a holdover constraint, not a universal timestamp deadline while Locked.

## Executed host checks

- Five-path rustfmt check: exit 0.
- Strict-remote workspace Clippy native 347: exit 0, denied warnings, all targets.
- Strict-remote workspace tests native 348: 3014 passed / 0 failed / 2 existing ignored / 0 filtered, 81 result groups. All 14 required new tests run exactly once and pass.
- Actual PCM oracle: 24000 frames, 48000 samples, 94 packets including 192 final frames; peak 1 LSB, RMS 0.7097975063354337, below unchanged 4 / 1.5 limits.
- Pinned SDK native 349: 24 passed / 0 failed / 0 ignored / 0 filtered across 7 result groups. All 24 required names ran once; the expected isolation negative-control canary occurred once.

Both workspace jobs matched 1661 / 1661 transferred path/hash/size/executable tuples, with exactly the two Beads configuration files excluded. Terminal acknowledgement, staging/source/pair/tree/record release and absent wrappers were checked. Independent review inspected the same native executions and exact source.

Failed native 345 (missing test import) and 346 (denied fixed-chunk lint) are retained with their source/receipt/log hashes. Neither ran tests. Fixes add the missing type import and use fixed-size chunk iteration without changed assertions or tolerances. Earlier source-review rejections were corrected before the passing v3 run; they are not retroactive successes.

## Reproduction

Use the source revision above and a fresh eligible remote worker. Preserve complete stdout/stderr, native terminal acknowledgement and source-custody evidence. `RCH_CONFIG_DIR` and `RCH_SOCKET_PATH` are operator-specific, omitted from this public record. Commands below use the same semantic argv after worker selection.

```sh
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "${RCH_WORKER_ID:?set an eligible worker}" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings

RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "${RCH_WORKER_ID:?set an eligible worker}" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline --workspace --no-fail-fast -j1 -- --show-output --test-threads=1
```

The client check uses only 59 selected input files from frankensonos revision
`8f422c333269073a256fe59c6f50e7e8429a1bf9`, in the sibling layout expected by
`tests/g03/fsonos-client/Cargo.toml`. Selected input inventory SHA-256:
`6333d7d5e67cce995402500c19768abdc55a976c3fa4c3a0da8e4f48e50f6549`. Its independent expected set has 24 tests, 7 footers and an intentional isolation negative-control canary. Native 349 passed with the declared denominator. All 1,720 path/hash/size/executable tuples across firmware (1,661), SDK workspace metadata (4), proto (51) and types (4) matched. Terminal acknowledgement and staging/source/pair/tree/record release were verified; the wrapper was absent. This is a confined host client result, not a provider or physical result.

```sh
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "${RCH_WORKER_ID:?set an eligible worker}" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +nightly-2026-08-31 test --locked --offline --manifest-path tests/g03/fsonos-client/Cargo.toml --no-fail-fast -j1 -- --show-output --test-threads=1
```

## Limits and retirement

The independent PCM comparison covers actual authenticated sent media before protection DSP. The managed owner also checks all received frames were pulled, nonzero protected output, no repeated submissions during feedback, and a separate HAL acknowledgement. This is not post-DSP waveform equality or a physical acoustic oracle.

This demonstrates an offline host composition using actual decoder/carrier/source/owner code with explicitly modeled time and retained HAL. It does not qualify deployed Spotify/AirPlay/Alexa/Tailscale services, big-endian execution of this feature, hardware playback, physical synchronization, a general EOS protocol or an authenticated source/control bridge. The separate dynamic source-clock uncertainty finding remains open. No new buffer-holdover test is claimed. Original N07 acceptance and its dependencies remain open.

Consumer: the supervisor/reviewer deciding publication of this final-credit feature under AGENTS.md evidence rules. This minimal immutable snapshot prevents source/result misattribution and preserves the failed compile history; retire active maintenance once the bounded publication is complete, retaining it only as historical evidence. It is not a new live readiness service.
