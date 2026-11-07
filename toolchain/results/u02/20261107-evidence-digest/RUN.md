# U02 production evidence-digest regression

Offline research qualification, 2026-11-07. No device, provider account,
installation, vendor-signature bypass, or physical A/B-capacity admission.

The production admission predicate accepted two absent evidence digests when
the policy carried `Some([0; 32])` and the signed manifest also named zero.
Zero denotes absence. The corrected predicate requires the policy digest to
be nonzero and equal the manifest digest. `EvidenceMismatch` and the existing
signature/board/feature precedence remain unchanged. Nonproduction admission
and matched nonzero production evidence remain permitted.

All 188 preceding vector objects were preserved. Ten cases were appended:
nine independently signed admission cases and one restart script. The final
inventory has 198 cases. The restart matrix covers all four persisted phases.

## Observed commands

The following commands ran from the repository root. RCH selected native Linux
workers; compilation was strictly remote. Worker identities, absolute private
paths and raw source manifests are intentionally omitted from public excerpts.
`native-green.log` preserves every required Rust test result by name.

```sh
RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +1.99.0 test --locked \
  -p franken-update --no-fail-fast -j1 -- --nocapture

RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +1.99.0 clippy --locked \
  -p franken-update --all-targets -j1 -- -D warnings

RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 check \
  --locked -p franken-update --all-targets --message-format=json \
  --target powerpc-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort -j1

RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 check \
  --locked -p franken-update --all-targets --message-format=json \
  --target mips-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort -j1

python3 -B -W error -m unittest discover -s tests/u02 -p 'test_*.py'
scripts/e2e/u02 --tier full --judge <private-native-log> --receipts <ignored-build-output>
```

The actual calls additionally selected specific eligible workers. The first
old-policy retry refused an unavailable worker before compilation (exit 103).
Normal eligible selection then produced the causal old-policy failure below;
this admission refusal was not counted as a product test.

## Results and qualification boundaries

| Gate | Observed result |
| --- | --- |
| First regression build | Compile error, exit 101: helper accidentally annotated `#[test]`; no runtime-regression credit |
| Corrected regression, old policy | 29 passed / 4 failed / 0 ignored, exit 101 |
| Same regression, corrected policy | 33 passed / 0 failed / 0 ignored, exit 0 |
| Current Clippy | All targets, warnings denied, exit 0 |
| Current PowerPC check | All targets, exit 0; compilation only |
| Current MIPS check | All targets, exit 0; compilation only |
| Python tests | 53 passed |
| Full E2E | 6 passed / 0 failed / 0 blocked; 33 required Rust names |
| Mutation controls | 50 planted defects detected, permitted positive controls retained |
| Bounded diagnostics | 13 critical events, 0 critical events lost |

The causal red and green runs used identical test, vector and judge bytes.
Production policy, Python reference and explanatory contract changed between
them; an unrelated uncompiled N05 contract also changed. Each of the four final
Rust gates independently transferred 1,216 files, all byte-equal to the local
tree when verified. Each completed with terminal acknowledgement, no live
wrapper or owner, and source/tree/pair/staging release confirmed. The selected
source hashes and receipt roots are in `qualification.json`.

The execution source witnesses bind commit `73fb62a`. A subsequent documentation-only
change refreshes the contract's stale qualification paragraph; its separate published
digest is recorded without replacing the captured execution digest. No runtime,
test, vector or manifest bytes changed for that documentation correction.

The previous initial native failure remains in the earlier committed
`20261107-2ccb1a5-initial` results. The helper compile failure and the causal
failure here are retained separately. No failed result was converted to a pass.

The root manifest change only excludes the standalone N05 research workspace;
it removes no firmware workspace member or required feature. N05 source and
performance are not qualified by these U02 checks. These checks also do not
qualify old guest kernels, retained drivers, BE crypto execution, board memory,
external capacity attestations, or the future effective SSH server policy.

The current bootstrap has no SSH daemon. The SSH package/policy admission model
does not claim that an installed server has been patched. Actual daemon/libc
and authentication qualification remain separately required.
