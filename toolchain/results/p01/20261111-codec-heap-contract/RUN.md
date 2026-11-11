# Codec heap dependency declaration: host correction, native checks unrun

The actual heap probe added an existing workspace codec test dependency to
the allocator probe. The declared workspace graph omitted that edge. The
canonical P01 pipeline exposed the regression: **261 total, 251 passed,
two failed and eight blocked**. P01-CON-002 named the missing
`dev:franken-alloc-probe->franken-codec` edge; P01-META-006 exposed the same
drift through its existing machinery tests. The failing baseline is retained.

The correction adds that single declared edge. Its necessary vector identity
update preserves all **143** IDs, operations, expected error codes, subjects
and admission assertions. Only 30 computed identity values change: one base
digest, one expected digest and 28 observed contract digests. The existing
generator reproduces them; no behavioral golden or threshold was changed.
Independent review checked both overlays and every one of the 1,558 frozen
files against the committed base. See `source-inputs.json` for exact hashes.

After that correction and the actual [current-lock E06 audit](../../e06/audit-codec-heap-lock-ecae67c737e4/RUN.md),
the canonical command executed:

```sh
scripts/e2e/p01 --tier full --receipts "$P01_PRIVATE_RECEIPTS"
python3 -B tests/p01/make_vectors.py --check
```

Actual outcome: **261 total, 254 passed, zero failed, seven blocked**,
`qualified=false`, exit 3. All **523 critical events** were written, with
zero drops or critical loss. This is host contract evidence, not a current
native workspace or device run. The old full-plan receipt remains stale.
The E06 inventory retains 23 human review items and 34 unrun build checks.

## Native attempts and custody

The required native command was prepared against the exact reviewed export:

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker "$P01_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-board-profile --test p01_contract --locked --offline -j1 -- --show-output
```

| Native job | Actual outcome | Cargo/tests |
|---|---|---|
| 30104858719683023 | Source upload timed out at 77 seconds; supported same-ID preparation cancellation settled custody | Not started; zero tests |
| 30104858719683026 | Remote disk reservation refused, causal `started=false`, exit 120 | Not started; zero tests |
| 30104858719683029 | A different worker's source upload also timed out at 77 seconds; same-ID cancellation settled custody | Not started; zero tests |

None supplied a source-content receipt or native test footer. The supervisor
independently checked terminal acknowledgements, absent wrappers and complete
source/tree/pair release and retirement for all three. No local retrieval
stage was created. The admission job's wrapper execution flag is true; it
does not override the causal fact that Cargo never started. The subsequent
board-profile Clippy command was **not submitted**. Neither native gate is
credited. Placements stopped after the repeated transfer failure; no floor,
fallback, timeout, source filter or test assertion was weakened.

## Retained qualification mistakes and remaining work

An earlier private one-edge export omitted the required vector identity
refresh and changed executable wrappers from 0755 to 0500. Existing checks
correctly rejected both. Its successor used the two exact overlays and 0555
wrapper modes, preserving all execute bits while keeping source read-only.
That export's machinery still encountered EACCES when an existing test tried
to mutate its own copied read-only fixture. The canonical run above uses the
original source modes and passes that same unchanged machinery. All earlier
errors remain retained; they do not count as passing executions.

The remaining seven blocked cases concern current-plan native/runtime and
artifact proof, compiler identity, service-profile distinction, central
metadata graphs and four live-planning acceptance mismatches. The narrow
four-test native replay and Clippy remain unrun. This correction does not
close P01, E06 or S02, refresh old receipts, or qualify replacement firmware.
