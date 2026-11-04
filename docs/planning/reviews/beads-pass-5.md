# Beads polish pass 5 — stored failure/test/self-containment review

Reviewed actual stored `br show --json` descriptions and dependency edges for:
N03 ffw-u07, U01 ffw-mgb, T01 ffw-32a, Q03 ffw-kp9, X04 ffw-myi.
Used `RUST_LOG=off`; compared these five stored prerequisite sets with task-catalog.json.
All five dependency sets match the catalog (14 checked prerequisite edges).
This is a focused stored-state audit, not a claim of a newly verified full 46-task graph.
No Beads records, device state, implementation files, or plan files were modified.

## Required correction: contradictory synchronization acceptance in N03

The stored N03 detailed clock contract says:
"The initial proposed room-group objective is at most one millisecond p99 skew."
The same stored body appends a qualification target of electrical-output p99 <= 2 ms,
maximum <= 5 ms over at least one hour.
Both are provisional but the task does not establish their relationship or precedence.
An implementer or reviewer cannot determine which baseline threshold controls completion.

Bounded exact correction:
Replace the one-millisecond sentence in the runtime source and generated/stored bodies with:
"The baseline group-skew acceptance is defined by the versioned qualification profile below; a one-millisecond p99 objective may be tracked separately as a stretch experiment and does not replace that baseline."
Alternatively remove that obsolete numeric objective while retaining the common qualification profile.
Keep the existing tighter-pair/Sub and analog-measurement requirements.
Regenerate affected descriptions from the corrected source so the contradiction does not return.

## Checked null: U01

Stored scope includes bounded scanner, record schema, publication state machine and old/new oracle.
Stored acceptance includes write/sync/publication interruption, torn records, capacity, checksum,
malformed length, schema mismatch, failed sync, and revocation.
Physical rollback resistance is explicitly separate.
P02/E05 prerequisites match; no further required correction found in this pass.

## Checked null: T01

Stored description now supplies concrete output paths and pinned candidate-table contents.
Synthetic identity/network-map/relay/expiry tests are explicit.
Negative feasibility may complete investigation while leaving native T02 blocked.
Gateway/Go comparison cannot satisfy strict-Rust native implementation.
Combined Q04 admission remains separate from provisional feasibility budgets.
P02/E06 prerequisites match; no further required correction found.

## Checked null: Q03

Stored scope is a human-run qualification definition; it does not authorize device execution.
Inputs include Q02 resources, U03 rollback/activation handoff, and E02 incumbent baseline package.
Acceptance requires predeclared thresholds and distinguishes absolute from comparative evidence.
Embedded synthetic, guest, real-service, and physical proof levels remain separate.
All three prerequisites match; no further required correction found.

## Checked null: X04

Stored description distinguishes Alexa control from supported voice-to-Spotify routing.
Unavailable provider admission remains blocked rather than substituted with volume support.
Later owner-run utterance-to-selected-group evidence is explicit and outside present authority.
S03/G01/X02/X01 prerequisites match; optional local voice remains contextual and not a prerequisite.
No further required correction found.

## Verification limitation

A proposed dynamic Python subprocess wrapper for reading all task IDs was rejected by the
command-review hook because its argument count could not be statically verified.
The review instead used explicit read-only `br show` arguments and parsed their JSON output.
No permission bypass or Beads mutation was attempted.
