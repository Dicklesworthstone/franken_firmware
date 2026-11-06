# N01 diagnostic privacy regression

Independent review found that the runner's panic detail reached human output
and JSON receipts without the redaction already used by its JSONL sink. N01 was
reopened against its original logging acceptance. `Result` now applies the
existing Q00 redactor before those outputs and withholds raw detail if the
redactor is unavailable. Failure verdicts and useful causal text are retained.

The new failed-case regression checks the actual human and JSON output for a
synthetic credential canary and the derived home path. The CLI test helper now
has a bounded timeout. The recorded command executed 25 passing Python tests;
`receipt.json` binds its runner, tests and existing logging dependency hashes.

No Rust, wire-format, protocol, fuzz target or device code changed. The earlier
source-bound Rust and fuzz evidence is separate; this record adds no build,
hardware or service qualification. Independent review owns the normal reclose.
