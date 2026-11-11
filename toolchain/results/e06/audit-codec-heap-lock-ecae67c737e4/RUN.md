# E06 source inventory after the codec heap-test dependency

The unchanged existing auditor ran on a clean committed export of
`e4c21da7067449b3522035ca8ac04bc19775d170`. Its actual `audit.json` is copied
byte-for-byte, SHA-256
`74b9caf1f442bf6ce0c775b3829d238aa10fdcad8a775b7df4e0b04199a7f863`.
It binds the 72-entry lockfile
`ecae67c737e47feaef3df83c0521da3ba75886c4a7daa6b7ce51fd0738acb987`.
Only the allocator probe's test dependency on the already present codec was
added; package versions, sources and checksums are unchanged.

The command executed outside the checkout:

```sh
RUSTUP_TOOLCHAIN=nightly-2026-11-02 PYTHONDONTWRITEBYTECODE=1 python3 -B "$E06_EXPORT/scripts/e06/audit.py" audit --manifest-path "$E06_EXPORT/Cargo.toml" --jobs 2 --unsafe-allowed franken-platform-linux --json "$E06_PRIVATE_AUDIT"
```

This is E06's existing local locked/offline resolver and source analysis,
explicitly allowed by the P01 inventory consumer. It performs no compilation,
test, target execution or lock generation. The actual exit is **3**: zero
blockers, **23 review** findings and 57 information findings. Review includes
20 dependency-unsafe items, one soft-float cost item, one native-build signal
and one test-only workspace-unsafe item. Those reviews remain unresolved.
The build-check denominator remains **34 planned, zero passed, zero failed,
34 not run**. Resolved metadata on host, MIPS and PowerPC is not build or
hardware evidence.

The verifier compared all 1,558 exported files, directory/symlink inventory
and executable bits to the committed archive after the analysis; nothing
changed. The supervisor independently checked the report digest and the
existing `tests/p01/inventory.py` judge against the actual current lock:
55 external packages pinned on all three platforms, 17 workspace entries,
zero inventory inconsistencies, with all 23 human review items retained.
Auditor SHA-256 is
`aa126d4615f93966845f749eb7a2e89beda8f129a538f5558128f3db7c25e240`;
private original output log SHA-256 is
`730466a9736dcda75af4826ffe41b264dd8f8f311fab10019c917568aa2573e0`.

This replaces a stale-lock inventory input for P01-BLK-005. It does not
admit dependencies, refresh old runtime receipts or close E06/P01. No prior
audit was edited or relabeled for the new lock.
