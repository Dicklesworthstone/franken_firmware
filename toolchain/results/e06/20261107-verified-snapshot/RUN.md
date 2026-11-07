# E06 verified snapshot and manifest binding

Base `2f62b3f`; exact code/lock hashes and artifact digests are in `qualification.json`.
Unlinked registry-source scans now consume the archive bytes whose checksums were verified,
instead of reopening a mutable checkout. Snapshot text decoding matches the directory reader,
including universal newlines and invalid UTF-8 replacement. Attested manifest fields bind the
reported library, build script and explicitly declared binary paths before inventory results
are accepted. An omitted or substituted explicit binary cannot produce an unsafe-count zero.

```sh
python3 -W error -B -m unittest discover -s tests/e06 -p 'test_*.py'
RUSTUP_TOOLCHAIN=nightly-2026-08-31 python3 -I -B scripts/e06/audit.py audit --manifest-path Cargo.toml --jobs 2 --unsafe-allowed franken-platform-linux --json <output.json>
python3 -m py_compile scripts/e06/audit.py tests/e06/test_audit.py
```

The full Python suite passed **377 tests, zero failed or skipped**, with warnings treated as
errors. The actual current-tree audit returned **3**: zero blockers, **23 review items** and
57 informational findings. `audit.json` is the actual output, not an admission or a green
build result. Its digest also matches the independent private dry run of this same source
composition. No compiler, guest or physical device was run by these commands.

Source review AM10972 independently reproduced the omitted/wrong-path binary refusals,
library/build-script binding and snapshot text parity, with permitted positive controls.
The earlier historical audit records remain unchanged. Workspace manifests and linked or
upstream scans retain their existing paths; this patch specifically fixes the verified
unlinked-source consumption boundary. It adds no dependency admission or full-firmware claim.
