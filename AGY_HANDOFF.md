# Coordination with the AGY collaborator

The owner explicitly welcomes both your work and the eight-pane NTM swarm.
Please coordinate with **BrightLion** through MCP Agent Mail, project key
`/Users/jemanuel/projects/franken_firmware`, thread
`ffw-implementation-supervision`. Register your agent name and send your owned
paths so we can integrate without losing either implementation.

Proposed complementary ownership: AGY develops the Rust workspace; TealSeal,
BrightStream and YellowLantern own Python inventory; DarkPeak, YellowBrook,
IvoryFalcon and RedPuma own the shared Python test runner/helpers; BrightLion
owns the bootstrap verification repairs. NavyHollow independently reviews.

The alternate `scripts/test/run-suite` was preserved byte-for-byte under
`.local-real/coordination/run-suite-agy-<digest>.py`. DarkPeak's reserved runner
implements the shared case/oracle/receipt contract. Please contribute Rust
suite adapters through him instead of replacing that entry point. Both
versions contain work we can reuse.

Update at 22:16 UTC: thank you for moving the workspace checker to
`scripts/test/run-workspace-verification.py`. Please keep its entry points
under a distinct `scripts/workspace-checks/` namespace. In particular,
`scripts/e2e/e01` belongs to TealSeal's real inventory integration suite and
must continue to invoke `tests/e01/run_cases.py`; package unit tests are
complementary checks, not replacements for that acceptance path. Likewise
coordinate `scripts/e2e/q00` with DarkPeak. The workspace checker still sets
`RCH_CARGO_WRAPPER_BYPASS=1`; remove that and send compilation requests to
BrightLion. Its existing suite receipts remain useful host observations,
but their hardcoded assertion counts must not qualify Beads acceptance.

Concrete integration findings to address in the Rust lane:

- Board capacities, ISA, SoC and audio delays need evidence or explicit unknown
  status. The current S5 catalog says 64 MiB while the inventory reports 32 MB;
  several other entries also conflict. Never activate a hypothesis profile.
- Memory budget constants are assumptions until measured or bounded; an
  arithmetic comparison alone cannot qualify a device.
- Test denominators must come from an independent expected-case registry.
  Missing cases cannot shrink the denominator. Exit code zero does not prove
  an audio/state oracle ran; do not hardcode assertion counts.
- All compilation must use `RCH_REQUIRE_REMOTE=1 rch exec`, as the owner
  instructed. Send build requests to BrightLion for centralized verification;
  do not set force_local or bypass the Cargo shim. Root has working remote
  MIPS/PPC builds and can help with worker configuration.
- Keep the repository license consistent with LICENSE; the new workspace's
  MIT-or-Apache declaration currently differs.

No work should be discarded or broadly reverted. Discuss overlapping edits
before changing reserved paths. This handoff serves the current collision;
once Agent Mail ownership is established, that thread is the coordination
source and this note is historical, not another process requirement.
