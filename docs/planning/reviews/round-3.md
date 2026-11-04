# Plan review round 3 — checked null after bounded revisions

RESULT_STATUS: CHECKED_NULL

No additional material planning correction was found in this pass.
This means the revised plan is sufficiently specified for Beads conversion and offline implementation work.
It does not establish firmware feasibility, hardware safety, measured resource fit, or provider interoperability.
The reviewer authored the integration companion and earlier integration audit; this is a fresh challenger pass, not independent authorship of that companion.

## Reviewed artifacts

- Main plan: docs/SLIM_SPEAKER_PLAN.md, including embedded runtime/integration specifications and canonical task definitions.
- Enriched machine-readable task catalog: docs/planning/task-catalog.json.
- Design-package mapping: docs/planning/design-crosswalk.md.
- Prior round-2 findings and earlier integration challenger findings.

Snapshot SHA-256 receipts:

- Main plan: `19a3f13ec28ef95d63d68fed3c3da6572623512f0e176c4086235907602d3a11`.
- Catalog: `23567b98516e6fadb7b471e5a7b3f59878d73b6c9e97683d3091249907192cf0`.
- Crosswalk: `4e836a2727e77e8b07723d41130f0f711e06b1bf5357b219beb7a5ae216fae50`.

## Graph and consistency checks actually performed

A Python read-only check loaded all catalog entries and recursively visited their dependencies.
There are 46 unique canonical tasks, with no dangling dependency or cycle detected.
Every catalog title, scope, and acceptance string occurs in the current main plan.
Every catalog task includes a substantive detailed contract for its downstream issue body.
All 15 runtime packages and all 18 integration packages have canonical task mappings: 33/33 covered.
The crosswalk declares canonical keys as completion owners and does not propose duplicate companion issues.
These checks validate planning data, not executable product behavior.

The Q03 dependency closure contains the Spotify/render/control/activation-handoff baseline.
It excludes AirPlay, video, line-in, native Tailscale, Alexa, optional FEC, gateway, and voice branches.
The Q05 closure includes T02, X04, A02, V02, and L01 for the complete requested integration campaign.
It excludes optional N05/N06, T03, and X03.
The X03 closure excludes X01/X02/X04, so local voice feasibility no longer waits for Alexa admission.

## Requirement preservation and executable acceptance review

| Requirement | Canonical ownership | Concrete acceptance retained |
| --- | --- | --- |
| Reliable Spotify on the slim endpoint | S01/S02/S03, Q01/Q02/Q03 | Account/session failure distinctions, negotiated codecs, bounded caches, exact-target peaks, loss/rejoin/soak handoff |
| Unified cross-generation groups | G01/G02, N03/N04, Q01 | One epoch, stale-owner rejection, sample/state assertions, coherent join/leave and volume |
| Native AirPlay 2 | A01/A02, Q04 | Honest capability advertising, pairing persistence/reset, timing and authenticated sessions; gateway cannot satisfy native scope |
| Source-aware YouTube/video sync | V01/V02 | Injected-delay oracle, seek/pause/rate/route cases, source-specific qualification and explicit unsupported applications |
| Native Tailscale | T01/T02, Q04 | Full identity/control feasibility, denied access, expiry, relay/key rotation, WAN-independent local playback |
| Alexa control and music destination | X01/X02/X04 | Duplicate/revoked/unavailable command cases plus a separate supported music-routing mechanism and later utterance-to-group receipt |
| Line-in | L01, Q04 | ADC/DAC timing, capture drift, feedback prevention and explicit unavailable-input behavior |
| Optional local voice | X03 | Board evidence, capture/privacy/indicator contract, model compute budget without audio starvation |
| Existing fsonos control | G03 | Call-surface extraction, SOAP/GENA/topology cases, expiry/escaping/unknown-action behavior |

No native requirement was silently replaced by a host or gateway.
X04 now prevents completion of Alexa music routing through volume-only success.
S02 no longer assumes a Vorbis-only provider contract.
The native Tailscale feasibility decision can close with reproducible rejection while T02 remains blocked.
This is an honest terminating investigation, not a waiver of the owner's native requirement.

## Round-2 correction disposition

N03 now directly consumes P02 clock capabilities and rejects unadmitted/replayed timing inputs.
U01 now specifies old-or-new complete-value recovery under write/sync/publication and torn-record faults.
N02 now depends on durable U01 pairing state and checks authentication before authority-bearing mutation.
G01 owns shared source arbitration; Q01 and Q04 exercise conflicts through actual adapter interfaces.
Q04 now requires combined enabled-feature peak-resource and deadline qualification, including reconnect/key rotation.
The explicit crosswalk and enriched catalog carry companion contracts into canonical issue ownership.
These corrections resolve the material integration and dependency gaps identified in prior passes.

## Remaining empirical uncertainty is correctly left open

The oldest target may still fail native service budgets or old-kernel compatibility.
AirPlay sender behavior and Alexa provider admission still require external interoperability evidence.
Offline timing models do not establish acoustic alignment or universal video lip sync.
Retained driver and radio behavior still require the separate human-led qualification lane.
The advertised small-footprint numbers remain hypotheses, not release acceptance receipts.
The plan specifies discriminating tests for these uncertainties rather than inventing their outcomes.

No further edits are requested by this round. Proceed to Beads conversion with these detailed contracts intact.
