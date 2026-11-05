# Sanitized fleet inventory (model-level, publication-safe)

Observed 2026-11-04 via SSDP + device-description HTTP GET against the owner's
own LAN. **This public copy deliberately omits per-device identifiers** (IP
addresses, MACs, serial numbers, household IDs, room names); raw captures live
in the git-ignored `.local-real/` area only. Counts and hardware classes below
are exactly as observed: 18 distinct devices.

Fleet hardware classes (device-reported nominal RAM/flash — the description XML
gives bare numbers with no unit, shown here as MB, an unverified reading; not
measured available memory):

| Model | Series id | Count | Firmware line | RAM/flash | Notes |
|---|---|---|---|---|---|
| Play:5 Gen1 | P100 (S5) | 8 | S1 57.23-74170 | 32/32 | Dominant constraint of the fleet |
| Play:1 (2013) | A101 (S1) | 2 | S2 86.10-81100 | 128/64 | |
| Play:1 (2018) | A200 (S12) | 2 | S2 86.10-81100 | 256/256 | Roomiest known endpoints |
| Play:3 | A100 (S3) | 1 | S2 86.10-81100 | 128/64 | |
| Sub | A100 | 1 | S2 86.10-81100 | 128/64 | Amp + DSP only, no streaming UI |
| Playbar | A100 (S9) | 1 | S1 57.23-74170 | 128/128 | Optical TV input (not HDMI ARC) |
| Bridge | X999 (ZB100) | 3 | S1 57.23-74170 | 8/8 | Network-only, no audio outputs; excluded from the first audio target. Inventory scope only, not an audio result |

Totals: 18 devices = 15 audio endpoints + 3 Bridges.

Play:3 note: the unit reports a bare memory number of 128, while the cited
published teardown lists 64 MiB RAM for a possibly different revision
(`hardware-profiles.json`, `S3`). The two are not reconciled and neither is a
measurement.

## What the description XML proves (and does not)

Verified per-device from live `device_description.xml`: `modelName`,
`modelNumber`, `seriesid`, `hardwareVersion`, `softwareVersion`/`swGen`,
`memory`, `flash`, `displayName`, `zoneType`, feature bitmasks.

NOT exposed by the XML: CPU/SoC identity, RAM bus width, flash type (NOR vs
NAND), boot chain, radio silicon. Architecture inference from extracted
firmware images (see `FIRMWARE_ASSESSMENT.md` §"Second peer review"):

- Model 16 (internal id; paired with the Play:5 Gen1 by product name only, a
  join still pending owner ratification, `docs/contracts/e01.md` §11 blocker
  3): `anacapad` is ELF32 **big-endian PowerPC**; `audiodev.o` is PowerPC
  relocatable. The committed seed records the join to `S5` as `name-inferred`
  with no image digest. Published teardowns point at an NXP MPC8247 (603e) for
  this vintage — historical hypothesis, not silicon-verified.
- Model 12: `anacapad` is ELF32 **big-endian MIPS**. The committed record
  carries no ISA revision, ABI or float ABI, so "MIPS32" is not established.
  **No live unit is mapped to this image**: no committed evidence joins model
  12 to any unit, and the record is deliberately unjoined
  (`docs/contracts/e01.md` §11, blocker 4). An older note called model 12 the
  Play:1; that label is not used. Which fleet units run MIPS is therefore
  unknown.
- The evidence confirms two instruction-set families exist in extracted images,
  not which live units use which. The teardown profiles in
  `hardware-profiles.json` are hypotheses and never select a board.
- Exact SoC identity per unit is open. Published board evidence can be gathered
  offline (that is what `hardware-profiles.json` holds), but joining a specific
  unit to a board needs per-unit observations from the human-led frankensonos
  process, which this repo does not perform.

## Reproduction

`scan.py` performs the SSDP sweep + description fetch (read-only, owner-run
against the owner's own LAN; it is the only script here that touches a network).
`reconcile.py` is offline and explicit: it reads only the files you name and
never modifies them.

    python3 inventory/reconcile.py --input .local-real/devices.json \
        --evidence inventory/image-evidence.json \
        --private-out .local-real/report.json

prints a sanitized board-profile manifest (counts and model-level classes, no
per-device identifiers) and rejects any output that would contain a value seen
in the private input. Contract, reason codes and tests: `docs/contracts/e01.md`.
Keep real captures out of git.
