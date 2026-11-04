# Sanitized fleet inventory (model-level, publication-safe)

Observed 2026-11-04 via SSDP + device-description HTTP GET against the owner's
own LAN. **This public copy deliberately omits per-device identifiers** (IP
addresses, MACs, serial numbers, household IDs, room names); raw captures live
in the git-ignored `.local-real/` area only. Counts and hardware classes below
are exactly as observed: 18 distinct devices.

Fleet hardware classes (device-reported nominal RAM/flash in MB — not measured
available memory):

| Model | Series id | Count | Firmware line | RAM/flash | Notes |
|---|---|---|---|---|---|
| Play:5 Gen1 | P100 (S5) | 8 | S1 57.23-74170 | 32/32 | Dominant constraint of the fleet |
| Play:1 (2013) | A101 (S1) | 2 | S2 86.10-81100 | 128/64 | |
| Play:1 (2018) | A200 (S12) | 2 | S2 86.10-81100 | 256/256 | Roomiest known endpoints |
| Play:3 | A100 (S3) | 1 | S2 86.10-81100 | 128/64 | |
| Sub | A100 | 1 | S2 86.10-81100 | 128/64 | Amp + DSP only, no streaming UI |
| Playbar | A100 (S9) | 1 | S1 57.23-74170 | 128/128 | Optical TV input (not HDMI ARC) |
| Bridge | X999 (ZB100) | 3 | S1 57.23-74170 | 8/8 | No audio; candidate sacrifice units |

Totals: 18 devices = 15 audio endpoints + 3 Bridges.

## What the description XML proves (and does not)

Verified per-device from live `device_description.xml`: `modelName`,
`modelNumber`, `seriesid`, `hardwareVersion`, `softwareVersion`/`swGen`,
`memory`, `flash`, `displayName`, `zoneType`, feature bitmasks.

NOT exposed by the XML: CPU/SoC identity, RAM bus width, flash type (NOR vs
NAND), boot chain, radio silicon. Architecture inference from extracted
firmware images (see `FIRMWARE_ASSESSMENT.md` §"Second peer review"):

- Model 16 (Play:5 Gen1, ZPS5): `anacapad` is ELF32 **big-endian PowerPC**;
  `audiodev.o` is PowerPC relocatable. Published teardowns point at NXP
  MPC8247-class (603e/e300 core) for this vintage — historical hypothesis,
  not silicon-verified.
- Model 12 (Play:1 A101-era): `anacapad` is ELF32 **big-endian MIPS32**.
- Exact SoC identity per unit remains an open, offline-resolvable question
  (kernel version strings, /proc on a devmode-unlocked unit, or board RE).

## Reproduction

`scan.py` performs the SSDP sweep + description fetch (read-only).
`enrich.py`/`reconcile.py` post-process captures into the local (never
committed) `devices.json`. Run them yourself against your own LAN; keep real
captures out of git.
