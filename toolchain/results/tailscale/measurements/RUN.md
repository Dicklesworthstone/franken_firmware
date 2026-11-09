# T01-X02 guest measurements (v3b), 2026-11-08

Four files, copied byte for byte from the operator's local QEMU runs. Nothing here was regenerated, trimmed or re-wrapped. `*.serial.txt` carries bare CR and CRLF bytes from the
guest console; `.gitattributes` in this directory switches line-ending conversion off for it and for the receipts, and `*.serial.txt` is spelled that way because the repository
ignores `*.log`.

| File | sha256 |
| --- | --- |
| `x02-v3b-mips-20261108.json` | `ba467b0ba4f80021d00da79cadb96a64dbdeb2c0319b8b7e7315c9f6998020db` |
| `x02-v3b-mips-20261108.serial.txt` | `525eb000094000a56d6421f7d35772cf6cbcc095903201b24664c4a23dfcfd6e` |
| `x02-v3b-powerpc-20261108.json` | `1314b4d6f91e7d8ecd4d0de7175b28f7c0b6ebeb12eb1fd7010e8f0f5a1b6a9b` |
| `x02-v3b-powerpc-20261108.serial.txt` | `5eabb2d9d4cd9015216b0b6d7d5642f3a0eee4bd8783fa7155a69a4277a468b1` |

Each `.json` is an `ffw.t01.x02_receipt.v1` receipt with `evidence_kind` `captured_guest_execution`; its `transcript_sha256` is the sha256 of the adjacent `.serial.txt`. The
scanner that reads them is `case_resources` in `toolchain/tests/run_cases.py`, which accepts `*.json` directly under this directory and nothing deeper, which is why they live here.

## What produced them

* Probe: `toolchain/src/t01-core-probe/` at the v3b bytes (`src/main.rs` `c2b2c646…`, `Cargo.lock` `cb88a6f5…`). Built centrally for `mips-unknown-linux-musl` and
  `powerpc-unknown-linux-musl` (big-endian, 32-bit), linked with zig 0.14.1 wrappers. The receipt records the ELF's sha256 and byte size and sets
  `source_provenance` to `not_attested_by_this_runner`: the link between these bytes and that source is the operator's build record, not something the receipt proves.
* Guest: `qemu-system-mips -M malta -cpu 24Kf` on the Debian `4.19.0-21-4kc-malta` kernel, and `qemu-system-ppc -M g3beige -cpu G3` on the Debian `4.9.0-0.bpo.6-powerpc` kernel,
  64 MB, no network (`-nic none`), an initramfs holding the E07 supervisor and the probe. Driven by `scripts/e2e/t01 --x02 run`.
* Both passed: `T01X02 END ok=8 fail=0 unknown=0`, `TS_TUNNEL wire_bytes=348`, `CRYPTO_KAT` with the planted fault caught.

## How to re-judge them

`python3 -B -W error -m unittest tests/t01/test_x02_evidence.py` runs `x02_judge analyze` over each committed transcript (the supervisor envelope is satisfied by a header-only
stand-in ELF, since the supervisor binary is not committed) and requires the verdict, transcript hash and child hash to equal the receipt's. It also plants one flipped PHASE and
one END total off by one in copies, and requires each to be refused for the named reason, with the unplanted copy passing again.

## What this does not show

One QEMU guest per architecture, on the harness Debian kernels. No real board, no network, no peer, no enrollment. The probe
exercises known-answer vectors and the core crates only: not `tailscaled`, not the whole library, and not the speaker's resource budget. The VmHWM, VmRSS and CPU figures are the
emulated guest's, on an emulated CPU, and bound nothing about the real device. T01 (`ffw-32a`) stays open.
