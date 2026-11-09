# P05 single-owner profile: big-endian guest runs (MIPS32 and PowerPC32), 2026-11-09

Four files, copied byte for byte from the build owner's local QEMU runs. Nothing here was regenerated, trimmed or re-wrapped. `*.serial.txt` carries bare CR and CRLF bytes from
the guest console; `.gitattributes` in this directory switches line-ending conversion off for it and for the receipts, and `*.serial.txt` is spelled that way because the
repository ignores `*.log`.

| File | sha256 |
| --- | --- |
| `single-owner-mips-20261109.receipt.json` | `7070553e8bac8ef3b7e5a27af73eb54f4368764d3c29d32b663e8fab4f30d917` |
| `single-owner-mips-20261109.serial.txt` | `4606444af9c5fdc3628a4e7ab56636ab05ad1b3cbdbebd5f5a751eb3745850d4` |
| `single-owner-powerpc-20261109.receipt.json` | `45b94ab533f4e4dda5ff1ce4a983a0225bde078d1e77738602142bd813cc0615` |
| `single-owner-powerpc-20261109.serial.txt` | `1c049afeedbec229c499498be4a1ac00f6a7c314031144fec8c7abe03d06d467` |

Each `.receipt.json` is an `ffw.p05.runtime_receipt.v1` receipt with `evidence_kind` `captured_guest_execution`, `profile` `single-owner` and `result`
`accepted_with_declared_unsupported`; its `transcript_sha256` is the sha256 of the adjacent `.serial.txt`. The receipts hold no absolute host path: the writer rewrites a
path outside the repository to `<outside-repo>/<basename>` and lists each rewritten path in `path_hashes` with the sha256 of the file it named.

## What produced them

* Probe: `toolchain/src/p05-runtime/` at `src/main.rs` `5f6337122dbafbe7…`, `Cargo.toml` `e8a0422d…`, `Cargo.lock` `870ae5f5…`, built centrally for `mips-unknown-linux-musl` and
  `powerpc-unknown-linux-musl` (big-endian, 32-bit). The receipts record each ELF's sha256 and byte size and set `source_provenance` to `not_attested_by_this_runner`: the link
  between these bytes and that source is the build owner's record, not something the receipt proves.
* Judge: `toolchain/src/measure-p05-target.py` `69fb914a32e225e7…`, with `--profile single-owner`. Both receipts carry the revision claim
  `3e9c8a0+p05 settle main.rs 5f633712, judge 69fb914a`, which is an operator claim and not an attestation.
* Guest, per architecture:

| | MIPS32 big-endian | PowerPC32 big-endian |
| --- | --- | --- |
| QEMU | `qemu-system-mips -M malta -cpu 24Kf`, 11.1.3 | `qemu-system-ppc -M g3beige -cpu G3`, 11.1.3 |
| Memory, network | 64 MB, `-nographic -no-reboot -nic none` | 64 MB, `-nographic -no-reboot -nic none` |
| Kernel (Debian) | `vmlinux-4.19.0-21-4kc-malta`, sha256 `3803357ef7821dbf691c901105fb9b2b00382abf67fce8a4be2a0d592267dc61` | `vmlinux-4.9.0-0.bpo.6-powerpc`, sha256 `289f40b63ea9aa82743f568ddeaba669a16a859970497dccf7135596da538f98` |
| Probe ELF (`/franken-speaker`) | `134583132a30180cea910c41f942e1ccd8a20793aa09deaa7ece7a6321ed6072`, 2,448,712 bytes | `0338ca6417803500fd2cf7156867ffe6aa109f4def59d6cb761b2b2af8b87e64`, 1,895,640 bytes |
| E07 supervisor ELF (`/init`) | `94ee93ff2ab1bf4a6469f17db8aedfe971c524c05ebd785567898511a76847fc`, 30,788 bytes | `faf5f35a17b11047092a907be5e3ae86097d82682fa44bdb0534b46235caf721`, 27,788 bytes |
| Initramfs archive | `db3db64312300137603c9fe99af413306b9b9b492302ee36935c71971ba3f067` | `7e7f5fcd7e065cf8409cf98b78c01f6f4990af5f8d3e715da04effea9b80ba4e` |

* The initramfs holds the supervisor as `/init`, the probe as `/franken-speaker`, and the profile marker `/ffw_p05_profile` containing exactly `single-owner` and a newline (13
  bytes, sha256 `8cf1b1f89686634cfdfda642fa9cd9b54af2e7d502c61e7f4412887eb481f85f`), because the unchanged supervisor passes the child no argument.
* Command, with placeholders and no host paths (`FFW_BUILD_DIR` names the directory that holds the kernels):

```
FFW_BUILD_DIR=<build-dir> scripts/e2e/p05 --runtime run --arch <mips|powerpc> --profile single-owner \
    --elf <probe-ELF> --supervisor <supervisor-ELF> --log-dir <fresh-log-dir> --receipt <receipt.json> \
    --revision "3e9c8a0+p05 settle main.rs 5f633712, judge 69fb914a"
```

`file(1)` on the two probe ELFs that ran (sha256 `13458313…` and `0338ca64…`), verbatim:

```
mips/ffw-p05-runtime:    ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, stripped
powerpc/ffw-p05-runtime: ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV), statically linked, stripped
```

The QEMU output is the `*.serial.txt` file of each run, and the QEMU version, `QEMU emulator version 11.1.3`, is recorded in each receipt's `execution.qemu`.

## Results

Both runs: `accepted_with_declared_unsupported`, command-line exit 4, all nine gates passed (`P05R-TRANSCRIPT`, `-ENV`, `-PHASES`, `-DECLARED`, `-CLEANUP`, `-CENSUS` "each runtime
drop settled", `-END`, `-SUPERVISOR`, `-CAPTURE`). `END` reads `ops=33 ok=32 failed=0 unsupported=1 partial=0 unknown=0 census_samples=13`, and the one `unsupported` row is the declared
`CALLER_DRIVEN_CURRENT_THREAD`. `FFW_SPEAKER_EXIT status=0`, then `TEST_SUCCESS failures=0`.

| Settle row | MIPS32 | PowerPC32 |
| --- | --- | --- |
| `after_runtime_drop` | `settle=settled settle_threads=1 settle_polls=1` | `settle=settled settle_threads=1 settle_polls=1` |
| `after_byte_budget` | `settle=settled settle_threads=1 settle_polls=2` | `settle=settled settle_threads=1 settle_polls=1` |

On MIPS the settle after the second drop took two readings: the first listed more than the starting count of one thread, the second did not. That is an observation that a thread was
still leaving; it does not say which thread, and it does not reproduce the mechanism the probe's comments give from source reading (a join can return before the kernel unlists the
joined thread).

## How to re-judge them

`python3 -B -W error -m unittest discover -s tests/p05 -p test_single_owner_evidence.py` (from the repository root) checks that the contract's "What ran" figures equal these files, and
runs `measure-p05-target.py analyze-runtime --profile single-owner` over each committed transcript. The supervisor and probe binaries are not committed, so the analysis is given
header-only stand-in ELFs of the right class, byte order and machine (the supervisor envelope is satisfied by the text alone); it requires the verdict, the transcript hash and the
gate results (all but `P05R-CAPTURE`, which needs the live capture) to equal the receipt's. It also plants a changed `END` total, a `settle=pending` row and a transcript without the
settle pairs in copies, and requires each to be refused for the named gate, with the unplanted copy passing again. This proves the committed transcripts satisfy the committed judge.
It proves nothing about the ELFs, the kernels or the guests, which the receipts only record.

## What this does not show

One QEMU guest per architecture, on the harness Debian kernels, not the speakers' stock kernels: no board, no peer, no physical audio. The census figures (`VmRSS`, `VmHWM`,
`MemAvailable`, thread counts) are the emulated guest's on an emulated CPU and bound nothing about the real device; this is not a memory-fit, latency or throughput result. An
accepted run is `accepted_with_declared_unsupported`, not a pass: the caller-driven current-thread mode is declared unsupported from reading the pinned Asupersync source
(`LegacyProfile` cannot build it), not observed. The ELF hashes bind bytes, not their compiler or source provenance. Two runs, one per architecture: the late-leaving thread seen on
MIPS says nothing about how often it happens. P05 (`ffw-ipz`) stays open; `P05-EXT-TARGET-BUILD` is not recorded here as a judgeable result.
