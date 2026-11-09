# Finite wake-wait consumer evidence

Consumer: P02 finite wake-wait integration and its successor implementer. This is test and compilation evidence for the frozen consumer snapshot, with prior failures retained. It supplies no new guest/QEMU, P03, service/provider or physical-device proof.

## Tested source and publication

The actual test snapshot is base da072bb6f140c725686647c6692ea442411e0dc2 plus combined patch efb3b9934854ccb2b5e6349ab4fe47805fc478beddd0b0aece3592ad41238d6c. All twelve frozen file hashes match the four executed RCH receipts and the corresponding Git blobs in published commit 5e08ab1f5df9f29258c094854d0ce2bbbe9c55e1. This binds the changed bytes; it does not qualify the whole published HEAD. The four complete recorded content sets contain 1,423 files each and are identical. Exact opaque build IDs, receipt roots, source maps and terminal custody are in native-records.json.

## Actual v3 results

| Command | Actual result | Boundary |
|---|---|---|
| d1 speaker library + CLI | exit 0; 42/42 library, 392 filtered; 3/3 CLI, 13 filtered; 0 failed/ignored | 45 distinct selected names, all 12 new consumer names |
| d2 host strict Clippy | executed exit 0 | all-targets compilation/lint |
| d3 BE MIPS strict Clippy | executed exit 0 | compilation only; no target execution |
| d4 BE PPC strict Clippy | executed exit 0 | compilation only; no target execution |
| v3 full P02 judge | planned 13, passed 13, failed 0, blocked 0 | checker evidence |

All four jobs are recorded finished0, strict remote, acknowledged, wrapper dead/owner absent, with source/tree/pair/staging retirement released. BE commands explicitly select nightly-2026-08-31. No rustc -V capture is supplied, so no measured host compiler version is asserted.

The frozen CLI requirement remains 2: diagnose and malformed-provider. The third selected existing case is platform_startup_is_still_refused_on_a_build_with_no_kernel_backend; it also passed. Frozen expectations were not changed to match output.

## Commands and failure history

command-frames.log and manifest.json list the exact seven observed Cargo argv for historical c2/c3 retry/c4 and actual v3 d1–d4, with raw basename, line number, raw frame hash and full raw-file SHA256. These argv come from observed frames; they were not reversed from command_sha256. The derived frame listing omits one presentation-only terminal blank line. v3-batch.log retains the successful all-lines batch.

Historical v2 is retained separately: c2 42 passed; c3 retry 3 passed; the v2 full judge 13/13; c4 host Clippy actually failed101 on one unnecessary_lazy_evaluations diagnostic in cfg(test) Fake::poll. That retry stopped101 and did not start c5/c6. The earlier p02cc queue-timeout attempt was NOT RUN (raw wrapper candidate103, outer/batch104), distinct from the p02c original admission-wait stop143 and the p02cr Clippy stop101. The original batch presentation excerpt was already truncated at capture; its full c3 refusal diagnostic remains separately retained.

The v2 combined patch SHA256 is 81518f2f2d771455379a5652668bfbc39da4320f1bc95316b25a4d46408e7e0f; this differs from consumer-only patch 3ca98b5abaf09c3a0480a2aef5bfe3cd9572c8772f9bd06b28127d4f609f80ff and the final v3 combined patch above. v3-test-only.patch is the exact small v2-to-v3 lint correction; reversing its unique delta on the published v3 file restores historical v2 source hash d0c0d486e9dc5f380f7c234fe693370d7b198e6b8bf0bf8514e1024d8c3bef73. v2 test passes do not stand in for v3; v3 has its own actual results above.

## Retained output and privacy

The actual Cargo test and diagnostic output is preserved, apart from operational identifier/path pseudonyms and ANSI removal. Seven giant source-content receipt payload lines are omitted; manifest.json retains each omitted line hash/byte count and each complete raw-input hash/byte count. Receipt-root values are in native-records.json. Historical c4 receipt metadata was extracted from the omitted source-content-receipt line in raw p02cr-c4-host-clippy.log; its full raw-input and omitted-line hashes are retained in manifest.json. All operational absolute paths, including root-home toolchain locations, are replaced; normal public documentation URLs remain. IP, MAC, UUID, account and worker labels are pseudonymized.

Archive preparation performed no builds, source or skill changes, Git mutations, tracker edits or device actions. Independent delta and privacy review completed before publication; later evidence may supersede these observations while the original failures remain historical.
