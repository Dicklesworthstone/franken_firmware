# N03 final runner acceptance evidence

Consumer: independent original-acceptance review of `ffw-u07`. This evidence expires when a code hash in `verification.json` changes.

Actual root commands:

```
python3 -B -I -m unittest discover -s tests/n03 -p 'test*.py'
scripts/e2e/n03 --tier full --judge <actual selected host log> <actual current single-test log> --receipts <fresh directory>
scripts/e2e/n03 --tier smoke --judge <same actual logs> --receipts <fresh directory>
scripts/e2e/n03 --tier soak --receipts <fresh directory>
scripts/e2e/n03 --tier full --judge <missing synthetic secret-bearing path> --receipts <fresh directory>
```

Results: 81/81 Python tests; full 33/33 cases with 67/67 critical diagnostic events, zero dropped or lost critical events; smoke exit0; soak explicitly NOT RUN exit4; missing secret-bearing path refuses2 with no token in output or retained files. No real credential was used. Source hashes, complete structured full receipt/JSONL, concise full output, unit output and actual mode outputs are retained here. Only temporary receipt-directory prefixes and trailing horizontal whitespace in human summaries were normalized; original full-output and mode-output hashes are recorded. Receipts/JSONL and unit output are byte copies.

OrangeHarbor independently reproduced post-admission file growth and real growth after `fstat`: both refuse before judging. A regular-file-to-FIFO swap refuses under a two-second alarm. An accepted credential-bearing log basename is redacted in stdout, receipts and JSONL while the actual judged-byte digest and ordinary filename are retained. The permitted regular log still reaches judging. Root separately confirmed AST identity of registry, required-test derivation, comparison, world oracle, target-receipt checker and selector against ff3dcc1. No numeric oracle, threshold, expected outcome or case was removed.

The deadline is cooperative between finite cases. Descriptor reads bound bytes and reject non-regular files; they do not claim to preempt an arbitrary filesystem stall. Temporary parser copies live only in host test infrastructure, not the speaker's device budget.

Rust proof is recorded in the parent folder and actual MIPS guest proof under `toolchain/results/runs/e014873c299ab7860f3e2f860db21525`. These are offline model/ISA qualifications, not provider, physical DAC, acoustic or device-resource qualification. Final bead closure requires the independent supervisor's complete original-acceptance decision.
