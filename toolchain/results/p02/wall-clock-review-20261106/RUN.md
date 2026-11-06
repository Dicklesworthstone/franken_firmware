# P02 wall-time helper verification

The reviewed helper and its tested dependency closure passed 166 host unit tests,
including all 19 new wall-time cases, and host Clippy with warnings denied.
MIPS and PowerPC compile checks also passed. All four jobs used strict remote
RCH; terminal acknowledgements, wrapper absence and source/tree/pair retirement
are recorded in `receipt.json`. Both owned root wrapper sessions completed.

The receipt contains the exact Cargo argument lists. Reproduce from a frozen
workspace with `RCH_REQUIRE_REMOTE=1 rch exec --` followed by the selected list;
substitute that workspace for the `<workspace>` parameter. Host checks use the
Rust 1.99.0 pin; device checks explicitly use nightly-2026-08-31 and build-std.
`source-bindings.json` binds the actual platform-test dependency closure. The
unrelated newly landed SSDP and syscall-table changes are not claimed rerun.

The four logs retain actual Cargo/Rust output. Full private orchestration logs
are excluded; separate raw/extracted hashes and explicit path/ANSI
transformations are in the receipt. Results and test names are unchanged.
No keys, worker addresses or credential-bearing paths are present.

The earlier hz3 host attempt was refused before execution because its 21 GiB
free space could not meet the 40 GiB requested headroom. It was NOT RUN and earns
no test credit. Actual host tests and Clippy ran on trj after positive native
admission. No resource floor, global setting, local fallback or assertion was
changed to obtain these results.

This is component validation. No service uses the credential gate yet, no time
authority is provisioned, and real kernel/bootstrap and suspend-lifecycle
integration remain unqualified. No firmware guest, physical clock, speaker or
fleet-reliability claim follows from these host and compile checks. P02 stays
open while its original acceptance remains incomplete.
