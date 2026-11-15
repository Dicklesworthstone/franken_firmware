# Fresh admission time for actual source packets

The finite-source receiver previously reused one clock view for an entire
carrier poll. A pause could make an authenticated packet at or beyond its
preparation cutoff appear timely. Production now samples after authenticating
each media packet, immediately before N04 admission. A clock error stops further
media reads in that poll and propagates before feedback or capture decisions.
Authenticated sequence consumption remains distinct from prepared output.

The fixed-view adapter exists only in explicit deterministic tests. Two actual
signed localhost UDP tests cover a permitted packet just before cutoff, packets
exactly at and after cutoff (including the exact `Late` counter), and clock
failure with no prepared PCM or additional packet reads.

Executed on the frozen source identified by `source-inputs.sha256`:

- Executable unit tests: job 30109207290184184, **20 passed, 0 failed**.
- Original source/group process tests: job 30109207290184188, **5 passed,
  0 failed**; three source journeys and three group journeys passed their
  original independent PCM, ordering and authentication checks. All seven
  healthy group captures were complete with zero muted blocks.
- Strict remote workspace/all-target Clippy: job 30109207290184191, exit 0,
  `-D warnings`. The previous pinned-worker Clippy request was cancelled before
  admission while another project occupied that worker; it executed no tests
  or compiler and is not a pass.

Source receipts were checked separately against the frozen input bytes, and
terminal ACK plus source/tree/pair retirement was verified. Formatting passed.

This does **not** fix the previously observed 56 ms sleep/wake intervals.
The failed full runs retained in `../20261115-pollable-service/` remain failed.
This is one new-code regression run, not a repeated attempt to erase those
failures. Sampling and admission can themselves be interrupted; no hard wall
deadline, physical output, distributed clock, provider or legacy-target fit is
established. P03 and P05 remain open.
