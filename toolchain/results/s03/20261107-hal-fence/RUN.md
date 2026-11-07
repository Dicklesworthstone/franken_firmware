# S03 HAL output-fence adapter

The six HAL/render integration inputs were qualified in the joint control/HAL snapshot
documented in [the batch record](../../n02/20261107-control-hal/RUN.md). That directory holds
exact source hashes, commands, native output, both BE checks, strict Clippy and retained reds.

The adapter reads the existing HAL session identity, acknowledged generation, accepted output
tail and conservative consumed-position lower bound. It binds those facts to the queue's
source epoch and renderer output domain. It refuses unresolved decoder work and genuinely
busy render blocks; it neither manufactures a flush acknowledgment nor treats a flush request
as completion. The busy accessor uses actual loop state, so abandoned mid-block cancellation
or fault cannot permanently block every later handoff through stale cumulative counters.

All **16 output-fence tests** passed in the 326-test speaker library; the HAL library passed
151 tests, and the complete batch passed 1,107 with zero failures and one unrelated ignored
long soak. Cases include wrong session/generation/rate, unfinished output, conservative
position, failed flush, and cancellation/fault recovery. Source review AM11083 checked the
real HAL generation and output-counter producers. Runtime qualification used the synthetic
backend. No physical driver, native provider or complete S03 admission is claimed.
