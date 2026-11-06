# P02 wall-time confidence helper

This implements the local bootstrap and validity-window policy required by P02
acceptance item 6. It is a foundation for service adapters, not an implemented
Spotify, AirPlay, tailnet or Alexa connection. No service currently calls it.
Runtime/provider, provisioning and suspend-lifecycle integration remain
unqualified until their owners connect and exercise those paths.

`crates/franken-platform/src/wall_clock.rs` forbids unsafe through its crate.
It consumes the existing workspace HMAC-SHA256 pins. No registry version or
checksum changes are needed. A dedicated, provisioned device/time-authority key
is borrowed; it is never logged, serialized, or exposed through `Debug`.
Possessing a key does not establish that the authority's own time is correct.
Admission of that authority is an external integration obligation. There is no
default authority, guessed date, unchecked RTC path, or disabled TLS validation.

## Bootstrap and wire contract

`AuthenticatedWallClock::begin` reads the admitted platform's monotonic clock
and fills a 32-byte nonce through its selected secure entropy provider. A
simulated platform is refused before either read. Unavailable/unseeded entropy
returns the real typed failure; there is no fallback or nonce synthesized from
time. One pending challenge is retained. A new successful `begin` replaces it.

The fixed 80-byte response contains:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 32 | Challenge nonce |
| 32 | 8 | Earliest Unix nanoseconds, unsigned big-endian |
| 40 | 8 | Latest Unix nanoseconds, unsigned big-endian |
| 48 | 32 | HMAC-SHA256 tag |

The tag covers `b"FFW-P02-TIME-V1\0"` followed by the first 48 response bytes.
The authority-side encoder authenticates supplied bounds; it cannot determine
their truth. The client checks exact length, authenticates the complete body,
and requires the outstanding nonce. Unauthenticated traffic does not consume a
legitimate pending response or replace an existing fresh anchor. An authenticated
matching response consumes its nonce even if its bounds or transit are refused.
Replay without a challenge fails. No socket or provisioning operation is present.

## Confidence and credential policy

Policy explicitly supplies maximum real round-trip time, holdover, interval
width, correction and physical oscillator error. If the counter's physical rate
is between `1-rho` and `1+rho`, a measured duration `d` means real elapsed time
between `floor(d/(1+rho))` and `ceil(d/(1-rho))`. Two admitted clock-resolution
quanta widen the measured difference before this conversion, covering one
quantization-error bound per endpoint read, including same-tick responses.
Arithmetic uses wide intermediates, checked conversion and outward rounding.

The full transit upper bound widens the authority interval. Later intervals
advance from that anchor with the same elapsed bounds. Excessive transit,
uncertainty, expiry or overflow refuses authentication. A large forward or
backward authenticated correction withdraws confidence and requires a fresh
bootstrap. It never changes audio's clock or deadlines.

Each admitted `PlatformLayer` owns an opaque `Arc` epoch token, allocated once
at admission, with native pointer-width reference counts. The wall-time client
retains that token on first real-platform use. Moving a layer preserves its
identity; replacing it is refused, including after the old layer drops. No raw
address or persisted numeric identity is accepted. A monotonic regression,
including one caught by the platform before reaching the client, invalidates the
client until recreation.

`check_credential` permits only an interval wholly inside the half-open window
`[not_before, expires)`. Unknown time, expired/not-yet-valid credentials and
uncertainty crossing either boundary have distinct bounded typed errors and safe
next actions. Certificate signatures/chains, names, revocation and protocol
boundary conventions still belong to the actual service adapter.

The current Linux clock excludes suspend time. The runtime must call
`invalidate_after_resume` before allowing credential checks after resume; that
clears the anchor and challenge while leaving audio time untouched. This helper
does not detect power events. Suspend-safe service admission is unqualified until
that hook is wired and tested against the selected real clock provider.

## Verification boundary

Nineteen Rust unit cases cover a Python-stdlib HMAC golden, response tampering,
replay/replacement, malformed bounds, clock/epoch replacement, read quantization,
slow-oscillator expiration, holdover, correction, resume and credential edges.
Synthetic policy seams remain explicitly synthetic. The public simulated-input
test does not relabel a double as kernel evidence. These tests are not provider
qualification, service integration or physical clock measurements.

The supervisor must run the full `franken-platform` tests and Clippy through
strict remote RCH, plus MIPS/PPC compile checks, before committing this Rust.
Source review, rustfmt, Cargo metadata and the dependency audit are separate
checks and do not establish that the Rust compiles or runs. The owner must still
wire a real authority transport, lifecycle hooks and actual credential consumer;
P02 remains open while its original acceptance is incomplete.
