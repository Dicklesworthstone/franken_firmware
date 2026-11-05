//! The planted bug of the control run (`docs/contracts/n01.md` section 11).
//!
//! A fuzzer that finds nothing proves nothing unless it is shown to find something. In a build with the `control`
//! feature, the harness's call into the real decoder panics when an ACCEPTED packet carries a payload of
//! `CONTROL_PAYLOAD_MIN` to `CONTROL_PAYLOAD_MAX` bytes, the shape of a length-dependent defect that only a mid-sized
//! payload reaches. No seed has such a payload, and no seed is a bit flip or a small arithmetic step from one (the seeds'
//! accepted payloads are 4, 8, 12 and 1024 bytes, that is 1, 2, 3 and 256 frames). Reaching it takes a datagram that is
//! structurally valid, carries a valid tag and declares a frame count in the band: the re-sign mode that fits the payload
//! length to the frame count (`wire::MODE_RESIGN_FIT`) makes that one edit, where the first plant, one exact length, needed
//! two fields to change together and was not found in 20.5 million executions. The plant is here and not in franken-stream
//! on purpose: a device closure crate carries no deliberately broken path, even a gated one. What this proves is reach and
//! reporting; it does not prove the real decoder has no bug the oracles cannot see.

/// The band of planted payload lengths: both ends are multiples of 4 and at most 1024, so a datagram with such a payload
/// can be valid. 50 of the 256 valid lengths, 19.5 percent; a buffer-size defect ("longer than N") would take more.
pub const CONTROL_PAYLOAD_MIN: usize = 600;
pub const CONTROL_PAYLOAD_MAX: usize = 796;

/// Whether a payload length is one the plant fires on.
pub fn in_band(payload_len: usize) -> bool {
    (CONTROL_PAYLOAD_MIN..=CONTROL_PAYLOAD_MAX).contains(&payload_len)
}

/// Whether this build carries the plant.
pub const fn control_enabled() -> bool {
    cfg!(feature = "control")
}

/// Called with the payload length of every packet the decoder accepted.
pub fn after_accept(payload_len: usize) {
    if control_enabled() && in_band(payload_len) {
        panic!("planted decoder bug: payload length {payload_len}");
    }
}
