//! Negotiated source codecs and the 44.1 -> 48 kHz rate bridge (`S02` / `ffw-6dh`).
//!
//! * [`admission`]: the admission table (`admit`): which negotiated offers are decoded at all, with a named, bounded, redacted refusal for every
//!   other (RedPuma's slice of S02).
//! * [`decode`]: real decoders (Symphonia 0.6.1) for the mandatory set derived from the pinned clients: Ogg Vorbis and MP3 (Spotify), ALAC,
//!   AAC-LC and PCM S16BE (AirPlay). Bounded by [`decode::Caps`]; unsupported material is refused by name.
//! * [`rate_bridge`]: the exact 160/147 polyphase converter, integer arithmetic, with a stated delay and counted operations.
//!
//! The contract, the ledger of negotiated formats (including the BLOCKED rows) and what is NOT claimed are in `docs/contracts/s02.md`.
//! Host tests count operations; there is no CPU, heap or stack claim for any device here.

#![forbid(unsafe_code)]

pub mod admission;
pub mod decode;
pub mod rate_bridge;
mod rate_table;

pub use decode::{
    AacConfig, AlacConfig, BlockInfo, Caps, CodecError, ContainerDecoder, DecodeStats,
    PacketDecoder, PcmFormat, SeekInfo, SourceCodec, SourceReaderLimits, Step, decode_pcm_s16be,
    f32_to_s16, parse_aac_asc, parse_alac_cookie,
};
pub use rate_bridge::{
    BRIDGE_DELAY_IN_FRAMES, BRIDGE_DOWN, BRIDGE_IN_RATE_HZ, BRIDGE_OUT_RATE_HZ, BRIDGE_TAPS,
    BRIDGE_UP, BridgeCounts, BridgeStats, MAX_BRIDGE_CHANNELS, Q23_MAX, Q23_MIN, RateAdapter,
    RateBridge, RateError, RatePlan, f32_to_q23, outputs_after, plan_for_rate, q23_to_f32,
    q23_to_s16, s16_to_q23,
};
