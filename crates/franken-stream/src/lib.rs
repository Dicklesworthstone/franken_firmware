//! Authenticated Audio Stream Framing, Replay Window, Bounded Jitter Buffer, and FEC
//! (`N01` / `ffw-ey5`, `N04` / `ffw-nx0`, `N05` / `ffw-8cy`, `N06` / `ffw-re8`).

#![forbid(unsafe_code)]

use franken_dsp::{FRAMES_PER_BLOCK, StereoAudioBlock};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

pub const WIRE_MAGIC: [u8; 4] = *b"FFWS";
pub const WIRE_VERSION: u8 = 1;
/// Fixed 56-byte big-endian header:
/// - `0..4`: magic `FFWS`
/// - `4`: version (`1`)
/// - `5`: `fec_index`
/// - `6..8`: `fec_group_id` (`u16` BE)
/// - `8..16`: `session_epoch` (`u64` BE)
/// - `16..24`: `seq` (`u64` BE)
/// - `24..32`: `start_frame` (`u64` BE)
/// - `32..40`: `presentation_time_ns` (`u64` BE)
/// - `40..48`: `consume_by_ns` (`u64` BE)
/// - `48..50`: `payload_len` (`u16` BE)
/// - `50..56`: reserved (`[0u8; 6]`)
pub const HEADER_LEN_BYTES: usize = 56;
pub const AUTH_TAG_LEN_BYTES: usize = 16;
pub const MAX_PAYLOAD_BYTES: usize = FRAMES_PER_BLOCK * 4; // 1024 bytes for 256 stereo i16 frames

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum StreamError {
    #[error("packet length {0} is shorter than minimum header+tag size")]
    PacketTooShort(usize),
    #[error("invalid wire magic or unsupported protocol version {version}")]
    UnsupportedWireVersion { version: u8 },
    #[error("payload length {len} exceeds maximum {MAX_PAYLOAD_BYTES}")]
    PayloadTooLarge { len: usize },
    #[error("HMAC authentication tag verification failed")]
    AuthenticationFailed,
    #[error("stale session epoch: packet epoch {packet_epoch} < active epoch {active_epoch}")]
    StaleSessionEpoch {
        packet_epoch: u64,
        active_epoch: u64,
    },
    #[error("packet seq {seq} is outside or already seen in replay window")]
    ReplayOrDuplicatePacket { seq: u64 },
    #[error("packet arrived after its consume_by deadline ({now_ns} > {consume_by_ns})")]
    ExpiredConsumeByDeadline { now_ns: u64, consume_by_ns: u64 },
}

/// Authenticated big-endian audio stream packet (`N01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedStreamPacket {
    pub session_epoch: u64,
    pub seq: u64,
    pub start_frame: u64,
    pub presentation_time_ns: u64,
    pub consume_by_ns: u64,
    pub fec_group_id: u16,
    pub fec_index: u8,
    pub payload: Vec<u8>,
}

impl AuthenticatedStreamPacket {
    /// Encode header + payload + 16-byte truncated HMAC-SHA256 tag in network big-endian byte order.
    pub fn encode_signed(&self, key: &[u8; 32]) -> Result<Vec<u8>, StreamError> {
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(StreamError::PayloadTooLarge {
                len: self.payload.len(),
            });
        }
        let mut buf =
            Vec::with_capacity(HEADER_LEN_BYTES + self.payload.len() + AUTH_TAG_LEN_BYTES);
        buf.extend_from_slice(&WIRE_MAGIC);
        buf.push(WIRE_VERSION);
        buf.push(self.fec_index);
        buf.extend_from_slice(&self.fec_group_id.to_be_bytes());
        buf.extend_from_slice(&self.session_epoch.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.start_frame.to_be_bytes());
        buf.extend_from_slice(&self.presentation_time_ns.to_be_bytes());
        buf.extend_from_slice(&self.consume_by_ns.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&[0u8; 6]);
        debug_assert_eq!(buf.len(), HEADER_LEN_BYTES);
        buf.extend_from_slice(&self.payload);

        let tag = compute_tag_16(key, &buf);
        buf.extend_from_slice(&tag);
        Ok(buf)
    }

    /// Verify HMAC-SHA256 tag and decode big-endian packet fields.
    pub fn decode_and_verify(wire: &[u8], key: &[u8; 32]) -> Result<Self, StreamError> {
        if wire.len() < HEADER_LEN_BYTES + AUTH_TAG_LEN_BYTES {
            return Err(StreamError::PacketTooShort(wire.len()));
        }
        if wire[0..4] != WIRE_MAGIC {
            return Err(StreamError::UnsupportedWireVersion { version: wire[4] });
        }
        let version = wire[4];
        if version != WIRE_VERSION {
            return Err(StreamError::UnsupportedWireVersion { version });
        }
        let payload_len = u16::from_be_bytes([wire[48], wire[49]]) as usize;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(StreamError::PayloadTooLarge { len: payload_len });
        }
        let expected_total = HEADER_LEN_BYTES + payload_len + AUTH_TAG_LEN_BYTES;
        if wire.len() != expected_total {
            return Err(StreamError::PacketTooShort(wire.len()));
        }

        let body = &wire[..HEADER_LEN_BYTES + payload_len];
        let observed_tag = &wire[HEADER_LEN_BYTES + payload_len..];
        let computed_tag = compute_tag_16(key, body);
        let mut diff = 0u8;
        for (&a, &b) in observed_tag.iter().zip(computed_tag.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(StreamError::AuthenticationFailed);
        }

        let fec_index = wire[5];
        let fec_group_id = u16::from_be_bytes([wire[6], wire[7]]);
        let session_epoch = u64::from_be_bytes(wire[8..16].try_into().unwrap());
        let seq = u64::from_be_bytes(wire[16..24].try_into().unwrap());
        let start_frame = u64::from_be_bytes(wire[24..32].try_into().unwrap());
        let presentation_time_ns = u64::from_be_bytes(wire[32..40].try_into().unwrap());
        let consume_by_ns = u64::from_be_bytes(wire[40..48].try_into().unwrap());
        let payload = wire[HEADER_LEN_BYTES..HEADER_LEN_BYTES + payload_len].to_vec();

        Ok(Self {
            session_epoch,
            seq,
            start_frame,
            presentation_time_ns,
            consume_by_ns,
            fec_group_id,
            fec_index,
            payload,
        })
    }
}

fn compute_tag_16(key: &[u8; 32], data: &[u8]) -> [u8; AUTH_TAG_LEN_BYTES] {
    let mut mac = HmacSha256::new_from_slice(key).expect("32-byte HMAC key is valid");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; AUTH_TAG_LEN_BYTES];
    tag.copy_from_slice(&full[..AUTH_TAG_LEN_BYTES]);
    tag
}

/// 64-packet sliding anti-replay and epoch window (`N01`).
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    active_epoch: u64,
    highest_seq: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    #[must_use]
    pub const fn new(active_epoch: u64) -> Self {
        Self {
            active_epoch,
            highest_seq: None,
            bitmap: 0,
        }
    }

    pub fn advance_epoch(&mut self, new_epoch: u64) {
        if new_epoch > self.active_epoch {
            self.active_epoch = new_epoch;
            self.highest_seq = None;
            self.bitmap = 0;
        }
    }

    pub fn check_and_record(&mut self, epoch: u64, seq: u64) -> Result<(), StreamError> {
        if epoch < self.active_epoch {
            return Err(StreamError::StaleSessionEpoch {
                packet_epoch: epoch,
                active_epoch: self.active_epoch,
            });
        }
        if epoch > self.active_epoch {
            self.advance_epoch(epoch);
        }
        match self.highest_seq {
            None => {
                self.highest_seq = Some(seq);
                self.bitmap = 1;
                Ok(())
            }
            Some(high) if seq > high => {
                let shift = seq - high;
                if shift >= 64 {
                    self.bitmap = 1;
                } else {
                    self.bitmap = (self.bitmap << shift) | 1;
                }
                self.highest_seq = Some(seq);
                Ok(())
            }
            Some(high) => {
                let delta = high - seq;
                if delta >= 64 {
                    return Err(StreamError::ReplayOrDuplicatePacket { seq });
                }
                let mask = 1u64 << delta;
                if (self.bitmap & mask) != 0 {
                    return Err(StreamError::ReplayOrDuplicatePacket { seq });
                }
                self.bitmap |= mask;
                Ok(())
            }
        }
    }
}

/// Playout mode controlling target buffering depth (`N04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlayoutMode {
    /// 500 ms target playout horizon (94 blocks of 5.333 ms).
    Music500ms,
    /// 45 ms low-latency video playout horizon (9 blocks of 5.333 ms).
    VideoLowLatency,
}

/// Decision returned when pulling the next due block from [`BoundedJitterBuffer`].
#[derive(Debug, Clone, PartialEq)]
pub enum PlayoutPullDecision {
    /// Exact block arrived in time.
    AuthenticBlock(StereoAudioBlock),
    /// Missing block recovered via bounded XOR parity FEC before its `consume_by_ns` deadline.
    FecRecoveredBlock(StereoAudioBlock),
    /// Block missing at deadline; emitted smooth attenuated PLC concealment block.
    PlcConcealedBlock {
        start_frame: u64,
        consecutive_missing: u32,
        block: StereoAudioBlock,
    },
}

/// Bounded adaptive jitter buffer with `consume_by` cutoff, PLC fade, and 4-packet XOR parity FEC (`N04` / `N06`).
#[derive(Debug, Clone)]
pub struct BoundedJitterBuffer {
    mode: PlayoutMode,
    max_blocks: usize,
    queue: BTreeMap<u64, StereoAudioBlock>,
    last_good_block: Option<StereoAudioBlock>,
    consecutive_missing: u32,
    late_dropped_count: u64,
    plc_concealed_count: u64,
    fec_recovered_count: u64,
}

impl BoundedJitterBuffer {
    #[must_use]
    pub const fn new(mode: PlayoutMode, max_blocks: usize) -> Self {
        Self {
            mode,
            max_blocks: if max_blocks < 4 { 4 } else { max_blocks },
            queue: BTreeMap::new(),
            last_good_block: None,
            consecutive_missing: 0,
            late_dropped_count: 0,
            plc_concealed_count: 0,
            fec_recovered_count: 0,
        }
    }

    #[must_use]
    pub const fn mode(&self) -> PlayoutMode {
        self.mode
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub const fn late_dropped_count(&self) -> u64 {
        self.late_dropped_count
    }

    #[must_use]
    pub const fn plc_concealed_count(&self) -> u64 {
        self.plc_concealed_count
    }

    #[must_use]
    pub const fn fec_recovered_count(&self) -> u64 {
        self.fec_recovered_count
    }

    /// Admit an FEC-recovered block into the jitter buffer.
    pub fn record_fec_recovered_block(&mut self, block: StereoAudioBlock) {
        self.fec_recovered_count = self.fec_recovered_count.saturating_add(1);
        self.queue.insert(block.start_frame, block);
        while self.queue.len() > self.max_blocks {
            let _ = self.queue.pop_first();
        }
    }

    /// Admit an authenticated packet into the jitter buffer if it arrives before `consume_by_ns`.
    pub fn push_packet(
        &mut self,
        pkt: &AuthenticatedStreamPacket,
        now_ns: u64,
    ) -> Result<(), StreamError> {
        if now_ns > pkt.consume_by_ns {
            self.late_dropped_count = self.late_dropped_count.saturating_add(1);
            return Err(StreamError::ExpiredConsumeByDeadline {
                now_ns,
                consume_by_ns: pkt.consume_by_ns,
            });
        }
        let Ok(block) = StereoAudioBlock::from_be_i16_bytes(pkt.start_frame, &pkt.payload) else {
            return Err(StreamError::PayloadTooLarge {
                len: pkt.payload.len(),
            });
        };
        if self.queue.len() >= self.max_blocks
            && !self.queue.contains_key(&pkt.start_frame)
            && let Some(&oldest_frame) = self.queue.keys().next()
        {
            self.queue.remove(&oldest_frame);
        }
        self.queue.insert(pkt.start_frame, block);
        Ok(())
    }

    /// Pull the block for `expected_start_frame`. If absent, synthesize a smooth attenuated PLC block.
    pub fn pull_for_frame(&mut self, expected_start_frame: u64) -> PlayoutPullDecision {
        // Evict any stale blocks older than expected_start_frame
        while let Some(&first_key) = self.queue.keys().next() {
            if first_key < expected_start_frame {
                self.queue.remove(&first_key);
                self.late_dropped_count = self.late_dropped_count.saturating_add(1);
            } else {
                break;
            }
        }

        if let Some(block) = self.queue.remove(&expected_start_frame) {
            self.consecutive_missing = 0;
            self.last_good_block = Some(block.clone());
            return PlayoutPullDecision::AuthenticBlock(block);
        }

        self.consecutive_missing = self.consecutive_missing.saturating_add(1);
        self.plc_concealed_count = self.plc_concealed_count.saturating_add(1);

        let mut concealed = StereoAudioBlock::silence(expected_start_frame);
        // Attenuate previous block exponentially across up to 8 missing blocks (~42 ms), then mute to silence
        if self.consecutive_missing <= 8
            && let Some(prev) = &self.last_good_block
        {
            let decay = 0.7_f32.powi(self.consecutive_missing as i32);
            for i in 0..FRAMES_PER_BLOCK {
                concealed.left[i] = prev.left[i] * decay;
                concealed.right[i] = prev.right[i] * decay;
            }
        }

        PlayoutPullDecision::PlcConcealedBlock {
            start_frame: expected_start_frame,
            consecutive_missing: self.consecutive_missing,
            block: concealed,
        }
    }
}

/// Bounded XOR parity FEC helper (`N05` / `N06`) recovering 1 missing payload in a K-packet group.
#[must_use]
pub fn compute_xor_parity_payload(payloads: &[&[u8]]) -> Vec<u8> {
    let max_len = payloads.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut parity = vec![0u8; max_len];
    for p in payloads {
        for (i, &b) in p.iter().enumerate() {
            parity[i] ^= b;
        }
    }
    parity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_packet_roundtrip_and_tamper_rejection() {
        let key = [0x42u8; 32];
        let pkt = AuthenticatedStreamPacket {
            session_epoch: 7,
            seq: 100,
            start_frame: 25_600,
            presentation_time_ns: 500_000_000,
            consume_by_ns: 495_000_000,
            fec_group_id: 25,
            fec_index: 0,
            payload: vec![0u8; 1024],
        };
        let mut wire = pkt.encode_signed(&key).unwrap();
        let decoded = AuthenticatedStreamPacket::decode_and_verify(&wire, &key).unwrap();
        assert_eq!(decoded, pkt);

        // Flip 1 bit in payload -> must fail HMAC verification
        wire[HEADER_LEN_BYTES + 10] ^= 0x01;
        assert_eq!(
            AuthenticatedStreamPacket::decode_and_verify(&wire, &key),
            Err(StreamError::AuthenticationFailed)
        );
    }

    #[test]
    fn replay_window_rejects_stale_epochs_and_duplicate_sequences() {
        let mut win = ReplayWindow::new(3);
        assert_eq!(
            win.check_and_record(2, 1),
            Err(StreamError::StaleSessionEpoch {
                packet_epoch: 2,
                active_epoch: 3
            })
        );
        assert!(win.check_and_record(3, 10).is_ok());
        assert!(win.check_and_record(3, 8).is_ok());
        assert_eq!(
            win.check_and_record(3, 10),
            Err(StreamError::ReplayOrDuplicatePacket { seq: 10 })
        );
        assert_eq!(
            win.check_and_record(3, 8),
            Err(StreamError::ReplayOrDuplicatePacket { seq: 8 })
        );
    }

    #[test]
    fn jitter_buffer_enforces_consume_by_deadline_and_plc_fade() {
        let mut jb = BoundedJitterBuffer::new(PlayoutMode::Music500ms, 16);
        let mut blk = StereoAudioBlock::silence(0);
        blk.left = [0.5; FRAMES_PER_BLOCK];
        blk.right = [0.5; FRAMES_PER_BLOCK];

        let pkt0 = AuthenticatedStreamPacket {
            session_epoch: 1,
            seq: 0,
            start_frame: 0,
            presentation_time_ns: 100_000_000,
            consume_by_ns: 95_000_000,
            fec_group_id: 0,
            fec_index: 0,
            payload: blk.to_be_i16_bytes(),
        };
        assert!(jb.push_packet(&pkt0, 90_000_000).is_ok());
        // Late packet arriving at 96 ms (> 95 ms consume_by) is rejected
        let mut pkt1_late = pkt0.clone();
        pkt1_late.seq = 1;
        pkt1_late.start_frame = 256;
        assert_eq!(
            jb.push_packet(&pkt1_late, 96_000_000),
            Err(StreamError::ExpiredConsumeByDeadline {
                now_ns: 96_000_000,
                consume_by_ns: 95_000_000
            })
        );

        assert!(matches!(
            jb.pull_for_frame(0),
            PlayoutPullDecision::AuthenticBlock(_)
        ));
        match jb.pull_for_frame(256) {
            PlayoutPullDecision::PlcConcealedBlock {
                start_frame,
                consecutive_missing,
                block,
            } => {
                assert_eq!(start_frame, 256);
                assert_eq!(consecutive_missing, 1);
                assert!(block.left[0] > 0.3 && block.left[0] < 0.4);
            }
            other => panic!("expected PLC concealment, got {other:?}"),
        }
    }
}
