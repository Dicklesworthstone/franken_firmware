//! Bounded single-producer/single-consumer frame ring and a bounded capture sink
//! (`D01` / `ffw-f3b`). Contract: `docs/contracts/d01.md`.
//!
//! The ring stores whole frames of one [`StreamFormat`] (packed, interleaved). It is created
//! once (the only allocation) and split into a [`RingProducer`] and a [`RingConsumer`]; after
//! that `push`/`pop` do not allocate, block, log or panic on any caller-controlled length.
//!
//! Safe code only: each byte slot is an `AtomicU8`; the producer publishes with a `Release`
//! store of the tail position and the consumer observes it with an `Acquire` load (and the
//! reverse for the head), so slot contents are never read before they are published.
//!
//! Positions are kept in `[0, 2 * capacity)`, so occupancy is `(tail + 2c - head) % 2c`
//! for any capacity (not only powers of two) and a counter wrap can never become an
//! enormous or discontinuous buffer index.

pub use crate::format::MAX_RING_FRAMES;
use crate::format::{PcmError, StreamFormat, frames_in_packed_bytes};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};

struct RingShared {
    format: StreamFormat,
    capacity_frames: usize,
    bytes_per_frame: usize,
    storage: Box<[AtomicU8]>,
    head: AtomicUsize,
    tail: AtomicUsize,
    overruns: AtomicU32,
    underruns: AtomicU32,
}

impl RingShared {
    /// Positions live in `[0, period)`.
    fn period(&self) -> usize {
        self.capacity_frames * 2
    }

    /// Frames currently stored, for positions `head`, `tail` in `[0, period)`.
    fn used_frames(&self, head: usize, tail: usize) -> usize {
        let period = self.period();
        (tail + period - head) % period
    }
}

fn bump(counter: &AtomicU32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(1))
    });
}

/// Write half of a ring. Not `Clone`: there is exactly one producer.
pub struct RingProducer {
    shared: Arc<RingShared>,
}

/// Read half of a ring. Not `Clone`: there is exactly one consumer.
pub struct RingConsumer {
    shared: Arc<RingShared>,
}

impl std::fmt::Debug for RingProducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingProducer")
            .field("capacity_frames", &self.shared.capacity_frames)
            .field("format", &self.shared.format)
            .finish()
    }
}

impl std::fmt::Debug for RingConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingConsumer")
            .field("capacity_frames", &self.shared.capacity_frames)
            .field("format", &self.shared.format)
            .finish()
    }
}

/// Create a ring holding up to `capacity_frames` frames of `format`.
///
/// This is the only allocating call (control path, before the render path runs). Capacity must
/// be `1..=MAX_RING_FRAMES`.
pub fn ring_channel(
    format: StreamFormat,
    capacity_frames: usize,
) -> Result<(RingProducer, RingConsumer), PcmError> {
    if capacity_frames == 0 || capacity_frames > MAX_RING_FRAMES {
        return Err(PcmError::InvalidRingCapacity {
            frames: capacity_frames,
        });
    }
    let bytes_per_frame = format.bytes_per_frame();
    let total_bytes = capacity_frames
        .checked_mul(bytes_per_frame)
        .ok_or(PcmError::LengthOverflow)?;
    let storage: Vec<AtomicU8> = (0..total_bytes).map(|_| AtomicU8::new(0)).collect();
    let shared = Arc::new(RingShared {
        format,
        capacity_frames,
        bytes_per_frame,
        storage: storage.into_boxed_slice(),
        head: AtomicUsize::new(0),
        tail: AtomicUsize::new(0),
        overruns: AtomicU32::new(0),
        underruns: AtomicU32::new(0),
    });
    Ok((
        RingProducer {
            shared: Arc::clone(&shared),
        },
        RingConsumer { shared },
    ))
}

impl RingProducer {
    /// Append a whole block of packed frames, or nothing.
    ///
    /// Errors: empty / misaligned / over-[`MAX_BLOCK_FRAMES`](crate::format::MAX_BLOCK_FRAMES)
    /// blocks, a block larger than the whole ring ([`PcmError::BlockTooLarge`] with the ring
    /// capacity as `max`), and [`PcmError::RingFull`] when free space is short (counted in
    /// [`overruns`](Self::overruns); the ring is unchanged). Returns the frames written.
    pub fn push(&mut self, block: &[u8]) -> Result<usize, PcmError> {
        let shared = &*self.shared;
        let frames = frames_in_packed_bytes(block.len(), &shared.format)?;
        if frames > shared.capacity_frames {
            return Err(PcmError::BlockTooLarge {
                frames,
                max: shared.capacity_frames,
            });
        }
        let tail = shared.tail.load(Ordering::Relaxed);
        let head = shared.head.load(Ordering::Acquire);
        let free = shared.capacity_frames - shared.used_frames(head, tail);
        if frames > free {
            bump(&shared.overruns);
            return Err(PcmError::RingFull {
                free_frames: free,
                needed_frames: frames,
            });
        }
        let total_bytes = shared.storage.len();
        // `tail % capacity < capacity`, so `index < total_bytes`; it wraps back to 0 below.
        let mut index = (tail % shared.capacity_frames) * shared.bytes_per_frame;
        for &byte in block {
            shared.storage[index].store(byte, Ordering::Relaxed);
            index += 1;
            if index == total_bytes {
                index = 0;
            }
        }
        shared
            .tail
            .store((tail + frames) % shared.period(), Ordering::Release);
        Ok(frames)
    }

    /// Frames of free space right now (a lower bound; the consumer may free more).
    #[must_use]
    pub fn free_frames(&self) -> usize {
        let shared = &*self.shared;
        let tail = shared.tail.load(Ordering::Relaxed);
        let head = shared.head.load(Ordering::Acquire);
        shared.capacity_frames - shared.used_frames(head, tail)
    }

    #[must_use]
    pub fn capacity_frames(&self) -> usize {
        self.shared.capacity_frames
    }

    #[must_use]
    pub fn format(&self) -> &StreamFormat {
        &self.shared.format
    }

    /// Number of rejected pushes ([`PcmError::RingFull`]); saturating.
    #[must_use]
    pub fn overruns(&self) -> u32 {
        self.shared.overruns.load(Ordering::Relaxed)
    }
}

impl RingConsumer {
    /// Fill `out` with whole frames, or leave the ring and `out` untouched.
    ///
    /// `out.len()` selects the block size. Errors: empty / misaligned / oversize `out`, a block
    /// larger than the ring, and [`PcmError::RingUnderrun`] when fewer frames are queued
    /// (counted in [`underruns`](Self::underruns)). Returns the frames read.
    pub fn pop(&mut self, out: &mut [u8]) -> Result<usize, PcmError> {
        let shared = &*self.shared;
        let frames = frames_in_packed_bytes(out.len(), &shared.format)?;
        if frames > shared.capacity_frames {
            return Err(PcmError::BlockTooLarge {
                frames,
                max: shared.capacity_frames,
            });
        }
        let head = shared.head.load(Ordering::Relaxed);
        let tail = shared.tail.load(Ordering::Acquire);
        let available = shared.used_frames(head, tail);
        if frames > available {
            bump(&shared.underruns);
            return Err(PcmError::RingUnderrun {
                available_frames: available,
                needed_frames: frames,
            });
        }
        let total_bytes = shared.storage.len();
        let mut index = (head % shared.capacity_frames) * shared.bytes_per_frame;
        for slot in out.iter_mut() {
            *slot = shared.storage[index].load(Ordering::Relaxed);
            index += 1;
            if index == total_bytes {
                index = 0;
            }
        }
        shared
            .head
            .store((head + frames) % shared.period(), Ordering::Release);
        Ok(frames)
    }

    /// Frames queued right now (a lower bound; the producer may add more).
    #[must_use]
    pub fn available_frames(&self) -> usize {
        let shared = &*self.shared;
        let head = shared.head.load(Ordering::Relaxed);
        let tail = shared.tail.load(Ordering::Acquire);
        shared.used_frames(head, tail)
    }

    #[must_use]
    pub fn capacity_frames(&self) -> usize {
        self.shared.capacity_frames
    }

    #[must_use]
    pub fn format(&self) -> &StreamFormat {
        &self.shared.format
    }

    /// Number of rejected pops ([`PcmError::RingUnderrun`]); saturating.
    #[must_use]
    pub fn underruns(&self) -> u32 {
        self.shared.underruns.load(Ordering::Relaxed)
    }
}

/// Destination for finished output blocks (a device owner, a file, a test capture).
pub trait BlockSink {
    /// Accept one non-empty block, or return a typed error without partial effects.
    fn write_block(&mut self, block: &[u8]) -> Result<(), PcmError>;
}

/// In-memory sink with a fixed capacity reserved up front; `write_block` never reallocates.
#[derive(Debug)]
pub struct BoundedCaptureSink {
    buffer: Vec<u8>,
    capacity: usize,
}

impl BoundedCaptureSink {
    /// Reserve `capacity` bytes now (control path).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Forget captured bytes; the reservation is kept.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl BlockSink for BoundedCaptureSink {
    fn write_block(&mut self, block: &[u8]) -> Result<(), PcmError> {
        if block.is_empty() {
            return Err(PcmError::EmptyBlock);
        }
        // `buffer.len() <= capacity` always holds, so this cannot underflow.
        let remaining = self.capacity - self.buffer.len();
        if block.len() > remaining {
            return Err(PcmError::BufferTooSmall {
                have: remaining,
                need: block.len(),
            });
        }
        self.buffer.extend_from_slice(block);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{Endian, MAX_BLOCK_FRAMES, SampleFormat};
    use std::collections::VecDeque;

    fn mono_s16() -> StreamFormat {
        StreamFormat::new(SampleFormat::S16, Endian::Big, 1, 48_000).unwrap()
    }

    /// `n` frames of mono `s16` whose bytes are `start, start+1, ...` (wrapping).
    fn pattern(start: u8, frames: usize) -> Vec<u8> {
        (0..frames * 2)
            .map(|i| start.wrapping_add(i as u8))
            .collect()
    }

    #[test]
    fn capacity_is_validated() {
        assert_eq!(
            ring_channel(mono_s16(), 0).unwrap_err(),
            PcmError::InvalidRingCapacity { frames: 0 }
        );
        assert_eq!(
            ring_channel(mono_s16(), MAX_RING_FRAMES + 1).unwrap_err(),
            PcmError::InvalidRingCapacity {
                frames: MAX_RING_FRAMES + 1
            }
        );
        let (p, c) = ring_channel(mono_s16(), 1).unwrap();
        assert_eq!((p.capacity_frames(), c.capacity_frames()), (1, 1));
        assert!(ring_channel(mono_s16(), MAX_RING_FRAMES).is_ok());
    }

    #[test]
    fn fifo_with_wrap_returns_exact_bytes() {
        let (mut p, mut c) = ring_channel(mono_s16(), 5).unwrap(); // 10 bytes of storage
        let a = pattern(1, 3);
        assert_eq!(p.push(&a), Ok(3));
        assert_eq!(p.free_frames(), 2);
        assert_eq!(c.available_frames(), 3);
        let mut out = vec![0u8; 6];
        assert_eq!(c.pop(&mut out), Ok(3));
        assert_eq!(out, a);
        // Tail is now at frame 3: this 4-frame push occupies bytes 6..10 then wraps to 0..4.
        let b = pattern(100, 4);
        assert_eq!(p.push(&b), Ok(4));
        assert_eq!(c.available_frames(), 4);
        let mut out = vec![0u8; 8];
        assert_eq!(c.pop(&mut out), Ok(4));
        assert_eq!(out, b);
        assert_eq!(c.available_frames(), 0);
        assert_eq!(p.free_frames(), 5);
    }

    #[test]
    fn exact_capacity_fills_then_refuses_then_drains() {
        let (mut p, mut c) = ring_channel(mono_s16(), 5).unwrap();
        let full = pattern(7, 5);
        assert_eq!(p.push(&full), Ok(5));
        assert_eq!(p.free_frames(), 0);
        assert_eq!(
            p.push(&pattern(0, 1)),
            Err(PcmError::RingFull {
                free_frames: 0,
                needed_frames: 1
            })
        );
        assert_eq!(p.overruns(), 1);
        let mut out = vec![0u8; 10];
        assert_eq!(c.pop(&mut out), Ok(5));
        assert_eq!(out, full, "a refused push must not disturb stored data");
        assert_eq!(p.push(&pattern(9, 5)), Ok(5)); // reusable after a drain
    }

    #[test]
    fn full_and_underrun_leave_state_untouched_and_are_counted() {
        let (mut p, mut c) = ring_channel(mono_s16(), 5).unwrap();
        let mut sink = vec![0xEEu8; 6];
        assert_eq!(
            c.pop(&mut sink),
            Err(PcmError::RingUnderrun {
                available_frames: 0,
                needed_frames: 3
            })
        );
        assert_eq!(
            sink,
            vec![0xEE; 6],
            "a refused pop must not touch the output"
        );
        assert_eq!(c.underruns(), 1);

        let a = pattern(1, 3);
        assert_eq!(p.push(&a), Ok(3));
        assert_eq!(
            p.push(&pattern(50, 3)),
            Err(PcmError::RingFull {
                free_frames: 2,
                needed_frames: 3
            })
        );
        assert_eq!(p.overruns(), 1);
        assert_eq!(c.pop(&mut sink), Ok(3));
        assert_eq!(sink, a);
        assert_eq!(c.underruns(), 1);
    }

    #[test]
    fn zero_misaligned_oversize_and_larger_than_ring_are_typed_errors() {
        let (mut p, mut c) = ring_channel(mono_s16(), 1000).unwrap();
        assert_eq!(p.push(&[]), Err(PcmError::EmptyBlock));
        assert_eq!(c.pop(&mut []), Err(PcmError::EmptyBlock));
        assert_eq!(
            p.push(&[1, 2, 3]),
            Err(PcmError::MisalignedBlock {
                len: 3,
                bytes_per_frame: 2
            })
        );
        assert_eq!(
            c.pop(&mut [0u8; 5]),
            Err(PcmError::MisalignedBlock {
                len: 5,
                bytes_per_frame: 2
            })
        );
        // Exactly the maximum block fits; one frame more does not.
        assert_eq!(p.push(&pattern(0, MAX_BLOCK_FRAMES)), Ok(MAX_BLOCK_FRAMES));
        assert_eq!(
            p.push(&pattern(0, MAX_BLOCK_FRAMES + 1)),
            Err(PcmError::BlockTooLarge {
                frames: MAX_BLOCK_FRAMES + 1,
                max: MAX_BLOCK_FRAMES
            })
        );
        let mut big = vec![0u8; 2 * (MAX_BLOCK_FRAMES + 1)];
        assert_eq!(
            c.pop(&mut big),
            Err(PcmError::BlockTooLarge {
                frames: MAX_BLOCK_FRAMES + 1,
                max: MAX_BLOCK_FRAMES
            })
        );
        // A block that can never fit a small ring is a distinct error from "currently full".
        let (mut small_p, mut small_c) = ring_channel(mono_s16(), 5).unwrap();
        assert_eq!(
            small_p.push(&pattern(0, 6)),
            Err(PcmError::BlockTooLarge { frames: 6, max: 5 })
        );
        assert_eq!(
            small_p.overruns(),
            0,
            "a never-fits block is not an overrun"
        );
        assert_eq!(
            small_c.pop(&mut [0u8; 12]),
            Err(PcmError::BlockTooLarge { frames: 6, max: 5 })
        );
        assert_eq!(small_c.underruns(), 0);
    }

    #[test]
    fn multichannel_frames_stay_whole_across_the_wrap() {
        let f = StreamFormat::new(SampleFormat::S24In32, Endian::Little, 3, 48_000).unwrap();
        assert_eq!(f.bytes_per_frame(), 12);
        let (mut p, mut c) = ring_channel(f, 4).unwrap(); // 48 bytes
        let a: Vec<u8> = (0..36).collect(); // 3 frames
        assert_eq!(p.push(&a), Ok(3));
        let mut out = vec![0u8; 24];
        assert_eq!(c.pop(&mut out), Ok(2));
        assert_eq!(out, &a[..24]);
        let b: Vec<u8> = (100..136).collect(); // 3 frames: wraps past byte 48
        assert_eq!(p.push(&b), Ok(3));
        let mut rest = vec![0u8; 48];
        assert_eq!(c.pop(&mut rest), Ok(4));
        let mut expected = a[24..].to_vec();
        expected.extend_from_slice(&b);
        assert_eq!(rest, expected);
    }

    /// Deterministic generator for the model test (xorshift32; not `rand`).
    struct Xorshift(u32);

    impl Xorshift {
        fn next(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            x
        }
    }

    #[test]
    fn behaves_like_a_bounded_fifo_model_across_many_position_wraps() {
        for capacity in [1usize, 2, 3, 5, 8, 13] {
            let (mut p, mut c) = ring_channel(mono_s16(), capacity).unwrap();
            let mut model: VecDeque<u8> = VecDeque::new();
            let mut rng = Xorshift(0x1234_5678 ^ capacity as u32);
            let mut counter = 0u8;
            let (mut pushes, mut pops, mut fulls, mut underruns) = (0u32, 0u32, 0u32, 0u32);
            for _ in 0..20_000 {
                let frames = (rng.next() % 4) as usize + 1;
                let model_frames = model.len() / 2;
                if rng.next().is_multiple_of(2) {
                    let block: Vec<u8> = (0..frames * 2)
                        .map(|_| {
                            counter = counter.wrapping_add(1);
                            counter
                        })
                        .collect();
                    if frames > capacity {
                        assert_eq!(
                            p.push(&block),
                            Err(PcmError::BlockTooLarge {
                                frames,
                                max: capacity
                            })
                        );
                    } else if model_frames + frames <= capacity {
                        assert_eq!(p.push(&block), Ok(frames));
                        model.extend(block.iter().copied());
                        pushes += 1;
                    } else {
                        assert_eq!(
                            p.push(&block),
                            Err(PcmError::RingFull {
                                free_frames: capacity - model_frames,
                                needed_frames: frames
                            })
                        );
                        fulls += 1;
                    }
                } else {
                    let mut out = vec![0u8; frames * 2];
                    if frames > capacity {
                        assert_eq!(
                            c.pop(&mut out),
                            Err(PcmError::BlockTooLarge {
                                frames,
                                max: capacity
                            })
                        );
                    } else if model_frames >= frames {
                        assert_eq!(c.pop(&mut out), Ok(frames));
                        let expected: Vec<u8> = model.drain(..frames * 2).collect();
                        assert_eq!(out, expected);
                        pops += 1;
                    } else {
                        assert_eq!(
                            c.pop(&mut out),
                            Err(PcmError::RingUnderrun {
                                available_frames: model_frames,
                                needed_frames: frames
                            })
                        );
                        underruns += 1;
                    }
                }
                assert_eq!(c.available_frames(), model.len() / 2);
                assert_eq!(p.free_frames(), capacity - model.len() / 2);
            }
            assert!(
                pushes > 100 && pops > 100,
                "capacity {capacity}: {pushes}/{pops}"
            );
            assert_eq!(p.overruns(), fulls, "capacity {capacity}");
            assert_eq!(c.underruns(), underruns, "capacity {capacity}");
        }
    }

    #[test]
    fn two_threads_preserve_order_and_content_with_different_block_sizes() {
        const TOTAL_FRAMES: u32 = 60_000;
        let (mut p, mut c) = ring_channel(mono_s16(), 64).unwrap();
        let producer = std::thread::spawn(move || {
            let mut next = 0u32;
            let mut spins = 0u64;
            while next < TOTAL_FRAMES {
                let n = ((next % 7) + 1).min(TOTAL_FRAMES - next);
                let block: Vec<u8> = (0..n)
                    .flat_map(|i| (((next + i) & 0xFFFF) as u16).to_be_bytes())
                    .collect();
                loop {
                    match p.push(&block) {
                        Ok(_) => break,
                        Err(PcmError::RingFull { .. }) => {
                            spins += 1;
                            assert!(spins < 100_000_000, "producer stalled");
                            std::thread::yield_now();
                        }
                        Err(e) => panic!("producer: {e}"),
                    }
                }
                next += n;
            }
            next
        });
        let consumer = std::thread::spawn(move || {
            let mut seen = 0u32;
            let mut spins = 0u64;
            while seen < TOTAL_FRAMES {
                let n = ((seen % 5) + 1).min(TOTAL_FRAMES - seen) as usize;
                let mut out = vec![0u8; n * 2];
                match c.pop(&mut out) {
                    Ok(_) => {
                        for (i, pair) in out.chunks_exact(2).enumerate() {
                            let got = u16::from_be_bytes([pair[0], pair[1]]);
                            let want = ((seen + i as u32) & 0xFFFF) as u16;
                            assert_eq!(got, want, "frame {}", seen + i as u32);
                        }
                        seen += n as u32;
                    }
                    Err(PcmError::RingUnderrun { .. }) => {
                        spins += 1;
                        assert!(spins < 100_000_000, "consumer stalled");
                        std::thread::yield_now();
                    }
                    Err(e) => panic!("consumer: {e}"),
                }
            }
            seen
        });
        // Each side finished only after handling every frame; the consumer checked every value.
        assert_eq!(producer.join().expect("producer thread"), TOTAL_FRAMES);
        assert_eq!(consumer.join().expect("consumer thread"), TOTAL_FRAMES);
    }

    #[test]
    fn capture_sink_is_bounded_and_rejects_empty_blocks() {
        let mut sink = BoundedCaptureSink::with_capacity(6);
        assert!(sink.is_empty());
        assert_eq!(sink.capacity(), 6);
        assert_eq!(sink.write_block(&[]), Err(PcmError::EmptyBlock));
        assert_eq!(sink.write_block(&[1, 2, 3, 4]), Ok(()));
        assert_eq!(
            sink.write_block(&[5, 6, 7]),
            Err(PcmError::BufferTooSmall { have: 2, need: 3 })
        );
        assert_eq!(
            sink.as_bytes(),
            &[1, 2, 3, 4],
            "a refused block has no partial effect"
        );
        assert_eq!(sink.write_block(&[5, 6]), Ok(()));
        assert_eq!(sink.len(), 6);
        assert_eq!(
            sink.write_block(&[7]),
            Err(PcmError::BufferTooSmall { have: 0, need: 1 })
        );
        sink.clear();
        assert!(sink.is_empty());
        assert_eq!(sink.write_block(&[9]), Ok(()));
    }
}
