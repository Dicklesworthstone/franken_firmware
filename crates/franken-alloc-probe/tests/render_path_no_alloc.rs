//! Proof that the D01 render path (convert -> ring -> convert -> sink) does not allocate.
//!
//! This test binary installs `CountingAllocator` as its global allocator. Every measured region
//! runs on the test thread, and the counters are per thread, so other tests running in parallel
//! cannot disturb the counts.

use franken_alloc_probe::{CountingAllocator, is_active, measure};
use franken_dsp::convert::{ConvertStats, convert_block};
use franken_dsp::format::{
    BufferSpec, Endian, MAX_BLOCK_FRAMES, PcmError, SampleFormat, StreamFormat,
};
use franken_dsp::ring::{BlockSink, BoundedCaptureSink, ring_channel};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

fn format(sf: SampleFormat, endian: Endian, channels: u8) -> StreamFormat {
    StreamFormat::new(sf, endian, channels, 48_000).expect("valid test format")
}

#[test]
fn the_counter_is_installed_and_really_counts() {
    assert!(
        is_active(),
        "CountingAllocator is not this binary's global allocator: a zero count would be vacuous"
    );
    let ((), quiet) = measure(|| {
        let x = std::hint::black_box(1u32) + 1;
        let _ = std::hint::black_box(x);
    });
    assert!(
        quiet.is_zero(),
        "plain arithmetic must not allocate: {quiet:?}"
    );

    let (buffer, loud) = measure(|| std::hint::black_box(vec![0u8; 4096]));
    assert!(loud.allocations >= 1, "{loud:?}");
    assert!(loud.bytes_requested >= 4096, "{loud:?}");
    drop(buffer);

    // A growing Vec must show up as allocator calls too.
    let (grown, growth) = measure(|| {
        let mut v: Vec<u8> = Vec::new();
        for i in 0..1000u32 {
            v.push(i as u8);
        }
        v
    });
    assert!(growth.allocations + growth.reallocations >= 2, "{growth:?}");
    drop(grown);
}

#[test]
fn control_path_construction_is_where_allocation_lives() {
    assert!(is_active());
    let (ring, ring_delta) =
        measure(|| ring_channel(format(SampleFormat::F32, Endian::Little, 2), 512));
    assert!(ring.is_ok());
    assert!(
        ring_delta.allocations >= 1,
        "ring_channel allocates once: {ring_delta:?}"
    );

    let (sink, sink_delta) = measure(|| BoundedCaptureSink::with_capacity(4096));
    assert!(sink_delta.allocations >= 1, "{sink_delta:?}");
    assert_eq!(sink.capacity(), 4096);
}

#[test]
fn convert_ring_convert_sink_pipeline_does_not_allocate() {
    assert!(is_active());

    // ---- control path: everything that may allocate happens here, before "Running" ----
    let src_fmt = format(SampleFormat::S16, Endian::Big, 2);
    let ring_fmt = format(SampleFormat::F32, Endian::Little, 2);
    let out_fmt = format(SampleFormat::S24In32, Endian::Big, 2);
    let (src_spec, ring_spec, out_spec) = (
        BufferSpec::packed(src_fmt),
        BufferSpec::packed(ring_fmt),
        BufferSpec::packed(out_fmt),
    );
    let (src_bpf, ring_bpf, out_bpf) = (
        src_fmt.bytes_per_frame(),
        ring_fmt.bytes_per_frame(),
        out_fmt.bytes_per_frame(),
    );
    let (mut producer, mut consumer) = ring_channel(ring_fmt, 3 * MAX_BLOCK_FRAMES).expect("ring");

    let total_frames = 10 * MAX_BLOCK_FRAMES + 37; // ends with a partial block
    let samples: Vec<i16> = (0..total_frames * 2)
        .map(|i| ((i as i32 * 977) % 65_536 - 32_768) as i16)
        .collect();
    let src_pcm: Vec<u8> = samples.iter().flat_map(|v| v.to_be_bytes()).collect();
    assert_eq!(src_pcm.len(), total_frames * src_bpf);

    let mut ring_scratch = vec![0u8; MAX_BLOCK_FRAMES * ring_bpf];
    let mut pop_scratch = vec![0u8; MAX_BLOCK_FRAMES * ring_bpf];
    let mut out_scratch = vec![0u8; MAX_BLOCK_FRAMES * out_bpf];
    let mut sink = BoundedCaptureSink::with_capacity(total_frames * out_bpf);

    // ---- render path: must not touch the allocator at all ----
    let (result, delta) = measure(|| -> Result<(ConvertStats, u32), PcmError> {
        let mut stats = ConvertStats::default();
        let mut frames_done = 0usize;
        while frames_done < total_frames {
            let frames = MAX_BLOCK_FRAMES.min(total_frames - frames_done);
            let src_bytes = &src_pcm[frames_done * src_bpf..(frames_done + frames) * src_bpf];
            stats.merge(convert_block(
                src_bytes,
                &src_spec,
                &mut ring_scratch,
                &ring_spec,
                frames,
            )?);
            producer.push(&ring_scratch[..frames * ring_bpf])?;
            consumer.pop(&mut pop_scratch[..frames * ring_bpf])?;
            stats.merge(convert_block(
                &pop_scratch[..frames * ring_bpf],
                &ring_spec,
                &mut out_scratch,
                &out_spec,
                frames,
            )?);
            sink.write_block(&out_scratch[..frames * out_bpf])?;
            frames_done += frames;
        }

        // Every typed-error path, too: they are `Copy` values and must not allocate either.
        let mut refusals = 0u32;
        let full_block = MAX_BLOCK_FRAMES * ring_bpf;
        refusals += u32::from(producer.push(&[]) == Err(PcmError::EmptyBlock));
        refusals += u32::from(consumer.pop(&mut []) == Err(PcmError::EmptyBlock));
        refusals += u32::from(matches!(
            producer.push(&ring_scratch[..ring_bpf - 1]),
            Err(PcmError::MisalignedBlock { .. })
        ));
        for _ in 0..3 {
            producer.push(&ring_scratch[..full_block])?;
        }
        refusals += u32::from(matches!(
            producer.push(&ring_scratch[..full_block]),
            Err(PcmError::RingFull { .. })
        ));
        for _ in 0..3 {
            consumer.pop(&mut pop_scratch[..full_block])?;
        }
        refusals += u32::from(matches!(
            consumer.pop(&mut pop_scratch[..ring_bpf]),
            Err(PcmError::RingUnderrun { .. })
        ));
        refusals += u32::from(
            convert_block(&src_pcm, &src_spec, &mut ring_scratch, &ring_spec, 0)
                == Err(PcmError::EmptyBlock),
        );
        refusals += u32::from(matches!(
            convert_block(
                &src_pcm,
                &src_spec,
                &mut ring_scratch,
                &ring_spec,
                MAX_BLOCK_FRAMES + 1
            ),
            Err(PcmError::BlockTooLarge { .. })
        ));
        refusals += u32::from(sink.write_block(&[]) == Err(PcmError::EmptyBlock));
        refusals += u32::from(matches!(
            sink.write_block(&out_scratch[..out_bpf]),
            Err(PcmError::BufferTooSmall { .. })
        ));
        Ok((stats, refusals))
    });

    let (stats, refusals) = result.expect("render loop");
    assert!(
        delta.is_zero(),
        "render path touched the allocator: {delta:?} over {total_frames} frames"
    );
    assert_eq!(refusals, 9, "every error path was exercised and refused");
    assert_eq!(
        stats,
        ConvertStats::default(),
        "no sample saturated or was non-finite"
    );

    // The output is also exactly right: s16 -> f32 is exact and f32 -> s24 is `v << 8`, written
    // sign-extended big-endian in the 4-byte container.
    assert_eq!(sink.len(), total_frames * out_bpf);
    let expected: Vec<u8> = samples
        .iter()
        .flat_map(|&v| (i32::from(v) << 8).to_be_bytes())
        .collect();
    assert_eq!(sink.as_bytes(), expected.as_slice());
}

#[test]
fn error_paths_alone_do_not_allocate() {
    assert!(is_active());
    let fmt = format(SampleFormat::S16, Endian::Big, 1);
    let spec = BufferSpec::packed(fmt);
    let (mut producer, mut consumer) = ring_channel(fmt, 4).expect("ring");
    let mut buffer = vec![0u8; 16];
    let mut sink = BoundedCaptureSink::with_capacity(2);

    let (refusals, delta) = measure(|| {
        let mut refusals = 0u32;
        for _ in 0..1_000 {
            refusals += u32::from(producer.push(&[]).is_err());
            refusals += u32::from(producer.push(&[1, 2, 3]).is_err());
            refusals += u32::from(consumer.pop(&mut buffer[..2]).is_err());
            refusals += u32::from(convert_block(&[], &spec, &mut buffer, &spec, 1).is_err());
            refusals += u32::from(sink.write_block(&[]).is_err());
        }
        refusals
    });
    assert_eq!(refusals, 5_000);
    assert!(delta.is_zero(), "error returns allocated: {delta:?}");
}
