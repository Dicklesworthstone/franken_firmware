//! Thin exact-source generation and independent differential qualification.
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use franken_alloc_probe::{CountingAllocator, measure};
    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator::new();
    use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use asupersync::raptorq::gf256::Gf256;
    use asupersync::raptorq::systematic::SystematicEncoder;
    use franken_stream::fec::*;
    use franken_stream::{StreamId, StreamKey};
    use raptorq::{Decoder, EncodingPacket, ObjectTransmissionInformation, PayloadId};
    use std::sync::atomic::AtomicBool;
    const SEED: u64 = 0x5eed05;

    #[test]
    fn n06_real_ingress_scalar_decode_and_cancel_allocate_no_packet_heap() {
        use franken_stream::playout::{ClockView, PlayoutConfig, PlayoutEngine, PlayoutProfile};
        let (planted, sensor) = measure(|| vec![0_u8; 1024]);
        std::hint::black_box(&planted);
        assert_eq!(planted.len(), 1024);
        assert!(sensor.allocations > 0 && sensor.bytes_requested >= 1024);
        let config = SessionConfig {
            stream: StreamId::new(0x60601).unwrap(),
            epoch: 1,
            presentation_origin_ns: 500_000_000,
            key: StreamKey::from_bytes([0x66; 32]),
        };
        let source = [[3; BYTES]; K];
        let digest = content_digest(&config.metadata(0).unwrap(), &source);
        let wires: Vec<_> = (2..N)
            .map(|esi| {
                sign_symbol(
                    &config,
                    0,
                    esi,
                    if esi < K { 0 } else { 2 },
                    digest,
                    &encode_symbol(&source, esi).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let mut engine = PlayoutEngine::new(
            PlayoutProfile::MUSIC,
            PlayoutConfig {
                work_ns: 1_000_000,
                lead_ns: 1_000_000,
                tolerance_ns: 0,
            },
        )
        .unwrap();
        engine.begin_stream(1, 0, 500_000_000).unwrap();
        let mut receiver = Receiver::new(config).unwrap();
        let view = |group_ns| ClockView {
            group_ns,
            uncertainty_ns: 500_000,
            usable: true,
        };
        let (result, actual) = measure(|| {
            for wire in &wires {
                receiver
                    .ingest(&mut engine, view(20_000_000), wire)
                    .unwrap();
            }
            for i in 0..1000 {
                let state = receiver
                    .poll(
                        &mut engine,
                        view(80_000_000 + i * 30_000),
                        &AtomicBool::new(false),
                    )
                    .unwrap();
                if state == DecodeState::Ready {
                    assert_eq!(
                        receiver
                            .publish(
                                &mut engine,
                                view(80_000_000 + i * 30_000),
                                &AtomicBool::new(false)
                            )
                            .unwrap(),
                        DecodeState::Ready
                    );
                    receiver.stop();
                    return state;
                }
                assert_eq!(state, DecodeState::Pending);
            }
            panic!("real bounded receiver failed to terminate")
        });
        assert_eq!(result, DecodeState::Ready);
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.bytes_requested, 0);
        assert_eq!(receiver.status().counters.recovered, 2);
        println!(
            "N06-ALLOCATION {}",
            serde_json::json!({"schema":"n06.allocation.v1","profile":PROFILE,"sensor_calls":sensor.allocations,"sensor_bytes":sensor.bytes_requested,"packet_allocation_calls":actual.allocations,"packet_requested_bytes":actual.bytes_requested,"fixed_receiver_bytes":Receiver::resident_bytes(),"recovered":receiver.status().counters.recovered})
        );
    }

    #[test]
    fn n06_generator_and_every_gf_product_match_actual_pinned_asup() {
        for a in 0..=255_u8 {
            for b in 0..=255_u8 {
                assert_eq!(solver::multiply(a, b), Gf256(a).mul_field(Gf256(b)).raw());
            }
        }
        for source_index in 0..K {
            let basis: Vec<_> = (0..K)
                .map(|i| vec![u8::from(i == source_index); BYTES])
                .collect();
            let encoder = SystematicEncoder::new(&basis, BYTES, SEED).unwrap();
            for (esi, coefficients) in GENERATOR.iter().enumerate().skip(K) {
                let actual = encoder.repair_symbol(esi as u32);
                assert!(
                    actual
                        .iter()
                        .all(|byte| *byte == coefficients[source_index])
                );
            }
        }
        println!(
            "N06-GENERATOR {}",
            serde_json::json!({"schema":"n06.generator.v1","profile":PROFILE,"asup":CODING_REVISION,"generator":GENERATOR,"gf_products":65536,"basis_encodes":4})
        );
    }

    #[test]
    fn n06_all163_subsets_match_actual_asup_and_independent_raptorq() {
        let source: [[u8; BYTES]; K] =
            std::array::from_fn(|i| std::array::from_fn(|b| ((i * 997 + b * 31) % 251) as u8));
        let source_vec: Vec<Vec<u8>> = source.iter().map(|x| x.to_vec()).collect();
        let encoder = SystematicEncoder::new(&source_vec, BYTES, SEED).unwrap();
        let all: [[u8; BYTES]; N] = std::array::from_fn(|esi| {
            if esi < K {
                source[esi]
            } else {
                encoder.repair_symbol(esi as u32).try_into().unwrap()
            }
        });
        let config = SessionConfig {
            stream: StreamId::new(0x60601).unwrap(),
            epoch: 1,
            presentation_origin_ns: 500_000_000,
            key: StreamKey::from_bytes([0x66; 32]),
        };
        let metadata = config.metadata(0).unwrap();
        let digest = content_digest(&metadata, &source);
        let expected: Vec<u8> = source.iter().flatten().copied().collect();
        let mut observed = 0;
        let mut maximum = 0;
        for mask in 0_u16..256 {
            if mask.count_ones() < 4 {
                continue;
            }
            let actual = InactivationDecoder::try_new(K, BYTES, SEED).unwrap();
            let mut rows = actual.constraint_symbols();
            let mut independent =
                Decoder::new(ObjectTransmissionInformation::new(4096, 1024, 1, 1, 1));
            let mut independently_decoded = None;
            for (esi, bytes) in all.iter().enumerate() {
                if mask & (1 << esi) == 0 {
                    continue;
                }
                if esi < K {
                    rows.push(ReceivedSymbol::source(esi as u32, bytes.to_vec()));
                } else {
                    let (columns, coefficients) = actual.repair_equation(esi as u32).unwrap();
                    rows.push(ReceivedSymbol::repair(
                        esi as u32,
                        columns,
                        coefficients,
                        bytes.to_vec(),
                    ));
                }
                if let Some(bytes) = independent.decode(EncodingPacket::new(
                    PayloadId::new(0, esi as u32),
                    bytes.to_vec(),
                )) {
                    independently_decoded = Some(bytes);
                }
            }
            let real = actual
                .decode(&rows)
                .expect("N05 observed all163 admitted masks full rank");
            assert_eq!(real.source, source_vec);
            assert_eq!(independently_decoded, Some(expected.clone()));
            let mut bounded = IncrementalDecode::new();
            assert_eq!(
                bounded.begin(mask as u8, digest, &metadata),
                DecodeState::Pending
            );
            let mut polls = 0;
            while bounded.state() == DecodeState::Pending {
                bounded.poll(&all, 512, &AtomicBool::new(false));
                polls += 1;
                assert!(polls <= MAX_WORK / 256 + 1);
            }
            assert_eq!(bounded.state(), DecodeState::Ready, "mask={mask}");
            for (i, want) in source.iter().enumerate() {
                assert_eq!(bounded.output(i), Some(want.as_slice()));
            }
            assert!(
                bounded.used() + K as u64 * solver::PUBLICATION_WORK <= MAX_WORK,
                "frozen all-step bound mask={mask}"
            );
            maximum = maximum.max(bounded.used());
            observed += 1;
        }
        assert_eq!(observed, 163);
        println!(
            "N06-SUBSETS {}",
            serde_json::json!({"schema":"n06.subsets.v1","profile":PROFILE,"expected":163,"observed":observed,"recovered":observed,"maximum_work":maximum,"limit_work":MAX_WORK,"includes_publication_reserve":K as u64*solver::PUBLICATION_WORK,"asup":CODING_REVISION})
        );
    }
}
