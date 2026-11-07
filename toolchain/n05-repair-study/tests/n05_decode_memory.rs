//! Actual exhaustive decoder heap measurement. No firmware crate depends on this probe.
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use franken_alloc_probe::{CountingAllocator, is_active, measure};
use n05_repair_study::{
    CodingSymbol, DecodeReject, PROFILE, context, decode_window, encode_repairs, source_payload,
    symbol,
};
use raptorq::{Decoder, EncodingPacket, ObjectTransmissionInformation, PayloadId};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();
const LIMIT: usize = 1024 * 1024;
const SEED: u64 = 0x5eed05;

fn all_symbols() -> (Vec<Vec<u8>>, Vec<CodingSymbol>) {
    let source: Vec<_> = (0..4).map(source_payload).collect();
    let mut symbols: Vec<_> = source
        .iter()
        .enumerate()
        .map(|(i, bytes)| symbol(context(0), i as u32, bytes.clone()))
        .collect();
    let repairs = encode_repairs(context(0), &symbols, SEED).unwrap();
    symbols.extend(repairs);
    (source, symbols)
}
fn rank_deficit(received: &[CodingSymbol]) -> usize {
    let decoder = InactivationDecoder::try_new(4, 1024, SEED).unwrap();
    let mut rows = decoder.constraint_symbols();
    for item in received {
        if item.meta.esi < 4 {
            rows.push(ReceivedSymbol::source(item.meta.esi, item.payload.clone()));
        } else {
            let (columns, coefficients) = decoder.repair_equation(item.meta.esi).unwrap();
            rows.push(ReceivedSymbol::repair(
                item.meta.esi,
                columns,
                coefficients,
                item.payload.clone(),
            ));
        }
    }
    decoder.rank_status(&rows).unwrap().deficit
}
fn independent_decode(received: &[CodingSymbol]) -> Option<Vec<u8>> {
    let config = ObjectTransmissionInformation::new(4096, 1024, 1, 1, 1);
    let mut decoder = Decoder::new(config);
    let mut result = None;
    for item in received {
        if let Some(bytes) = decoder.decode(EncodingPacket::new(
            PayloadId::new(0, item.meta.esi),
            item.payload.clone(),
        )) {
            result = Some(bytes);
        }
    }
    result
}

#[test]
fn n05_actual_decode_peak_heap_upper_bound_includes_temporary_allocations() {
    assert!(is_active(), "planted allocator allocation must be observed");
    let (source, all) = all_symbols();
    let expected: Vec<u8> = source.iter().flatten().copied().collect();
    let mut patterns = Vec::with_capacity(163);
    let mut recovered = 0;
    let mut deficient = 0;
    let mut maximum = 0;
    for mask in 0_u16..256 {
        if mask.count_ones() < 4 {
            continue;
        }
        let received: Vec<_> = all
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, item)| item.clone())
            .collect();
        let input_bytes = received.capacity() * std::mem::size_of::<CodingSymbol>()
            + received
                .iter()
                .map(|item| item.payload.capacity())
                .sum::<usize>();
        // ONLY this actual decode interval is measured. Reference/rank work is outside it.
        let (actual, observed) = measure(|| decode_window(context(0), SEED, &received));
        let deficit = rank_deficit(&received);
        let reference = independent_decode(&received);
        assert!(observed.allocations > 0 && observed.bytes_requested > 4096);
        let upper = input_bytes.checked_add(observed.bytes_requested).unwrap();
        assert!(
            upper <= LIMIT,
            "frozen conservative heap bound failed mask={mask} upper={upper}"
        );
        maximum = maximum.max(upper);
        let status = if deficit == 0 {
            let decoded = actual.expect("full-rank actual decoder must succeed");
            assert_eq!(decoded.source, source);
            assert_eq!(reference, Some(expected.clone()));
            recovered += 1;
            "recovered"
        } else {
            assert!(matches!(actual, Err(DecodeReject::Library)));
            assert!(
                reference.is_none(),
                "independent decoder disagrees with actual rank deficit"
            );
            deficient += 1;
            "rank_deficient"
        };
        patterns.push(serde_json::json!({"mask":mask,"received_symbols":mask.count_ones(),"rank_deficit":deficit,
            "status":status,"retained_input_heap_bytes":input_bytes,"cumulative_decode_requested_bytes":observed.bytes_requested,
            "decode_peak_heap_upper_bound_bytes":upper,"allocation_calls":observed.allocations,"deallocation_calls":observed.deallocations}));
    }
    assert_eq!(patterns.len(), 163);
    assert_eq!(recovered + deficient, 163);
    println!(
        "N05-DECODE-MEMORY {}",
        serde_json::json!({"schema":"n05.decode-memory.v2","profile":PROFILE,"seed":SEED,
        "expected_subsets":163,"observed_subsets":patterns.len(),"recovered_subsets":recovered,"rank_deficient_subsets":deficient,
        "rank_deficiency_note":if deficient == 0 {"none observed in exhaustive admitted subset enumeration"} else {"actual rank deficits independently confirmed by raptorq2.0.1"},
        "decode_peak_heap_upper_bound_bytes":maximum,"limit_bytes":LIMIT,"patterns":patterns,
        "measurement":"actual-allocator-cumulative-conservative-peak-upper-bound; all163 K4/R4 admitted subsets"})
    );
}

#[test]
fn n05_invalid_decode_symbols_refuse_before_matrix_allocation() {
    assert!(is_active());
    let (_, all) = all_symbols();
    assert!(decode_window(context(0), SEED, &all).is_ok());
    for variant in 0..4 {
        let mut bad = all.clone();
        match variant {
            0 => bad[4].meta.epoch = 2,
            1 => bad[4].meta.window = 1,
            2 => bad[4].meta.stream = 2,
            _ => bad[4].meta.esi = u32::MAX,
        }
        let (result, observed) = measure(|| decode_window(context(0), SEED, &bad));
        assert!(matches!(result, Err(DecodeReject::Metadata(_))));
        assert!(
            observed.bytes_requested < 1024,
            "malformed real metadata reached a matrix allocation"
        );
    }
}
