//! N01 loopback exchange (bead `ffw-ey5`): a sender and a receiver endpoint exchange exact
//! datagrams over real UDP sockets bound to 127.0.0.1 only. Nothing leaves the host: no LAN
//! discovery, no device, no provider. Only the crate's public API is used.
//!
//! The exchange is lock-step (send one datagram, receive one), so the order seen by the receiver
//! is the order planned here and the assertions do not depend on network scheduling.

use franken_stream::{
    BoundedJitterBuffer, HEADER_LEN_BYTES, MAX_DATAGRAM_BYTES, MAX_PAYLOAD_BYTES, OutboundFrame,
    PlayoutMode, PlayoutPullDecision, StreamId, StreamKey, StreamReceiver, StreamSender,
};
use std::net::UdpSocket;
use std::time::Duration;

const FRAMES_PER_BLOCK: u64 = 256;

fn payload(block: u64) -> Vec<u8> {
    (0..MAX_PAYLOAD_BYTES)
        .map(|i| (i as u8).wrapping_add(block as u8).wrapping_mul(3))
        .collect()
}

fn frame(block: u64) -> OutboundFrame {
    OutboundFrame::media(
        block * FRAMES_PER_BLOCK,
        2_000_000_000 + block * 5_333_333,
        1_995_000_000 + block * 5_333_333,
        payload(block),
    )
}

#[test]
fn two_endpoints_exchange_boundary_datagrams_over_loopback() {
    let key = StreamKey::from_bytes([0x24; 32]);
    let stream = StreamId::new(0x00C0_FFEE_0000_0001).expect("nonzero stream id");

    let rx_socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback receiver");
    rx_socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("receiver timeout");
    let tx_socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback sender");
    tx_socket
        .connect(rx_socket.local_addr().expect("receiver address"))
        .expect("connect sender to receiver");
    let tx_addr = tx_socket.local_addr().expect("sender address");

    let mut sender = StreamSender::new(key.clone(), stream, 4);
    let mut receiver = StreamReceiver::new(key, stream, 4);
    let mut jitter = BoundedJitterBuffer::new(PlayoutMode::Music500ms, 32);

    let genuine: Vec<Vec<u8>> = (0..8)
        .map(|n| sender.send(frame(n)).expect("sender encodes a legal frame"))
        .collect();

    // Tampered copies of block 4, each altered after signing. Offsets follow the documented
    // header layout: format at byte 7, the low byte of the epoch at byte 23.
    let mut payload_flipped = genuine[4].clone();
    payload_flipped[HEADER_LEN_BYTES + 5] ^= 0x10;
    let mut epoch_tampered = genuine[4].clone();
    epoch_tampered[23] ^= 0x01;
    let mut format_tampered = genuine[4].clone();
    format_tampered[7] ^= 0x03;
    let truncated = genuine[4][..genuine[4].len() - 1].to_vec();

    // (datagram, outcome the receiver must report). Reordered, duplicated, tampered, truncated,
    // oversize and tiny datagrams are interleaved with the genuine ones.
    let plan: Vec<(Vec<u8>, &str)> = vec![
        (genuine[0].clone(), "OK"),
        (genuine[1].clone(), "OK"),
        (genuine[3].clone(), "OK"),
        (genuine[2].clone(), "OK"),
        (genuine[3].clone(), "REPLAY_OR_DUPLICATE"),
        (payload_flipped, "AUTH_FAILED"),
        (epoch_tampered, "AUTH_FAILED"),
        (format_tampered, "AUTH_FAILED"),
        (truncated, "TRUNCATED"),
        (vec![0u8; MAX_DATAGRAM_BYTES + 100], "DATAGRAM_TOO_LONG"),
        (vec![0xAB; 3], "PACKET_TOO_SHORT"),
        // The tampered and truncated copies above must not have consumed block 4's sequence number.
        (genuine[4].clone(), "OK"),
        (genuine[5].clone(), "OK"),
        (genuine[6].clone(), "OK"),
        (genuine[7].clone(), "OK"),
    ];

    let mut buf = [0u8; 2048];
    for (index, (datagram, expected)) in plan.iter().enumerate() {
        tx_socket.send(datagram).expect("send datagram");
        let (len, from) = rx_socket
            .recv_from(&mut buf)
            .unwrap_or_else(|e| panic!("datagram {index} was not received on loopback: {e}"));
        assert_eq!(from, tx_addr, "datagram {index} came from the sender");
        assert_eq!(
            &buf[..len],
            &datagram[..],
            "datagram {index}: UDP must deliver the exact bytes, boundaries intact"
        );
        let outcome = match receiver.accept(&buf[..len]) {
            Ok(packet) => {
                jitter
                    .push_packet(&packet, 0)
                    .unwrap_or_else(|e| panic!("datagram {index}: jitter buffer refused: {e}"));
                "OK"
            }
            Err(err) => err.code(),
        };
        assert_eq!(outcome, *expected, "datagram {index}");
    }

    let counters = receiver.counters();
    assert_eq!(counters.datagrams_seen, plan.len() as u64);
    assert_eq!(counters.accepted, 8);
    assert_eq!(counters.rejected_replay, 1);
    assert_eq!(counters.rejected_authentication, 3);
    assert_eq!(counters.rejected_structure, 3);
    assert_eq!(
        counters.mac_verifications, 12,
        "only the three structurally invalid datagrams may skip the MAC"
    );

    // Only authenticated, non-replayed blocks reached scheduling, and each exactly once.
    assert_eq!(jitter.depth(), 8);
    for block in 0..8u64 {
        match jitter.pull_for_frame(block * FRAMES_PER_BLOCK) {
            PlayoutPullDecision::AuthenticBlock(decoded) => {
                assert_eq!(decoded.start_frame, block * FRAMES_PER_BLOCK);
                assert_eq!(decoded.frames, FRAMES_PER_BLOCK as usize);
            }
            other => panic!("block {block}: expected the authentic block, got {other:?}"),
        }
    }
    assert_eq!(jitter.plc_concealed_count(), 0);
    assert_eq!(jitter.late_dropped_count(), 0);
}
