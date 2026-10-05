//! 書き出したバッファのパケット分割の統合テスト
//!
//! `split_packets` の公開 API を検証する。

use shiguredo_ngtcp2::packet::split_packets;
use shiguredo_ngtcp2::varint;

/// 可変長整数をバイト列にする
fn varint_bytes(n: u64) -> Vec<u8> {
    let mut buf = vec![0u8; varint::encoded_len(n)];
    varint::encode(&mut buf, n);
    buf
}

/// Short header のパケットを作る
fn short_packet(len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x40;
    packet
}

/// Initial 以外の Long header のパケットを作る
fn long_packet(first: u8, payload_len: usize) -> Vec<u8> {
    let mut packet = vec![first];
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.push(8);
    packet.extend(std::iter::repeat_n(0x11, 8));
    packet.push(0);
    packet.extend_from_slice(&varint_bytes(payload_len as u64));
    packet.extend(std::iter::repeat_n(0x33, payload_len));
    packet
}

/// Short header のパケット 1 つは分割されないこと
#[test]
fn test_split_packets_short_header() {
    let packet = short_packet(30);
    let packets = split_packets(&packet);
    assert_eq!(packets.len(), 1, "1 パケットであること");
    assert_eq!(packets[0], &packet[..], "中身が変わらないこと");
}

/// Handshake と 1-RTT のパケットが分かれること
///
/// ハンドシェイクが確認される前の CONNECTION_CLOSE がこの形になる。
#[test]
fn test_split_packets_handshake_and_short() {
    // 0xe3 = Long header / Handshake / パケット番号長 3
    let handshake = long_packet(0xe3, 16);
    let short = short_packet(21);

    let mut buf = handshake.clone();
    buf.extend_from_slice(&short);

    let packets = split_packets(&buf);
    assert_eq!(packets.len(), 2, "2 パケットに分かれること");
    assert_eq!(packets[0], &handshake[..], "1 つ目が Handshake であること");
    assert_eq!(packets[1], &short[..], "2 つ目が 1-RTT であること");
}

/// Initial の Token Length を読み飛ばせること (RFC 9000 Section 17.2.2)
#[test]
fn test_split_packets_initial_with_token() {
    // 0xc3 = Long header / Initial / パケット番号長 3
    let mut initial = Vec::new();
    initial.push(0xc3);
    initial.extend_from_slice(&1u32.to_be_bytes());
    initial.push(8);
    initial.extend(std::iter::repeat_n(0x11, 8));
    initial.push(0);
    initial.extend_from_slice(&varint_bytes(4)); // Token Length
    initial.extend(std::iter::repeat_n(0x44, 4)); // Token
    initial.extend_from_slice(&varint_bytes(16)); // Length
    initial.extend(std::iter::repeat_n(0x33, 16));
    let short = short_packet(20);

    let mut buf = initial.clone();
    buf.extend_from_slice(&short);

    let packets = split_packets(&buf);
    assert_eq!(packets.len(), 2, "2 パケットに分かれること");
    assert_eq!(packets[0], &initial[..], "1 つ目が Initial であること");
    assert_eq!(packets[1], &short[..], "2 つ目が 1-RTT であること");
}

/// Retry は単独のパケットとして扱うこと (RFC 9000 Section 17.2.5)
#[test]
fn test_split_packets_retry() {
    // 0xf3 = Long header / Retry / パケット番号長 3 (Retry では未使用)
    let retry = long_packet(0xf3, 16);
    let packets = split_packets(&retry);
    assert_eq!(packets.len(), 1, "1 パケットであること");
    assert_eq!(packets[0], &retry[..], "中身が変わらないこと");
}

/// Version Negotiation は単独のパケットとして扱うこと
/// (RFC 9000 Section 17.2.1)
#[test]
fn test_split_packets_version_negotiation() {
    let mut buf = vec![0x80];
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.push(8);
    buf.extend(std::iter::repeat_n(0x11, 8));
    buf.push(0);
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    let packets = split_packets(&buf);
    assert_eq!(packets.len(), 1, "1 パケットであること");
    assert_eq!(packets[0], &buf[..], "中身が変わらないこと");
}

/// 長さを求められない場合は残りを 1 パケットとして返すこと
#[test]
fn test_split_packets_truncated() {
    let handshake = long_packet(0xe3, 16);
    // Length がバッファの残りより大きい状態を作る
    let truncated = &handshake[..handshake.len() - 4];
    let packets = split_packets(truncated);
    assert_eq!(packets.len(), 1, "1 パケットとして返すこと");
    assert_eq!(packets[0], truncated, "中身が変わらないこと");
}

/// 空のバッファでは何も返さないこと
#[test]
fn test_split_packets_empty() {
    assert!(split_packets(&[]).is_empty(), "空であること");
}
