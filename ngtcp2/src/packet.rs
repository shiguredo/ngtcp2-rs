//! 書き出したバッファのパケット分割
//!
//! ngtcp2 は 1 回の書き出しで複数の QUIC パケットを連結して返すことがある。
//! 代表例はハンドシェイクが確認される前の CONNECTION_CLOSE で、この場合は
//! Handshake パケットと 1-RTT パケットが連結される (RFC 9000 Section 12.2 の
//! パケットの連結)。
//!
//! 連結されたバッファをそのまま 1 つのデータグラムとして送ると、ピアが
//! Handshake 鍵を破棄済みの場合にデータグラム全体が破棄され、後続の 1-RTT
//! パケットが届かない。パケットごとに分けて送れるよう、境界を求めるのが
//! このモジュールの役割。

use crate::varint;

/// バッファに連結された QUIC パケットをパケットごとに分割する
///
/// Short header のパケットはデータグラムの末尾まで伸びるため、途中に現れた
/// 場合はそこから最後までが 1 パケットになる。Long header のパケットは
/// Length フィールドから長さを求める。
///
/// 長さを求められない場合は、残りを 1 パケットとして返す。パケットを
/// 落とすより、そのまま送ってピアに判断させるほうが安全なため。
pub fn split_packets(buf: &[u8]) -> Vec<&[u8]> {
    let mut packets = Vec::new();
    let mut rest = buf;

    while !rest.is_empty() {
        let Some(len) = packet_len(rest) else {
            // 長さを求められない場合は残りを 1 パケットとして扱う
            packets.push(rest);
            break;
        };
        let (packet, tail) = rest.split_at(len);
        packets.push(packet);
        rest = tail;
    }

    packets
}

/// 先頭にある QUIC パケットの長さを返す
///
/// 長さを求められない場合は `None`。
fn packet_len(buf: &[u8]) -> Option<usize> {
    let first = *buf.first()?;

    // Short header (1-RTT)。長さのフィールドが無く、データグラムの末尾までが
    // 1 パケットになる (RFC 9000 Section 17.3)
    if first & 0x80 == 0 {
        return Some(buf.len());
    }

    // Long header (RFC 9000 Section 17.2)
    //
    // first (1) + version (4) + DCID Length (1) + DCID + SCID Length (1) + SCID
    let version = u32::from_be_bytes(buf.get(1..5)?.try_into().ok()?);
    // Version Negotiation は Length フィールドを持たず、単独でデータグラムに
    // 入る (RFC 9000 Section 17.2.1)
    if version == 0 {
        return Some(buf.len());
    }

    let mut pos = 5;
    let dcid_len = usize::from(*buf.get(pos)?);
    pos = pos.checked_add(1)?.checked_add(dcid_len)?;
    let scid_len = usize::from(*buf.get(pos)?);
    pos = pos.checked_add(1)?.checked_add(scid_len)?;

    let packet_type = (first & 0x30) >> 4;
    // Retry は Length フィールドを持たず、単独でデータグラムに入る
    // (RFC 9000 Section 17.2.5)
    if packet_type == 3 {
        return Some(buf.len());
    }

    // Initial だけ Token Length を持つ (RFC 9000 Section 17.2.2)
    if packet_type == 0 {
        let (token_len, len) = varint::decode(buf.get(pos..)?)?;
        let token_len = usize::try_from(token_len).ok()?;
        pos = pos.checked_add(len)?.checked_add(token_len)?;
    }

    // Length はパケット番号とペイロードの長さ (RFC 9000 Section 17.2)
    let (length, len) = varint::decode(buf.get(pos..)?)?;
    let length = usize::try_from(length).ok()?;
    let end = pos.checked_add(len)?.checked_add(length)?;

    // バッファの末尾を超える長さは不正なため、分割しない
    (end <= buf.len()).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
