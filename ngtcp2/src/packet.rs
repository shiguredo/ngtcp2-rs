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
