//! 送信待ちのストリームデータをパケットに書き出す共通処理
//!
//! QUIC は複数のストリームデータを 1 つのパケットにまとめられる。ngtcp2 の
//! `ngtcp2_conn_writev_stream` は `NGTCP2_WRITE_STREAM_FLAG_MORE` を付けて
//! 呼ぶと `NGTCP2_ERR_WRITE_MORE` を返し、続けて別のストリームを詰められる
//! (ngtcp2 の API 契約。RFC ではなく ngtcp2 のドキュメントに規定がある)。
//! MORE を付けた呼び出しの後は `ngtcp2_conn_write_pkt` でパケットを完成させる
//! 必要がある。
//!
//! クライアントとサーバーで同じ手順が必要なため、このモジュールにまとめる。

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;

use shiguredo_ngtcp2::{Connection, Error, PathInfo, Result, StreamId};

/// 送信するパケット
///
/// 接続のマイグレーション中は、経路検証のパケットだけを別のアドレスへ送る
/// 必要がある (RFC 9000 Section 9.3)。そのためパケットごとに送信先を保持する。
pub(crate) struct OutgoingPacket {
    /// パケットのバイト列
    pub(crate) data: Vec<u8>,
    /// 送信元アドレス
    ///
    /// サーバーは優先アドレス (RFC 9000 Section 9.6) 用に 2 つ目のソケットを
    /// 持てるため、パケットごとにどのソケットから送るかを保持する。
    pub(crate) local: SocketAddr,
    /// 送信先アドレス
    pub(crate) remote: SocketAddr,
    /// 付ける ECN コードポイント (RFC 9000 Section 13.4.1)
    ///
    /// ngtcp2 が指定した値。ECN 非対応 (0) の場合は何も付けない。
    pub(crate) ecn: u8,
}

impl OutgoingPacket {
    /// 書き出したパケットと ngtcp2 が返した経路から作る
    ///
    /// `written > 0` の場合、ngtcp2 は必ず経路を返す
    /// (`ngtcp2_conn_writev_stream` の契約)。返らない場合は実装側の不具合。
    pub(crate) fn from_written(data: Vec<u8>, path: Option<PathInfo>, ecn: u8) -> Result<Self> {
        let Some(path) = path else {
            return Err(Error::Internal(
                "ngtcp2 did not report the path of the written packet".to_string(),
            ));
        };
        Ok(Self {
            data,
            local: path.local,
            remote: path.remote,
            ecn,
        })
    }
}

/// CONNECTION_CLOSE として書き出したバッファをパケットごとの送信に分ける
///
/// ngtcp2 はハンドシェイクが確認される前に CONNECTION_CLOSE を書き出すとき、
/// Handshake パケットと 1-RTT パケットを連結して返す。連結したまま 1 つの
/// データグラムで送ると、ピアが Handshake 鍵を破棄済みの場合にデータグラム
/// 全体が破棄され、1-RTT の CONNECTION_CLOSE が届かない。そのためパケットごとに
/// 分けて送る (RFC 9000 Section 12.2)。
pub(crate) fn close_packets(
    data: &[u8],
    local: SocketAddr,
    remote: SocketAddr,
    ecn: u8,
) -> Vec<OutgoingPacket> {
    shiguredo_ngtcp2::packet::split_packets(data)
        .into_iter()
        .map(|packet| OutgoingPacket {
            data: packet.to_vec(),
            local,
            remote,
            ecn,
        })
        .collect()
}

/// 送信待ちのストリームデータ
///
/// ストリーム ID ごとにデータと FIN の予約を保持する。ngtcp2 のフロー制御や
/// 輻輳制御で書ききれなかった分がここに残り、次の flush で再試行される。
pub(crate) struct PendingStreams {
    /// ストリーム ID -> (送信待ちデータ, このデータの後ろで終端するか)
    entries: HashMap<StreamId, (Vec<u8>, bool)>,
    /// 送信順を安定させるためのストリーム ID の集合
    order: BTreeSet<StreamId>,
}

impl PendingStreams {
    /// 空の送信待ちキューを作成する
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: BTreeSet::new(),
        }
    }

    /// ストリームデータを送信待ちに積む
    ///
    /// 同じストリームに対する複数回の呼び出しは順に連結される。
    pub(crate) fn push(&mut self, stream_id: StreamId, data: &[u8], fin: bool) {
        let entry = self
            .entries
            .entry(stream_id)
            .or_insert_with(|| (Vec::new(), false));
        entry.0.extend_from_slice(data);
        entry.1 |= fin;
        self.order.insert(stream_id);
    }

    /// ストリームの送信待ちを破棄する
    pub(crate) fn remove(&mut self, stream_id: StreamId) {
        self.entries.remove(&stream_id);
        self.order.remove(&stream_id);
    }

    /// 送信待ちのストリームが無いかどうかを返す
    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// 送信順に並んだストリーム ID を返す
    fn ordered_ids(&self) -> Vec<StreamId> {
        self.order.iter().copied().collect()
    }

    /// 送信待ちが空になったストリームを取り除く
    fn prune(&mut self, stream_id: StreamId) {
        if self
            .entries
            .get(&stream_id)
            .is_some_and(|(data, fin)| data.is_empty() && !fin)
        {
            self.remove(stream_id);
        }
    }
}

/// 送信待ちのデータと制御フレームをパケットに書き出す
///
/// 戻り値は送信するパケットの一覧 (送信先アドレス付き)。送信待ちが空にならない場合 (フロー制御や
/// 輻輳制御で進まない場合) は、書き出せた分だけを返して残りは保持する。
pub(crate) fn write_packets(
    conn: &mut Connection,
    pending: &mut PendingStreams,
    send_buf: &mut [u8],
    ts: u64,
) -> Result<Vec<OutgoingPacket>> {
    let mut packets: Vec<OutgoingPacket> = Vec::new();

    // 各パケットについて、詰められるストリームデータを詰めてから完成させる。
    // 1 回の呼び出しで送れるだけ送るが、進まなくなったら抜ける。
    loop {
        let ids = pending.ordered_ids();
        let mut wrote_any = false;
        // ストリームデータを含まないパケットを書き出したかどうか。
        // 経路 MTU の探索 (PING と PADDING) はストリームデータを載せずに
        // パケット 1 つを使い切るため、続けてもう 1 度書き出す必要がある
        let mut wrote_packet = false;
        let mut blocked = false;

        for (i, stream_id) in ids.iter().enumerate() {
            let stream_id = *stream_id;

            // 最後のストリーム以外は MORE を付けてパケットに詰め込む
            let is_last = i + 1 == ids.len();
            let flags = if is_last {
                0
            } else {
                shiguredo_ngtcp2::WRITE_STREAM_FLAG_MORE
            };

            // 送信待ちのデータは ngtcp2 が ACK まで保持するため、
            // ここで複製する必要はない
            let (result, data_len, fin) = match pending.entries.get(&stream_id) {
                None => continue,
                Some((data, fin)) if data.is_empty() && !*fin => {
                    pending.remove(stream_id);
                    continue;
                }
                Some((data, fin)) => {
                    let data_len = data.len();
                    let fin = *fin;
                    (
                        conn.write_stream_with_flags(send_buf, stream_id, data, fin, ts, flags),
                        data_len,
                        fin,
                    )
                }
            };

            match result {
                Ok((written, data_written, path, info)) => {
                    // 受理された分だけ送信待ちから取り除く
                    let consumed = data_written.unwrap_or(0);
                    if let Some(entry) = pending.entries.get_mut(&stream_id) {
                        let drain = consumed.min(entry.0.len());
                        entry.0.drain(..drain);
                        if fin && consumed >= data_len {
                            entry.1 = false;
                        }
                    }
                    pending.prune(stream_id);

                    if consumed > 0 || (fin && consumed >= data_len) {
                        wrote_any = true;
                    }

                    // MORE を付けた呼び出しでパケットが完成することはないため、
                    // written > 0 は MORE 無し (最後のストリーム) の結果。
                    if written > 0 {
                        packets.push(OutgoingPacket::from_written(
                            send_buf[..written].to_vec(),
                            path,
                            info.ecn,
                        )?);
                        wrote_packet = true;
                    }
                }
                Err(Error::StreamDataBlocked(_)) => {
                    // フロー制御でブロックされた。ピアの MAX_STREAM_DATA を
                    // 待って次の flush で再試行する (RFC 9000 Section 4.1)
                    blocked = true;
                    break;
                }
                Err(Error::StreamShutWr(_)) => {
                    // 送信側が既に終端されている。送信待ちを破棄する
                    pending.remove(stream_id);
                }
                Err(e) => return Err(e),
            }
        }

        // MORE で書き込んだデータをパケットとして完成させる
        let control = write_control_packets(conn, send_buf, ts)?;
        packets.extend(control);

        // フロー制御や輻輳制御で進まなくなったら、残りは次の flush に回す
        if (!wrote_any && !wrote_packet) || blocked || pending.is_empty() {
            break;
        }
    }

    Ok(packets)
}

/// 制御フレームのパケットを書き出す
///
/// MORE を付けて書き込まれたストリームデータもここでパケットになる。
/// 戻り値は書き出したパケットの一覧。
pub(crate) fn write_control_packets(
    conn: &mut Connection,
    send_buf: &mut [u8],
    ts: u64,
) -> Result<Vec<OutgoingPacket>> {
    let mut packets = Vec::new();
    loop {
        let (written, info, path) = conn.write_pkt(send_buf, ts)?;
        if written == 0 {
            break;
        }
        packets.push(OutgoingPacket::from_written(
            send_buf[..written].to_vec(),
            path,
            info.ecn,
        )?);
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 可変長整数をバイト列にする
    fn varint_bytes(n: u64) -> Vec<u8> {
        let mut buf = vec![0u8; shiguredo_ngtcp2::varint::encoded_len(n)];
        shiguredo_ngtcp2::varint::encode(&mut buf, n);
        buf
    }

    /// 連結された Handshake と 1-RTT のパケットが分かれて送られること
    ///
    /// ハンドシェイクが確認される前に CONNECTION_CLOSE を書き出すと、ngtcp2 は
    /// この形のバッファを返す。1 つのデータグラムで送るとピアがデータグラム全体を
    /// 破棄してしまうため、パケットごとに送る必要がある。
    #[test]
    fn test_close_packets_splits_coalesced_packets() {
        // 0xe3 = Long header / Handshake / パケット番号長 3
        let mut handshake = vec![0xe3];
        handshake.extend_from_slice(&1u32.to_be_bytes());
        handshake.push(8);
        handshake.extend(std::iter::repeat_n(0x11, 8));
        handshake.push(0);
        handshake.extend_from_slice(&varint_bytes(16));
        handshake.extend(std::iter::repeat_n(0x33, 16));

        let mut short = vec![0u8; 21];
        short[0] = 0x40;

        let mut buf = handshake.clone();
        buf.extend_from_slice(&short);

        let remote: SocketAddr = "127.0.0.1:4433".parse().expect("テスト用アドレスは有効");
        let packets = close_packets(&buf, remote, remote, 0);

        assert_eq!(packets.len(), 2, "2 つのデータグラムに分かれること");
        assert_eq!(packets[0].data, handshake, "1 つ目が Handshake であること");
        assert_eq!(packets[1].data, short, "2 つ目が 1-RTT であること");
        assert_eq!(packets[0].remote, remote, "送信先が同じであること");
        assert_eq!(packets[1].remote, remote, "送信先が同じであること");
    }

    /// 送信待ちが連結され、FIN が累積すること
    #[test]
    fn test_pending_streams_push() {
        let mut pending = PendingStreams::new();
        pending.push(0, b"abc", false);
        pending.push(0, b"def", true);
        pending.push(4, b"x", false);

        assert!(!pending.is_empty(), "送信待ちがあること");
        assert_eq!(pending.ordered_ids(), vec![0, 4], "ID が昇順に並ぶこと");
        assert_eq!(
            pending.entries.get(&0).map(|(d, f)| (d.clone(), *f)),
            Some((b"abcdef".to_vec(), true)),
            "データが連結され FIN が立つこと"
        );
    }

    /// 送信待ちが空になったストリームが取り除かれること
    #[test]
    fn test_pending_streams_prune() {
        let mut pending = PendingStreams::new();
        pending.push(0, b"abc", false);
        // データを空にすると prune で取り除かれる
        if let Some(entry) = pending.entries.get_mut(&0) {
            entry.0.clear();
        }
        pending.prune(0);
        assert!(pending.is_empty(), "送信待ちが空になること");

        // FIN が残っていれば取り除かれない
        let mut pending = PendingStreams::new();
        pending.push(0, b"abc", true);
        if let Some(entry) = pending.entries.get_mut(&0) {
            entry.0.clear();
        }
        pending.prune(0);
        assert!(!pending.is_empty(), "FIN が残る場合は保持すること");
    }

    /// 明示的に削除できること
    #[test]
    fn test_pending_streams_remove() {
        let mut pending = PendingStreams::new();
        pending.push(0, b"abc", true);
        pending.remove(0);
        assert!(pending.is_empty(), "削除後は空になること");
        assert_eq!(pending.ordered_ids(), Vec::<StreamId>::new());
    }
}
