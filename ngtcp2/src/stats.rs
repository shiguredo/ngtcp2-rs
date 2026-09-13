//! 接続の統計情報
//!
//! ngtcp2 の `ngtcp2_conn_info` を Rust の型で表現する。RTT や輻輳ウィンドウ、
//! 送受信量、パケット喪失を診断やメトリクスに使う。

use std::time::Duration;

/// ngtcp2 の「まだ値が無い」を表す `UINT64_MAX` を `Option` に変換する
fn optional_nanos(value: u64) -> Option<Duration> {
    (value != u64::MAX).then(|| Duration::from_nanos(value))
}

/// ngtcp2 の「まだ値が無い」を表す `UINT64_MAX` を `Option` に変換する
fn optional_bytes(value: u64) -> Option<u64> {
    (value != u64::MAX).then_some(value)
}

/// 接続の統計情報
///
/// [`crate::Connection::stats`] が返すスナップショット。取得した時点の値であり、
/// 以降の変化は追跡しない。
///
/// ngtcp2 は RTT を観測するまで一部の項目を `UINT64_MAX` で保持するため、
/// それらは `Option` として表現する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnStats {
    /// 直近の RTT (RFC 9002 Section 3)
    ///
    /// RTT をまだ観測していない場合は 0 になる (ngtcp2 の初期値)。
    pub latest_rtt: Duration,
    /// 観測された最小の RTT (RFC 9002 Section 3)
    ///
    /// RTT をまだ観測していない場合は `None`。
    pub min_rtt: Option<Duration>,
    /// 平滑化された RTT (RFC 9002 Section 3)
    ///
    /// 観測前は [`crate::Settings::initial_rtt`] が使われる。
    pub smoothed_rtt: Duration,
    /// RTT の平均偏差 (RFC 9002 Section 3)
    pub rttvar: Duration,
    /// 輻輳ウィンドウ (バイト)
    pub cwnd: u64,
    /// スロースタッシュのしきい値 (バイト)
    ///
    /// 喪失をまだ検出していない場合は `None` (ngtcp2 は `UINT64_MAX` で
    /// 「しきい値なし = スロースタート中」を表す)。
    pub ssthresh: Option<u64>,
    /// 送信済みでまだ ACK されていないバイト数 (RFC 9002 Section 2)
    pub bytes_in_flight: u64,
    /// 送信したパケット数
    pub packets_sent: u64,
    /// 送信したバイト数
    pub bytes_sent: u64,
    /// 受信したパケット数
    pub packets_received: u64,
    /// 受信したバイト数
    pub bytes_received: u64,
    /// 喪失したパケット数 (RFC 9002 Section 7.3)
    ///
    /// 見かけの喪失 (spurious loss) を含むことがある。
    pub packets_lost: u64,
    /// 喪失したバイト数
    pub bytes_lost: u64,
    /// 受信した PING フレームの数
    pub pings_received: u64,
    /// 破棄したパケットの数
    ///
    /// 復号に失敗したパケットや、接続先が変わったパケットなど。
    pub packets_discarded: u64,
}

impl ConnStats {
    /// ngtcp2 の生の構造体からスナップショットを作る
    pub(crate) fn from_raw(raw: &shiguredo_ngtcp2_sys::ngtcp2_conn_info) -> Self {
        Self {
            latest_rtt: Duration::from_nanos(raw.latest_rtt),
            min_rtt: optional_nanos(raw.min_rtt),
            smoothed_rtt: Duration::from_nanos(raw.smoothed_rtt),
            rttvar: Duration::from_nanos(raw.rttvar),
            cwnd: raw.cwnd,
            ssthresh: optional_bytes(raw.ssthresh),
            bytes_in_flight: raw.bytes_in_flight,
            packets_sent: raw.pkt_sent,
            bytes_sent: raw.bytes_sent,
            packets_received: raw.pkt_recv,
            bytes_received: raw.bytes_recv,
            packets_lost: raw.pkt_lost,
            bytes_lost: raw.bytes_lost,
            pings_received: raw.ping_recv,
            packets_discarded: raw.pkt_discarded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `UINT64_MAX` が「値なし」として `None` になること
    #[test]
    fn test_optional_sentinels() {
        assert_eq!(optional_nanos(u64::MAX), None, "UINT64_MAX は値なし");
        assert_eq!(
            optional_nanos(1_000),
            Some(Duration::from_nanos(1_000)),
            "有限値は Duration になること"
        );
        assert_eq!(optional_bytes(u64::MAX), None, "UINT64_MAX は値なし");
        assert_eq!(optional_bytes(0), Some(0), "0 は有効な値であること");
    }
}
