//! ngtcp2 の接続設定 (`ngtcp2_settings` のラッパー)
//!
//! 輻輳制御アルゴリズム、初期 RTT、ハンドシェイクのタイムアウトなど、
//! トランスポートパラメータ (RFC 9000 Section 18) とは別に ngtcp2 が持つ
//! 実装固有の設定を Rust の型で表現する。生の C 構造体は公開 API に露出させない。

use std::time::Duration;

use libc::c_int;
use shiguredo_ngtcp2_sys::*;

use crate::reset::StatelessResetSecret;
use crate::retry::AddressValidationToken;
use crate::types::QuicVersion;

/// 送信する UDP ペイロードの既定の最大サイズ (バイト)
///
/// ngtcp2 の既定値は 1452 (MTU 1500 から IP/UDP ヘッダーを引いた値)。
/// 本クレートは IPsec や GRE などのトンネルを通る経路でも IP 分割が
/// 起きにくい 1350 を既定にする。
pub const DEFAULT_MAX_TX_UDP_PAYLOAD_SIZE: usize = 1350;

/// 初期 RTT の推定値の既定 (RFC 9002 Section 6.2.2)
///
/// ngtcp2 の `NGTCP2_DEFAULT_INITIAL_RTT` と同じ 333 ミリ秒。
/// 定数自体は算出式を含むマクロのため bindgen が取り込めない。
pub const DEFAULT_INITIAL_RTT: Duration = Duration::from_millis(333);

/// 輻輳制御アルゴリズム
///
/// ngtcp2 の `settings.cc_algo` に対応する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionAlgorithm {
    /// Reno
    Reno,
    /// CUBIC (RFC 9438)。ngtcp2 の既定
    #[default]
    Cubic,
    /// BBR v2
    Bbr2,
}

impl CongestionAlgorithm {
    /// ngtcp2 の値から変換する
    ///
    /// 未知の値は ngtcp2 の既定と同じ CUBIC として扱う。
    ///
    /// bindgen が生成する定数名は小文字始まりのため、パターンとして使うと
    /// `non_upper_case_globals` 警告になる。比較で判定する。
    fn from_raw(value: ngtcp2_cc_algo) -> Self {
        if value == ngtcp2_cc_algo_NGTCP2_CC_ALGO_RENO {
            Self::Reno
        } else if value == ngtcp2_cc_algo_NGTCP2_CC_ALGO_BBR {
            Self::Bbr2
        } else {
            Self::Cubic
        }
    }

    /// ngtcp2 の値へ変換する
    fn as_raw(self) -> ngtcp2_cc_algo {
        match self {
            Self::Reno => ngtcp2_cc_algo_NGTCP2_CC_ALGO_RENO,
            Self::Cubic => ngtcp2_cc_algo_NGTCP2_CC_ALGO_CUBIC,
            Self::Bbr2 => ngtcp2_cc_algo_NGTCP2_CC_ALGO_BBR,
        }
    }
}

/// `u64` のナノ秒を `Option<Duration>` に変換する
///
/// ngtcp2 は「無効」を `UINT64_MAX` で表すため、その場合は `None` にする。
fn finite_duration(nanos: u64) -> Option<Duration> {
    (nanos != u64::MAX).then(|| Duration::from_nanos(nanos))
}

/// `Option<Duration>` を ngtcp2 の `u64` ナノ秒に変換する
///
/// `None` は ngtcp2 の「無効」を表す `UINT64_MAX` になる。
fn nanos_or_max(duration: Option<Duration>) -> u64 {
    duration.map_or(u64::MAX, |d| d.as_nanos() as u64)
}

/// ngtcp2 の接続設定
///
/// [`Settings::new`] で ngtcp2 の既定値から作成し、フィールドを書き換えて使う。
/// [`crate::Connection::client_new`] / [`crate::Connection::server_new`] に渡す。
///
/// ポインタを必要とする項目 (アドレス検証トークン、互換バージョン交渉の
/// バージョン一覧、PMTUD のプローブサイズ、qlog / ログのコールバック) は
/// 安全に扱えないため表現していない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// 接続を作成した時刻 (ナノ秒)
    ///
    /// ngtcp2 のすべてのタイマー計算の基準になる。単調増加する値であればよく、
    /// 呼び出し側が用意した時計の経過時間を使う。I/O 層はこの値を接続の
    /// 作成時に実際の時刻で上書きする。
    pub initial_ts: u64,

    /// 輻輳制御アルゴリズム
    ///
    /// 既定は [`CongestionAlgorithm::Cubic`]。
    pub congestion_algorithm: CongestionAlgorithm,

    /// 初期 RTT の推定値 (RFC 9002 Section 6.2.2)
    ///
    /// 実際の RTT が観測されるまでの再送タイムアウト計算に使う。
    /// 既定は [`DEFAULT_INITIAL_RTT`]。
    pub initial_rtt: Duration,

    /// ハンドシェイクのタイムアウト
    ///
    /// `initial_ts` からこの時間以内にハンドシェイクが完了しなければ、
    /// ngtcp2 は `NGTCP2_ERR_HANDSHAKE_TIMEOUT` を返して接続を失敗させる。
    /// `None` はタイムアウトなし (ngtcp2 の既定)。
    pub handshake_timeout: Option<Duration>,

    /// 送信する UDP ペイロードの最大サイズ (バイト)
    ///
    /// 既定は [`DEFAULT_MAX_TX_UDP_PAYLOAD_SIZE`]。PMTUD を無効にしている
    /// 場合、この値が送信パケットの上限になる。
    pub max_tx_udp_payload_size: usize,

    /// 接続レベルの輻輳ウィンドウの上限 (バイト)。0 は自動
    ///
    /// 0 の場合は ngtcp2 がアルゴリズムに応じて決める。
    pub max_window: u64,

    /// ストリームレベルの輻輳ウィンドウの上限 (バイト)。0 は自動
    pub max_stream_window: u64,

    /// 遅延 ACK を送るまでに許容する未 ACK パケット数 (RFC 9002 Section 7.3.1)
    ///
    /// 既定は 2。
    pub ack_threshold: usize,

    /// UDP ペイロードサイズの成形を無効にするかどうか
    ///
    /// 有効にすると ngtcp2 はパケットを `max_tx_udp_payload_size` まで
    /// 詰めず、フレームの途中でパケットを分割しない。既定は無効 (成形する)。
    pub no_tx_udp_payload_size_shaping: bool,

    /// PMTUD (Path MTU Discovery) を無効にするかどうか
    ///
    /// 有効にすると ngtcp2 は経路 MTU の探索を行わず、
    /// `max_tx_udp_payload_size` を常に使う。既定は無効 (PMTUD を行う)。
    pub no_pmtud: bool,

    /// keep-alive のタイムアウト
    ///
    /// この時間アイドルが続くと keep-alive パケット (PING) を送る。
    /// `None` は無効 (ngtcp2 の既定)。
    ///
    /// [`crate::Connection::set_keep_alive_timeout`] で接続の作成後も変更できる。
    pub keep_alive_timeout: Option<Duration>,

    /// アドレス検証トークン (RFC 9000 Section 8.1)
    ///
    /// クライアントが Initial に載せて送り返してきた Retry または NEW_TOKEN の
    /// トークン。設定すると ngtcp2 はこの接続をアドレス検証済みとみなし、
    /// 送信量の 3 倍制限 (RFC 9000 Section 8.1) を解除する。
    ///
    /// トークンの生成と検証は [`crate::generate_retry_token`] /
    /// [`crate::verify_retry_token`] を使う。ngtcp2 は接続の作成時にトークンを
    /// 複製するため、この構造体の生存期間を超えて保持されることはない。
    pub address_validation_token: Option<AddressValidationToken>,

    /// Stateless Reset トークンを導出するための秘密 (RFC 9000 Section 10.3.1)
    ///
    /// `ngtcp2_settings` には対応する項目が無いが、コネクション ID を発行する
    /// コールバックがトークンを導出するために必要。
    ///
    /// 設定すると NEW_CONNECTION_ID で配布するトークンがこの秘密から
    /// 決定論的に導出されるため、接続状態を失った後でも同じトークンを
    /// 再現して Stateless Reset を送れる。`None` の場合はトークンを乱数で
    /// 生成するため、Stateless Reset は送れない。
    pub stateless_reset_secret: Option<StatelessResetSecret>,
    /// 互換バージョン交渉で提示するバージョンの一覧 (RFC 9368)
    ///
    /// 優先順に並べる。空の場合は互換バージョン交渉を行わない。
    /// サーバーは、クライアントが提示したバージョンのうちこの一覧に含まれる
    /// ものがある場合、それを使って接続を確立する (Version Negotiation
    /// パケットを返さない)。
    ///
    /// クライアントは、自分が選んだバージョン (`client_new` に渡す
    /// `version`) をこの一覧に含めること。
    pub preferred_versions: Vec<QuicVersion>,
    /// 互換バージョン交渉で「利用可能なバージョン」として通知する一覧
    /// (RFC 9368)
    ///
    /// version_information トランスポートパラメータで相手に通知する。
    /// 空の場合、ngtcp2 は [`Settings::preferred_versions`] (クライアントでは
    /// 選んだバージョン 1 つ) を通知する。
    pub available_versions: Vec<QuicVersion>,
    /// qlog を出力するかどうか
    ///
    /// 有効にすると ngtcp2 が qlog のデータ断片を
    /// [`Connection::poll_qlog_data`] で取り出せる形で出力する。
    /// 出力先 (ファイルなど) の管理はアプリケーションの責任。
    ///
    /// [`Connection::poll_qlog_data`]: crate::Connection::poll_qlog_data
    pub qlog: bool,
}

impl Settings {
    /// ngtcp2 の既定値から設定を作成する
    ///
    /// `initial_ts` には接続を作成する時刻 (ナノ秒) を渡す。
    ///
    /// ngtcp2 の既定値との差分は `max_tx_udp_payload_size`
    /// ([`DEFAULT_MAX_TX_UDP_PAYLOAD_SIZE`]) だけ。
    pub fn new(initial_ts: u64) -> Self {
        let raw = default_raw(initial_ts);

        Self {
            initial_ts,
            congestion_algorithm: CongestionAlgorithm::from_raw(raw.cc_algo),
            initial_rtt: Duration::from_nanos(raw.initial_rtt),
            handshake_timeout: finite_duration(raw.handshake_timeout),
            max_tx_udp_payload_size: raw.max_tx_udp_payload_size,
            max_window: raw.max_window,
            max_stream_window: raw.max_stream_window,
            ack_threshold: raw.ack_thresh,
            no_tx_udp_payload_size_shaping: raw.no_tx_udp_payload_size_shaping != 0,
            no_pmtud: raw.no_pmtud != 0,
            // ngtcp2_settings には keep-alive の項目がない。
            // 無効 (UINT64_MAX) が ngtcp2 の既定のため None にする。
            keep_alive_timeout: None,
            // トークンと秘密は呼び出し側が明示的に設定する。
            // 既定ではアドレス検証も Stateless Reset も行わない。
            address_validation_token: None,
            stateless_reset_secret: None,
            preferred_versions: Vec::new(),
            available_versions: Vec::new(),
            qlog: false,
        }
    }

    /// ngtcp2 の settings 構造体を組み立てる
    ///
    /// `address_validation_token` が設定されている場合、返される構造体の
    /// `token` はそのバイト列を指す。ngtcp2 は接続の作成時にトークンを
    /// 複製するため、ポインタは呼び出し中だけ有効であればよい。
    pub(crate) fn to_raw(&self) -> ngtcp2_settings {
        let mut raw = default_raw(self.initial_ts);

        raw.cc_algo = self.congestion_algorithm.as_raw();
        raw.initial_rtt = self.initial_rtt.as_nanos() as u64;
        raw.handshake_timeout = nanos_or_max(self.handshake_timeout);
        raw.max_tx_udp_payload_size = self.max_tx_udp_payload_size;
        raw.max_window = self.max_window;
        raw.max_stream_window = self.max_stream_window;
        raw.ack_thresh = self.ack_threshold;
        raw.no_tx_udp_payload_size_shaping = self.no_tx_udp_payload_size_shaping as u8;
        raw.no_pmtud = self.no_pmtud as u8;
        // 互換バージョン交渉で提示するバージョン (RFC 9368)。
        // ngtcp2 は接続の作成時にこの配列を読み取るため、self が生きている
        // 間だけ有効なポインタでよい
        if !self.preferred_versions.is_empty() {
            raw.preferred_versions = self.preferred_versions.as_ptr() as *const u32;
            raw.preferred_versionslen = self.preferred_versions.len();
        }

        if !self.available_versions.is_empty() {
            raw.available_versions = self.available_versions.as_ptr() as *const u32;
            raw.available_versionslen = self.available_versions.len();
        }

        // qlog は有効なときだけコールバックを設定する (無効時は出力しない)
        if self.qlog {
            raw.qlog_write = Some(crate::conn::qlog_write_callback);
        }

        if let Some(token) = &self.address_validation_token {
            raw.token = token.as_bytes().as_ptr();
            raw.tokenlen = token.as_bytes().len();
            raw.token_type = token.as_raw_kind();
        }

        raw
    }
}

/// ngtcp2 の既定値を埋めた settings 構造体を作成する
///
/// `max_tx_udp_payload_size` だけ本クレートの既定値で上書きする。
fn default_raw(initial_ts: u64) -> ngtcp2_settings {
    let mut settings: ngtcp2_settings =
        // SAFETY: ngtcp2_settings はすべてのビットパターンが有効な POD
        unsafe { std::mem::zeroed() };
    // SAFETY: settings は書き込み可能な有効な領域
    unsafe {
        ngtcp2_settings_default_versioned(NGTCP2_SETTINGS_VERSION as c_int, &mut settings);
    }
    settings.initial_ts = initial_ts;
    settings.max_tx_udp_payload_size = DEFAULT_MAX_TX_UDP_PAYLOAD_SIZE;
    settings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 既定値が ngtcp2 の既定値と本クレートの上書きの組み合わせであること
    #[test]
    fn test_settings_defaults() {
        let settings = Settings::new(12345);

        assert_eq!(settings.initial_ts, 12345, "initial_ts が反映されること");
        assert_eq!(
            settings.congestion_algorithm,
            CongestionAlgorithm::Cubic,
            "ngtcp2 の既定は CUBIC であること"
        );
        assert_eq!(
            settings.initial_rtt, DEFAULT_INITIAL_RTT,
            "初期 RTT の既定は RFC 9002 Section 6.2.2 の 333 ミリ秒であること"
        );
        assert_eq!(
            settings.handshake_timeout, None,
            "ハンドシェイクのタイムアウトは既定で無効であること"
        );
        assert_eq!(
            settings.max_tx_udp_payload_size, DEFAULT_MAX_TX_UDP_PAYLOAD_SIZE,
            "UDP ペイロードの上限は本クレートの既定値になること"
        );
        assert_eq!(settings.max_window, 0, "輻輳ウィンドウの上限は既定で自動");
        assert_eq!(
            settings.max_stream_window, 0,
            "ストリームのウィンドウ上限は既定で自動"
        );
        assert_eq!(settings.ack_threshold, 2, "ack_thresh の既定は 2");
        assert!(
            !settings.no_tx_udp_payload_size_shaping,
            "ペイロードサイズの成形は既定で行うこと"
        );
        assert!(!settings.no_pmtud, "PMTUD は既定で行うこと");
        assert_eq!(
            settings.keep_alive_timeout, None,
            "keep-alive は既定で無効であること"
        );
    }

    /// 書き換えた値が ngtcp2 の構造体に反映されること
    #[test]
    fn test_settings_to_raw() {
        let settings = Settings {
            initial_ts: 999,
            congestion_algorithm: CongestionAlgorithm::Bbr2,
            initial_rtt: Duration::from_millis(50),
            handshake_timeout: Some(Duration::from_secs(3)),
            max_tx_udp_payload_size: 1200,
            max_window: 1024 * 1024,
            max_stream_window: 64 * 1024,
            ack_threshold: 10,
            no_tx_udp_payload_size_shaping: true,
            no_pmtud: true,
            qlog: true,
            preferred_versions: vec![QuicVersion::V2],
            available_versions: vec![QuicVersion::V1, QuicVersion::V2],
            keep_alive_timeout: Some(Duration::from_secs(30)),
            address_validation_token: None,
            // ngtcp2_settings に対応する項目がないため raw には反映されない
            stateless_reset_secret: None,
        };
        let raw = settings.to_raw();

        assert_eq!(raw.initial_ts, 999, "initial_ts");
        assert_eq!(
            raw.cc_algo, ngtcp2_cc_algo_NGTCP2_CC_ALGO_BBR,
            "cc_algo が BBRv2 であること"
        );
        assert_eq!(
            raw.initial_rtt,
            Duration::from_millis(50).as_nanos() as u64,
            "initial_rtt"
        );
        assert_eq!(
            raw.handshake_timeout,
            Duration::from_secs(3).as_nanos() as u64,
            "handshake_timeout"
        );
        assert_eq!(raw.max_tx_udp_payload_size, 1200, "max_tx_udp_payload_size");
        assert_eq!(raw.max_window, 1024 * 1024, "max_window");
        assert_eq!(raw.max_stream_window, 64 * 1024, "max_stream_window");
        assert_eq!(raw.ack_thresh, 10, "ack_thresh");
        assert_eq!(
            raw.no_tx_udp_payload_size_shaping, 1,
            "no_tx_udp_payload_size_shaping"
        );
        assert_eq!(raw.no_pmtud, 1, "no_pmtud");
        assert!(
            raw.qlog_write.is_some(),
            "qlog を有効にするとコールバックが設定されること"
        );
        assert_eq!(
            raw.preferred_versionslen, 1,
            "preferred_versions の数が反映されること"
        );
        assert_eq!(
            raw.available_versionslen, 2,
            "available_versions の数が反映されること"
        );
    }

    /// qlog を無効にするとコールバックが設定されないこと
    #[test]
    fn test_settings_to_raw_disables_qlog() {
        let settings = Settings::new(0);
        let raw = settings.to_raw();

        assert!(raw.qlog_write.is_none(), "qlog は既定で無効であること");
    }

    /// タイムアウトの無効が ngtcp2 の UINT64_MAX として表現されること
    #[test]
    fn test_settings_to_raw_disables_timeouts() {
        let settings = Settings::new(0);
        let raw = settings.to_raw();

        assert_eq!(
            raw.handshake_timeout,
            u64::MAX,
            "ハンドシェイクのタイムアウトが無効であること"
        );
    }

    /// 輻輳制御アルゴリズムが ngtcp2 の値と相互に変換できること
    #[test]
    fn test_congestion_algorithm_raw_roundtrip() {
        for algo in [
            CongestionAlgorithm::Reno,
            CongestionAlgorithm::Cubic,
            CongestionAlgorithm::Bbr2,
        ] {
            assert_eq!(
                CongestionAlgorithm::from_raw(algo.as_raw()),
                algo,
                "{algo:?} が往復できること"
            );
        }
    }

    /// ngtcp2 の「無効」を表す UINT64_MAX が None になること
    #[test]
    fn test_finite_duration_treats_max_as_disabled() {
        assert_eq!(finite_duration(u64::MAX), None, "UINT64_MAX は無効");
        assert_eq!(
            finite_duration(1000),
            Some(Duration::from_nanos(1000)),
            "有限値は Duration になること"
        );
        assert_eq!(
            nanos_or_max(None),
            u64::MAX,
            "None は UINT64_MAX になること"
        );
        assert_eq!(
            nanos_or_max(Some(Duration::from_secs(1))),
            1_000_000_000,
            "Some はナノ秒になること"
        );
    }
}
