//! QUIC トランスポートパラメータ (RFC 9000 Section 18)
//!
//! ローカルが設定する [`TransportParams`] と、ピアが通知した値を読む
//! [`RemoteTransportParams`] を提供する。生の C 構造体は公開 API に露出させない。

use std::net::SocketAddr;
use std::time::Duration;

use crate::reset::StatelessResetToken;
use crate::types::ConnectionId;

/// `Duration` を ngtcp2 のナノ秒に変換する
///
/// u64 に収まらない場合は、ngtcp2 が「無効」を意味する `UINT64_MAX` を
/// 避けるため `u64::MAX - 1` (約 584 年) に丸める。
fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX - 1)
}

/// ピアが通知したトランスポートパラメータ (RFC 9000 Section 18)
///
/// [`crate::Connection::remote_transport_params`] が返す読み取り専用の
/// スナップショット。ハンドシェイクでピアのパラメータが届くまでは取得できない。
///
/// ストリームデータの上限は「ピアが通知した値」であり、その値が適用される
/// ストリームの向きに注意すること。RFC 9000 Section 18.2 の local / remote は
/// **パラメータを送った側** から見た向きを指す。そのためピアのパラメータでは、
/// `initial_max_stream_data_bidi_remote` が「ローカルが開いた双方向ストリーム」に
/// 適用される上限になる。
///
/// コネクション ID を含むため `Copy` は実装しない。複数回使う場合は
/// [`Clone`] すること。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTransportParams {
    /// ローカルが送信できる接続全体のデータ量の初期上限
    pub initial_max_data: u64,
    /// ピアが開く双方向ストリーム 1 本あたりの初期上限
    pub initial_max_stream_data_bidi_local: u64,
    /// ローカルが開く双方向ストリーム 1 本あたりの初期上限
    pub initial_max_stream_data_bidi_remote: u64,
    /// ピアが開く単方向ストリーム 1 本あたりの初期上限
    pub initial_max_stream_data_uni: u64,
    /// ピアが開ける双方向ストリーム数の初期上限
    pub initial_max_streams_bidi: u64,
    /// ピアが開ける単方向ストリーム数の初期上限
    pub initial_max_streams_uni: u64,
    /// ピアのアイドルタイムアウト
    ///
    /// 両側の `max_idle_timeout` のうち小さい方が接続に適用される
    /// (RFC 9000 Section 10.1)。ゼロはアイドルタイムアウトなし。
    pub max_idle_timeout: Duration,
    /// ピアが受け付ける UDP ペイロードの最大サイズ (RFC 9000 Section 14)
    pub max_udp_payload_size: u64,
    /// ピアが同時に有効にしておくコネクション ID の数 (RFC 9000 Section 5.1.1)
    pub active_connection_id_limit: u64,
    /// ACK 遅延フィールドの指数 (RFC 9000 Section 18.2)
    pub ack_delay_exponent: u64,
    /// ピアが ACK を遅延させる最長時間 (RFC 9000 Section 18.2)
    pub max_ack_delay: Duration,
    /// ピアが受信できる DATAGRAM の最大サイズ (RFC 9221 Section 3)
    ///
    /// 0 はピアが DATAGRAM をサポートしていないことを意味する。
    pub max_datagram_frame_size: u64,
    /// ピアがアクティブマイグレーションを無効にしているか (RFC 9000 Section 18.2)
    pub disable_active_migration: bool,
    /// ピアが QUIC ビットのグリーシングを許可しているか (RFC 9287)
    pub grease_quic_bit: bool,
    /// ピアが RESET_STREAM_AT を受理するか
    /// (draft-ietf-quic-reliable-stream-reset)
    ///
    /// true の場合、ピアはリセットの時点までに送ったストリームデータを
    /// 届けることを約束する RESET_STREAM_AT を受理する。こちらの送信側から
    /// この仕組みを使うには
    /// [`crate::Connection::shutdown_stream_write_reliable`] を呼ぶ。
    pub reset_stream_at: bool,
    /// サーバーが Retry で使った SCID (RFC 9000 Section 18.2)
    ///
    /// サーバーが Retry を送った場合にだけ設定される。クライアントは
    /// 受け取った Retry の SCID と一致することを検証しなければならず、
    /// 一致しなければハンドシェイクを失敗させる (RFC 9000 Section 7.3)。
    /// Retry を経ていない接続では `None`。
    pub retry_scid: Option<ConnectionId>,
}

/// QUIC トランスポートパラメータ (RFC 9000 Section 18)
///
/// ngtcp2 の `ngtcp2_transport_params` をラップし、Rust の型で安全に設定できるようにする。
/// 生の C 構造体は公開 API に露出させない。
///
/// デフォルト値は以下のとおり:
///
/// | パラメータ | 値 |
/// | --- | --- |
/// | `initial_max_stream_data_bidi_local` / `bidi_remote` / `uni` | 1 MiB |
/// | `initial_max_data` | 10 MiB |
/// | `initial_max_streams_bidi` / `uni` | 100 |
/// | `max_idle_timeout` | 30 秒 |
/// | `active_connection_id_limit` | 8 |
///
/// その他の項目は ngtcp2 の既定値になる。
#[derive(Clone)]
pub struct TransportParams(pub(crate) shiguredo_ngtcp2_sys::ngtcp2_transport_params);

// SAFETY: ngtcp2_transport_params は値の集合であり、ポインタフィールド
// (token など) は設定しない限り null のまま。本クレートは token を設定しないため、
// 別スレッドへ move しても参照先の生存期間は問題にならない。
// なお本クレートの公開 API は生の構造体を露出しないため、利用者が
// ポインタを設定することもできない。
unsafe impl Send for TransportParams {}
unsafe impl Sync for TransportParams {}

impl TransportParams {
    /// デフォルト設定で作成する
    pub fn new() -> Self {
        let mut params: shiguredo_ngtcp2_sys::ngtcp2_transport_params =
            // SAFETY: ngtcp2_transport_params は全てのビットパターンが有効な POD
            unsafe { std::mem::zeroed() };
        // SAFETY: params は書き込み可能な有効な領域
        unsafe {
            shiguredo_ngtcp2_sys::ngtcp2_transport_params_default_versioned(
                shiguredo_ngtcp2_sys::NGTCP2_TRANSPORT_PARAMS_VERSION as libc::c_int,
                &mut params,
            );
        }

        // アプリケーション固有の設定で上書きする
        params.initial_max_stream_data_bidi_local = 1024 * 1024; // 1 MiB
        params.initial_max_stream_data_bidi_remote = 1024 * 1024; // 1 MiB
        params.initial_max_stream_data_uni = 1024 * 1024; // 1 MiB
        params.initial_max_data = 10 * 1024 * 1024; // 10 MiB
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 100;
        params.max_idle_timeout = duration_nanos(Duration::from_secs(30));
        params.active_connection_id_limit = 8;

        Self(params)
    }

    /// 最大アイドルタイムアウトを設定する (RFC 9000 Section 18.2)
    ///
    /// この時間パケットが途切れると接続はアイドルタイムアウトで終了する
    /// (RFC 9000 Section 10.1)。`Duration::ZERO` はアイドルタイムアウトなし。
    pub fn with_max_idle_timeout(mut self, timeout: Duration) -> Self {
        self.0.max_idle_timeout = duration_nanos(timeout);
        self
    }

    /// 初期の最大データ量を設定する (RFC 9000 Section 18.2 の `initial_max_data`)
    ///
    /// ピアが接続全体で送信できるデータ量の上限。
    pub fn with_initial_max_data(mut self, max_data: u64) -> Self {
        self.0.initial_max_data = max_data;
        self
    }

    /// 双方向ストリームの初期最大データ量 (ピア開始) を設定する
    ///
    /// ピアが開いた双方向ストリーム 1 本あたりで受信できるデータ量の上限
    /// (RFC 9000 Section 18.2 の `initial_max_stream_data_bidi_local`)。
    pub fn with_initial_max_stream_data_bidi_local(mut self, max_data: u64) -> Self {
        self.0.initial_max_stream_data_bidi_local = max_data;
        self
    }

    /// 双方向ストリームの初期最大データ量 (自エンドポイント開始) を設定する
    ///
    /// 自分が開いた双方向ストリーム 1 本あたりでピアが受信できるデータ量の上限
    /// (RFC 9000 Section 18.2 の `initial_max_stream_data_bidi_remote`)。
    pub fn with_initial_max_stream_data_bidi_remote(mut self, max_data: u64) -> Self {
        self.0.initial_max_stream_data_bidi_remote = max_data;
        self
    }

    /// 単方向ストリームの初期最大データ量 (ピア開始) を設定する
    ///
    /// ピアが開いた単方向ストリーム 1 本あたりで受信できるデータ量の上限
    /// (RFC 9000 Section 18.2 の `initial_max_stream_data_uni`)。
    ///
    /// 自分が開いた単方向ストリームに適用される上限はピアのパラメータの
    /// `initial_max_stream_data_uni` であり、[`RemoteTransportParams`] で読める。
    pub fn with_initial_max_stream_data_uni(mut self, max_data: u64) -> Self {
        self.0.initial_max_stream_data_uni = max_data;
        self
    }

    /// 最大双方向ストリーム数を設定する
    ///
    /// ピアが開ける双方向ストリームの累計上限 (RFC 9000 Section 18.2 の
    /// `initial_max_streams_bidi`)。
    pub fn with_max_streams_bidi(mut self, max_streams: u64) -> Self {
        self.0.initial_max_streams_bidi = max_streams;
        self
    }

    /// 最大単方向ストリーム数を設定する
    ///
    /// ピアが開ける単方向ストリームの累計上限 (RFC 9000 Section 18.2 の
    /// `initial_max_streams_uni`)。
    pub fn with_max_streams_uni(mut self, max_streams: u64) -> Self {
        self.0.initial_max_streams_uni = max_streams;
        self
    }

    /// 同時に有効にしておくコネクション ID の数を設定する
    ///
    /// RFC 9000 Section 18.2 の `active_connection_id_limit`。ピアはこの数だけ
    /// NEW_CONNECTION_ID を発行する。2 未満は設定できない (RFC 9000 Section 5.1.1)。
    pub fn with_active_connection_id_limit(mut self, limit: u64) -> Self {
        self.0.active_connection_id_limit = limit;
        self
    }

    /// 最大 ACK 遅延を設定する (RFC 9000 Section 18.2)
    ///
    /// ピアが RTT 計算に使う、ACK を遅延させる最長時間。
    pub fn with_max_ack_delay(mut self, delay: Duration) -> Self {
        self.0.max_ack_delay = duration_nanos(delay);
        self
    }

    /// ACK 遅延フィールドの指数を設定する (RFC 9000 Section 18.2)
    ///
    /// 既定は 3。3 より小さい値や 20 より大きい値はピアに
    /// `TRANSPORT_PARAMETER_ERROR` として拒否される。
    pub fn with_ack_delay_exponent(mut self, exponent: u64) -> Self {
        self.0.ack_delay_exponent = exponent;
        self
    }

    /// 受け付ける UDP ペイロードの最大サイズを設定する (RFC 9000 Section 14)
    ///
    /// ピアはこのサイズを超える UDP ペイロードを送らない。
    pub fn with_max_udp_payload_size(mut self, size: u64) -> Self {
        self.0.max_udp_payload_size = size;
        self
    }

    /// アクティブマイグレーションを無効にするかどうかを設定する
    /// (RFC 9000 Section 18.2)
    ///
    /// true にするとピアは接続のマイグレーションを開始しない。
    /// 本クレートはマイグレーションを実装していないため、既定値のままでも
    /// マイグレーションは起きない。
    pub fn with_disable_active_migration(mut self, disable: bool) -> Self {
        self.0.disable_active_migration = u8::from(disable);
        self
    }

    /// QUIC ビットのグリーシングを許可するかどうかを設定する (RFC 9287)
    ///
    /// true にするとピアは Long header / Short header の Fixed Bit を 0 にした
    /// パケットを送れるようになる。
    pub fn with_grease_quic_bit(mut self, grease: bool) -> Self {
        self.0.grease_quic_bit = u8::from(grease);
        self
    }

    /// DATAGRAM を有効化する (RFC 9221)
    ///
    /// `max_size` は `max_datagram_frame_size` に設定される。
    /// 0 を指定すると DATAGRAM は無効になる。
    pub fn with_datagram(mut self, max_size: u64) -> Self {
        self.0.max_datagram_frame_size = max_size;
        self
    }

    /// Stateless Reset トークンを設定する (サーバー用。RFC 9000 Section 18.2)
    ///
    /// サーバーは自分の最初の SCID に対応するトークンをトランスポート
    /// パラメータで配布する。ピアはこのトークンを持つ DCID に対して
    /// 送られた Stateless Reset だけを受理する (RFC 9000 Section 10.3.1)。
    ///
    /// トークンは [`crate::StatelessResetSecret::token`] で導出すること。
    pub fn with_stateless_reset_token(mut self, token: &StatelessResetToken) -> Self {
        self.0.stateless_reset_token = *token.as_bytes();
        self.0.stateless_reset_token_present = 1;
        self
    }

    /// original_dcid を設定する (サーバー用)
    ///
    /// サーバーは、クライアントからの最初の Initial パケットの
    /// Destination Connection ID をこのフィールドに設定する必要がある
    /// (RFC 9000 Section 7.3)。
    pub fn with_original_dcid(mut self, dcid: &ConnectionId) -> Self {
        let len = dcid.len();
        self.0.original_dcid.datalen = len;
        self.0.original_dcid.data[..len].copy_from_slice(dcid.as_bytes());
        self.0.original_dcid_present = 1;
        self
    }

    /// original_dcid が設定されているかどうかを返す
    ///
    /// サーバー接続の作成には必須で、クライアント接続の作成では設定しては
    /// ならない (RFC 9000 Section 7.3)。ngtcp2 は守られていない場合に assert で
    /// プロセスを abort するため、接続の作成前に検証するために使う。
    pub(crate) fn has_original_dcid(&self) -> bool {
        self.0.original_dcid_present != 0
    }

    /// RESET_STREAM_AT を受理するかどうかを設定する
    /// (draft-ietf-quic-reliable-stream-reset)
    ///
    /// true にすると `reset_stream_at` トランスポートパラメータを通知し、
    /// ピアが送ってきた RESET_STREAM_AT を受理する。RESET_STREAM_AT は
    /// RESET_STREAM と違い、リセットの時点までに送ったストリームデータを
    /// 届けることを送信側が約束するため、受信側は途中まで読んだデータを
    /// 捨てずに済む。
    ///
    /// false のまま RESET_STREAM_AT が届いた場合、ngtcp2 は接続を
    /// `FRAME_ENCODING_ERROR` で終了する。ピアはこのパラメータを通知した
    /// 相手にしか RESET_STREAM_AT を送らないため、通常は起こらない。
    /// 既定は false (ngtcp2 の既定と同じ)。
    ///
    /// 送信側としてこの仕組みを使う場合は、ピアがこのパラメータを通知して
    /// いることに加えて [`crate::Connection::shutdown_stream_write_reliable`]
    /// を呼ぶ必要がある。
    pub fn with_reset_stream_at(mut self, accept: bool) -> Self {
        self.0.reset_stream_at = u8::from(accept);
        self
    }

    /// Retry で使った SCID を通知する (サーバー用。RFC 9000 Section 18.2)
    ///
    /// Retry を送ったサーバーは、Retry パケットの Source Connection ID を
    /// `retry_source_connection_id` として通知しなければならない
    /// (RFC 9000 Section 7.3)。クライアントはこれが受け取った Retry の SCID と
    /// 一致することを検証するため、設定を忘れるとハンドシェイクが
    /// `TRANSPORT_PARAMETER_ERROR` で失敗する。
    ///
    /// Retry を送っていないサーバーが設定してはならない。クライアントは
    /// Retry を受け取っていない接続でこのパラメータが届くと
    /// `TRANSPORT_PARAMETER_ERROR` で接続を終了する (RFC 9000 Section 7.3)。
    pub fn with_retry_scid(mut self, scid: &ConnectionId) -> Self {
        let len = scid.len();
        self.0.retry_scid.datalen = len;
        self.0.retry_scid.data[..len].copy_from_slice(scid.as_bytes());
        self.0.retry_scid_present = 1;
        self
    }

    /// preferred_address を設定する (サーバー用。RFC 9000 Section 18.2)
    ///
    /// サーバーが別のアドレスでも接続を受けられることを通知する。クライアントは
    /// ハンドシェイクの確認後、このアドレスへ移るかどうかを自分で決める
    /// (RFC 9000 Section 9.6)。
    ///
    /// `cid` は優先アドレス用にサーバーが発行するコネクション ID で、クライアントは
    /// 移行後のパケットの Destination Connection ID にこれを使う。サーバーはこの
    /// CID をルーティングテーブルに登録しておく必要がある。
    ///
    /// `reset_token` は `cid` に対する Stateless Reset トークンで、通知は必須
    /// (RFC 9000 Section 18.2)。[`crate::StatelessResetSecret::token`] で導出すること。
    pub fn with_preferred_address(
        mut self,
        cid: &ConnectionId,
        addr: SocketAddr,
        reset_token: &StatelessResetToken,
    ) -> Self {
        let len = cid.len();
        self.0.preferred_addr.cid.datalen = len;
        self.0.preferred_addr.cid.data[..len].copy_from_slice(cid.as_bytes());

        match addr {
            SocketAddr::V4(v4) => {
                // このフィールドを ngtcp2 はプラットフォームの sockaddr_in として
                // 扱う。バインディングの構造体は生成環境のフィールド配置を持つため、
                // ネイティブの構造体を作ってバイト列として写す
                // SAFETY: sockaddr_in は全てのビットパターンが有効な POD
                let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                // アドレスとポートはネットワークバイトオーダーで保持する
                sin.sin_port = v4.port().to_be();
                sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();

                debug_assert_eq!(
                    std::mem::size_of::<libc::sockaddr_in>(),
                    std::mem::size_of::<shiguredo_ngtcp2_sys::sockaddr_in>()
                );
                // SAFETY: どちらも同じ大きさの sockaddr_in
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &sin as *const libc::sockaddr_in as *const u8,
                        &mut self.0.preferred_addr.ipv4 as *mut _ as *mut u8,
                        std::mem::size_of::<libc::sockaddr_in>(),
                    );
                }
                self.0.preferred_addr.ipv4_present = 1;
            }
            SocketAddr::V6(v6) => {
                // SAFETY: sockaddr_in6 は全てのビットパターンが有効な POD
                let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = v6.port().to_be();
                sin6.sin6_addr.s6_addr = v6.ip().octets();

                debug_assert_eq!(
                    std::mem::size_of::<libc::sockaddr_in6>(),
                    std::mem::size_of::<shiguredo_ngtcp2_sys::sockaddr_in6>()
                );
                // SAFETY: どちらも同じ大きさの sockaddr_in6
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &sin6 as *const libc::sockaddr_in6 as *const u8,
                        &mut self.0.preferred_addr.ipv6 as *mut _ as *mut u8,
                        std::mem::size_of::<libc::sockaddr_in6>(),
                    );
                }
                self.0.preferred_addr.ipv6_present = 1;
            }
        }

        self.0.preferred_addr.stateless_reset_token = *reset_token.as_bytes();
        self.0.preferred_addr_present = 1;
        self
    }

    /// 内側の FFI 構造体への参照を返す
    pub(crate) fn as_raw(&self) -> &shiguredo_ngtcp2_sys::ngtcp2_transport_params {
        &self.0
    }
}

impl Default for TransportParams {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteTransportParams {
    /// ngtcp2 の生の構造体からスナップショットを作る
    pub(crate) fn from_raw(raw: &shiguredo_ngtcp2_sys::ngtcp2_transport_params) -> Self {
        Self {
            initial_max_data: raw.initial_max_data,
            initial_max_stream_data_bidi_local: raw.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: raw.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: raw.initial_max_stream_data_uni,
            initial_max_streams_bidi: raw.initial_max_streams_bidi,
            initial_max_streams_uni: raw.initial_max_streams_uni,
            max_idle_timeout: Duration::from_nanos(raw.max_idle_timeout),
            max_udp_payload_size: raw.max_udp_payload_size,
            active_connection_id_limit: raw.active_connection_id_limit,
            ack_delay_exponent: raw.ack_delay_exponent,
            max_ack_delay: Duration::from_nanos(raw.max_ack_delay),
            max_datagram_frame_size: raw.max_datagram_frame_size,
            disable_active_migration: raw.disable_active_migration != 0,
            grease_quic_bit: raw.grease_quic_bit != 0,
            reset_stream_at: raw.reset_stream_at != 0,
            // 通知されていない場合は 0 なので、その場合は None にする
            // (RFC 9000 Section 18.2 の retry_source_connection_id)
            retry_scid: if raw.retry_scid_present != 0 {
                ConnectionId::new(&raw.retry_scid.data[..raw.retry_scid.datalen])
            } else {
                None
            },
        }
    }
}
