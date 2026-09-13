//! QUIC 接続の状態機械 (sans-IO)
//!
//! ngtcp2 の `ngtcp2_conn` をラップし、パケットの読み書き・ストリーム操作・
//! タイマー管理を提供する。ソケット I/O は持たないため、呼び出し側が
//! [`Connection::read_pkt`] と [`Connection::write_pkt`] を駆動する。
//!
//! ngtcp2 のコールバックで通知される事象は [`ConnectionEvent`] として内部キューに
//! 積まれ、[`Connection::poll_event`] で発生順に取り出す。

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::fmt;
use std::net::SocketAddr;
use std::ptr;

use libc::c_int;
use shiguredo_ngtcp2_sys::aws_lc_sys;
use shiguredo_ngtcp2_sys::*;

use crate::config::{RemoteTransportParams, TransportParams};
use crate::crypto::TlsSession;
use crate::error::{Error, Result, check_ngtcp2};
use crate::event::ConnectionEvent;
use crate::reset::{STATELESS_RESET_TOKEN_LEN, StatelessResetSecret};
use crate::settings::Settings;
use crate::stats::ConnStats;
use crate::types::{ConnectionId, PacketInfo, PathInfo, QuicVersion, StreamId};

/// 接続が終了した理由
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionError {
    /// エラーコード (RFC 9000 Section 20)
    pub error_code: u64,
    /// エラー理由の文字列。ピアが指定しなかった場合は空
    pub reason: String,
    /// アプリケーションエラーかどうか
    ///
    /// false の場合はトランスポートエラー。
    pub is_application: bool,
    /// CONNECTION_CLOSE による終了かどうか
    ///
    /// false の場合はアイドルタイムアウトによる終了。
    pub has_error: bool,
}

/// 次回の接続で 0-RTT を送るために保存するセッション情報
/// (RFC 9001 Section 4.6)
///
/// TLS のセッションチケット (RFC 8446 Section 4.6.1) と、チケットを発行した
/// 接続でサーバーが通知したトランスポートパラメータのうち 0-RTT に必要なものを
/// まとめたもの。[`Connection::take_session_ticket`] で取り出し、
/// [`Connection::client_new_with_0rtt`] に渡す。
///
/// 0-RTT ではハンドシェイクの完了前にデータを送るため、ピアが通知する前の
/// フロー制御の上限を知る必要がある (RFC 9001 Section 4.6.1)。そのため
/// チケットとトランスポートパラメータは常に組で保存する。
///
/// サーバーとその設定に紐付くため、別のサーバーや設定を変えたサーバーでは
/// 0-RTT は受理されない。受理されなかった場合もハンドシェイクは通常どおり
/// 完了する (エラーにはならない)。
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTicket {
    /// TLS セッション (aws-lc のシリアライズ形式)
    session: Vec<u8>,
    /// 0-RTT 用のトランスポートパラメータ
    ///
    /// `ngtcp2_conn_encode_0rtt_transport_params2` が返すバイト列。
    transport_params: Vec<u8>,
}

impl SessionTicket {
    /// 保存したバイト列からセッション情報を作り直す
    ///
    /// [`Connection::take_session_ticket`] で取り出した値をファイルなどに
    /// 保存しておき、次回の接続で復元するために使う。
    pub fn new(session: Vec<u8>, transport_params: Vec<u8>) -> Self {
        Self {
            session,
            transport_params,
        }
    }

    /// TLS セッションのバイト列を返す
    ///
    /// 内容は aws-lc のセッション形式であり、本クレートは解釈しない。
    pub fn session(&self) -> &[u8] {
        &self.session
    }

    /// 0-RTT 用のトランスポートパラメータを返す (RFC 9001 Section 4.6.1)
    ///
    /// サーバーが前回の接続で通知した値のうち、0-RTT で送れるデータ量を
    /// 決めるものを含む。内容は本クレートは解釈しない。
    pub fn transport_params(&self) -> &[u8] {
        &self.transport_params
    }
}

impl fmt::Debug for SessionTicket {
    /// セッションは接続の再開に使えるため、内容は出力せず長さだけを出す
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionTicket")
            .field("session_len", &self.session.len())
            .field("transport_params_len", &self.transport_params.len())
            .finish()
    }
}

/// QUIC 接続
pub struct Connection {
    inner: *mut ngtcp2_conn,
    // コールバック用のユーザーデータ
    //
    // ngtcp2 に渡したポインタが指す先を安定させるため Box で保持する。
    // Box の中身は move されないため、ポインタは Connection の生存期間中有効。
    user_data: Box<ConnectionUserData>,
    // TLS セッション (SSL の所有権を保持する)
    tls_session: Option<TlsSession>,
    // ngtcp2_crypto_conn_ref (SSL に設定するため保持する)
    _conn_ref: Option<Box<ConnRef>>,
}

/// コールバックから参照する接続ごとの可変状態
struct ConnectionUserData {
    /// 発生したイベントのキュー
    events: VecDeque<ConnectionEvent>,
    /// NEW_CONNECTION_ID フレームでピアに発行した CID の記録
    ///
    /// サーバー実装はピアが DCID として使用する可能性のある CID を
    /// ルーティングテーブルに登録するために使用する (RFC 9000 Section 5.1.1)。
    issued_cids: Vec<ConnectionId>,
    /// RETIRE_CONNECTION_ID でピアが使用を終了した CID の記録
    ///
    /// サーバー実装はルーティングテーブルから取り除くために使用する
    /// (RFC 9000 Section 5.1.2)。
    retired_cids: Vec<ConnectionId>,
    /// Stateless Reset トークンを導出するための秘密
    ///
    /// [`Settings::stateless_reset_secret`] から引き継ぐ。`None` の場合は
    /// トークンを乱数で生成する。
    stateless_reset_secret: Option<StatelessResetSecret>,
    /// 0-RTT (early data) の送信を試みたかどうか (クライアント用)
    ///
    /// [`Connection::client_new_with_0rtt`] でセッションが early data に
    /// 対応していた場合に true になる。ハンドシェイク完了時にサーバーが
    /// 受理しなかった場合を検出するために使う。
    early_data_attempted: bool,
    /// qlog の出力 (有効な場合のみ)
    qlog_data: Vec<u8>,
    /// NEW_TOKEN フレームで受け取ったトークン (RFC 9000 Section 8.1.4)
    ///
    /// クライアントは次の接続の Initial に載せることで、サーバーの Retry を
    /// 省略できる。
    new_tokens: VecDeque<Vec<u8>>,
    /// 送信済みでまだ ACK されていないストリームデータ (ストリーム ID 順)
    ///
    /// ngtcp2 は再送のためにこのデータを参照し続けるため、ACK されるか
    /// ストリームが閉じるまで保持する (`ngtcp2_conn_writev_stream` の契約)。
    /// 詳細は [`InFlightStreamData`] を参照。
    in_flight_stream_data: BTreeMap<StreamId, InFlightStreamData>,
}

/// 送信済みでまだ ACK されていないストリームデータ
///
/// ngtcp2 は STREAM フレームを再送するとき、アプリケーションが渡した
/// バッファをそのまま参照する (`ngtcp2_conn_writev_stream` の契約)。そのため
/// 書き出したデータは ACK されるまで保持する必要がある。ACK は重複のない
/// 増加する範囲で通知されるため、先頭から順に捨てられる。
struct InFlightStreamData {
    /// `data[start..]` の先頭がストリームの何バイト目か
    offset: u64,
    /// 送信したデータ
    data: Vec<u8>,
    /// 未 ACK の先頭 (data の先頭からの相対位置)
    start: usize,
}

/// 未 ACK のデータを捨てる際に、これだけたまったら詰め直す
///
/// ACK のたびに Vec を詰め直すと転送量の二乗のコストになるため、
/// 一定量たまるまで先頭のインデックスを進めるだけにする。
const IN_FLIGHT_COMPACT_THRESHOLD: usize = 64 * 1024;

impl InFlightStreamData {
    /// 未 ACK のデータを返す
    ///
    /// 書き出しでは渡す範囲を限定するため使わない (テストでの確認用)。
    #[cfg(test)]
    fn unacked(&self) -> &[u8] {
        &self.data[self.start..]
    }

    /// `offset` までの ACK を受け取ったものとして先頭を捨てる
    ///
    /// ngtcp2 は重複のない増加する範囲で通知するため、通知された終端より
    /// 前をまとめて捨てられる。
    fn ack_until(&mut self, offset: u64) {
        if offset <= self.offset {
            return;
        }

        let acked = usize::try_from(offset - self.offset).unwrap_or(usize::MAX);
        let acked = acked.min(self.data.len());
        self.offset += acked as u64;
        self.start += acked;

        if self.start == self.data.len() {
            // すべて ACK された。オフセットは保持する
            self.data.clear();
            self.start = 0;
        } else if self.start >= IN_FLIGHT_COMPACT_THRESHOLD {
            self.data.drain(..self.start);
            self.start = 0;
        }
    }

    /// 未 ACK のデータに追加して、追加した範囲を返す
    fn append(&mut self, data: &[u8]) -> std::ops::Range<usize> {
        let start = self.data.len();
        self.data.extend_from_slice(data);
        start..self.data.len()
    }

    /// 書き出されなかった末尾を捨てる
    ///
    /// 呼び出し元は書き出されなかったデータを次の呼び出しで渡し直す。
    fn truncate_unwritten(&mut self, len: usize) {
        self.data.truncate(self.start + len);
    }
}

impl ConnectionUserData {
    /// ACK された送信済みデータを解放する
    fn acked_stream_data(&mut self, stream_id: StreamId, offset: u64, datalen: u64) {
        let Some(entry) = self.in_flight_stream_data.get_mut(&stream_id) else {
            return;
        };
        entry.ack_until(offset.saturating_add(datalen));
    }

    /// ストリームが閉じたので送信済みデータを解放する
    ///
    /// ngtcp2 は閉じたストリームのデータを参照しなくなる (ngtcp2 の
    /// `ngtcp2_callbacks.stream_close` の契約)。
    fn closed_stream(&mut self, stream_id: StreamId) {
        self.in_flight_stream_data.remove(&stream_id);
    }
}

impl ConnectionUserData {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            issued_cids: Vec::new(),
            retired_cids: Vec::new(),
            stateless_reset_secret: None,
            early_data_attempted: false,
            qlog_data: Vec::new(),
            new_tokens: VecDeque::new(),
            in_flight_stream_data: BTreeMap::new(),
        }
    }
}

/// ngtcp2_crypto_conn_ref のラッパー
///
/// `SSL_set_ex_data` で SSL に設定し、TLS コールバックから ngtcp2_conn を
/// 取得するために使用する。
struct ConnRef {
    inner: ngtcp2_crypto_conn_ref,
}

// SAFETY: Connection が保持する ngtcp2_conn と SSL は、いずれも 1 つの
// 接続に対応付けられ、その接続を所有するスレッドから排他的に使用される。
// ngtcp2 のコールバックは同一スレッドから同期的に呼ばれる。
unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}

impl Connection {
    /// クライアント接続を作成する
    ///
    /// ngtcp2_crypto のコールバックを自動設定し、TLS セッションの所有権を引き取る。
    ///
    /// # Arguments
    ///
    /// * `dcid` - 宛先コネクション ID
    /// * `scid` - 送信元コネクション ID
    /// * `local_addr` - ローカルアドレス
    /// * `remote_addr` - リモートアドレス
    /// * `version` - 使用する QUIC バージョン (RFC 9000 Section 6)
    /// * `server_name` - サーバー名 (SNI 兼ホスト名検証。DNS 名限定)
    /// * `tls_session` - TLS セッション (所有権を移す)
    /// * `params` - トランスポートパラメータ
    /// * `settings` - 接続設定。`Settings::initial_ts` に接続を作成する時刻
    ///   (ナノ秒) を設定すること
    ///
    /// # Errors
    ///
    /// `params` に original_dcid が設定されている場合、SNI の設定に失敗した
    /// 場合、ngtcp2 の接続作成に失敗した場合、トランスポートパラメータの TLS へ
    /// の設定に失敗した場合はエラーを返す。
    #[expect(clippy::too_many_arguments)]
    pub fn client_new(
        dcid: &ConnectionId,
        scid: &ConnectionId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        version: QuicVersion,
        server_name: &str,
        mut tls_session: TlsSession,
        params: &TransportParams,
        settings: &Settings,
    ) -> Result<Self> {
        // クライアントは original_dcid を通知しない (RFC 9000 Section 7.3)。
        // 設定したまま接続を作ると ngtcp2 が assert でプロセスを abort する
        if params.has_original_dcid() {
            return Err(Error::InvalidArgument(
                "original_dcid must not be set for a client connection".to_string(),
            ));
        }

        // SNI を設定する
        tls_session.set_server_name(server_name)?;

        let callbacks = create_client_callbacks();
        let raw_settings = settings.to_raw();

        let mut user_data_box = Box::new(ConnectionUserData::new());
        // Stateless Reset トークンの導出に使う秘密をコールバックへ引き継ぐ
        user_data_box.stateless_reset_secret = settings.stateless_reset_secret.clone();
        let user_data_ptr = &mut *user_data_box as *mut ConnectionUserData as *mut c_void;

        let dcid_raw = cid_to_raw(dcid);
        let scid_raw = cid_to_raw(scid);
        let (local_sockaddr, local_len) = sockaddr_to_raw(&local_addr);
        let (remote_sockaddr, remote_len) = sockaddr_to_raw(&remote_addr);

        let path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &local_sockaddr as *const _ as *mut _,
                addrlen: local_len,
            },
            remote: ngtcp2_addr {
                addr: &remote_sockaddr as *const _ as *mut _,
                addrlen: remote_len,
            },
            user_data: ptr::null_mut(),
        };

        let mut conn: *mut ngtcp2_conn = ptr::null_mut();
        // SAFETY: 全ての引数は呼び出し中のみ有効だが、ngtcp2 は必要な情報を
        // 内部に複製する。user_data_ptr は Box の中身を指すため安定している。
        let rv = unsafe {
            ngtcp2_conn_client_new_versioned(
                &mut conn,
                &dcid_raw,
                &scid_raw,
                &path,
                version.as_u32(),
                NGTCP2_CALLBACKS_VERSION as c_int,
                &callbacks,
                NGTCP2_SETTINGS_VERSION as c_int,
                &raw_settings,
                NGTCP2_TRANSPORT_PARAMS_VERSION as c_int,
                params.as_raw(),
                ptr::null(),
                user_data_ptr,
            )
        };

        // ngtcp2 は失敗時に conn を生成していないため解放は不要
        check_ngtcp2(rv)?;

        Self::finish_new(conn, user_data_box, tls_session, settings)
    }

    /// 0-RTT 付きでクライアント接続を作成する (RFC 9001 Section 4.6)
    ///
    /// 前回の接続で [`Connection::take_session_ticket`] が返したセッション情報を
    /// 使って接続を作る。作成の直後からハンドシェイクの完了を待たずに
    /// 0-RTT データを送れる (`ngtcp2_conn_writev_stream` の契約)。
    /// 0-RTT を送っている最中かどうかは [`Connection::is_in_early_data`]、
    /// サーバーに受理されたかどうかは [`Connection::is_early_data_accepted`] と
    /// [`ConnectionEvent::EarlyDataRejected`] で確認できる。
    ///
    /// サーバーが 0-RTT を受理しなかった場合、ngtcp2 は 0-RTT で開いた
    /// ストリームと送信待ちのデータを破棄する。アプリケーションは
    /// ストリームを開き直してデータを送り直す必要がある。
    ///
    /// 引数は [`Connection::client_new`] と同じで、`ticket` が加わる。
    ///
    /// # Errors
    ///
    /// [`Connection::client_new`] と同じ。加えて、`ticket` のセッションを
    /// 設定できなかった場合と、`ticket` のトランスポートパラメータを
    /// デコードできなかった場合にエラーを返す。
    #[expect(clippy::too_many_arguments)]
    pub fn client_new_with_0rtt(
        dcid: &ConnectionId,
        scid: &ConnectionId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        version: QuicVersion,
        server_name: &str,
        mut tls_session: TlsSession,
        params: &TransportParams,
        settings: &Settings,
        ticket: &SessionTicket,
    ) -> Result<Self> {
        // セッションはハンドシェイクを始める前に設定する必要がある
        // (aws-lc の SSL_set_session はハンドシェイク開始後に呼ぶと異常終了する)
        let early_data = tls_session.set_session(ticket.session())?;

        let mut conn = Self::client_new(
            dcid,
            scid,
            local_addr,
            remote_addr,
            version,
            server_name,
            tls_session,
            params,
            settings,
        )?;

        // 0-RTT で送れるデータ量は前回の接続でサーバーが通知した値で決まる。
        // ストリームを開く前に設定する必要がある (ngtcp2 の
        // ngtcp2_conn_decode_and_set_0rtt_transport_params の契約)。
        //
        // SAFETY: conn.inner は有効。ticket のバイト列は呼び出し中のみ有効で、
        // ngtcp2 はデコード結果を内部に複製する。
        let rv = unsafe {
            ngtcp2_conn_decode_and_set_0rtt_transport_params(
                conn.inner,
                ticket.transport_params().as_ptr(),
                ticket.transport_params().len(),
            )
        };
        if rv != 0 {
            return Err(Error::InvalidArgument(format!(
                "invalid 0-RTT transport params: {}",
                Error::from_ngtcp2(rv)
            )));
        }

        conn.user_data.early_data_attempted = early_data;
        Ok(conn)
    }

    /// サーバー接続を作成する
    ///
    /// ngtcp2_crypto のコールバックを自動設定し、TLS セッションの所有権を引き取る。
    ///
    /// # Arguments
    ///
    /// * `dcid` - 宛先コネクション ID (クライアントから受信した SCID)
    /// * `scid` - 送信元コネクション ID (サーバーが生成)
    /// * `local_addr` - ローカルアドレス
    /// * `remote_addr` - リモートアドレス
    /// * `version` - クライアントが選んだ QUIC バージョン。サーバーは自分の
    ///   サポートするバージョン以外で接続を作ってはいけない (RFC 9000 Section 6)
    /// * `tls_session` - TLS セッション (所有権を移す)
    /// * `params` - トランスポートパラメータ
    /// * `settings` - 接続設定。`Settings::initial_ts` に接続を作成する時刻
    ///   (ナノ秒) を設定すること
    ///
    /// # Errors
    ///
    /// `params` に original_dcid が設定されていない場合、ngtcp2 の接続作成に
    /// 失敗した場合、トランスポートパラメータの TLS への設定に失敗した場合は
    /// エラーを返す。
    #[expect(clippy::too_many_arguments)]
    pub fn server_new(
        dcid: &ConnectionId,
        scid: &ConnectionId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        version: QuicVersion,
        tls_session: TlsSession,
        params: &TransportParams,
        settings: &Settings,
    ) -> Result<Self> {
        // サーバーは original_dcid を必ず通知する (RFC 9000 Section 7.3)。
        // 設定せずに接続を作ると ngtcp2 が assert でプロセスを abort する
        if !params.has_original_dcid() {
            return Err(Error::InvalidArgument(
                "original_dcid is required for a server connection".to_string(),
            ));
        }

        let callbacks = create_server_callbacks();
        let raw_settings = settings.to_raw();

        let mut user_data_box = Box::new(ConnectionUserData::new());
        // Stateless Reset トークンの導出に使う秘密をコールバックへ引き継ぐ
        user_data_box.stateless_reset_secret = settings.stateless_reset_secret.clone();
        let user_data_ptr = &mut *user_data_box as *mut ConnectionUserData as *mut c_void;

        let dcid_raw = cid_to_raw(dcid);
        let scid_raw = cid_to_raw(scid);
        let (local_sockaddr, local_len) = sockaddr_to_raw(&local_addr);
        let (remote_sockaddr, remote_len) = sockaddr_to_raw(&remote_addr);

        let path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &local_sockaddr as *const _ as *mut _,
                addrlen: local_len,
            },
            remote: ngtcp2_addr {
                addr: &remote_sockaddr as *const _ as *mut _,
                addrlen: remote_len,
            },
            user_data: ptr::null_mut(),
        };

        let mut conn: *mut ngtcp2_conn = ptr::null_mut();
        // SAFETY: 全ての引数は呼び出し中のみ有効だが、ngtcp2 は必要な情報を
        // 内部に複製する。user_data_ptr は Box の中身を指すため安定している。
        let rv = unsafe {
            ngtcp2_conn_server_new_versioned(
                &mut conn,
                &dcid_raw,
                &scid_raw,
                &path,
                version.as_u32(),
                NGTCP2_CALLBACKS_VERSION as c_int,
                &callbacks,
                NGTCP2_SETTINGS_VERSION as c_int,
                &raw_settings,
                NGTCP2_TRANSPORT_PARAMS_VERSION as c_int,
                params.as_raw(),
                ptr::null(),
                user_data_ptr,
            )
        };

        // ngtcp2 は失敗時に conn を生成していないため解放は不要
        check_ngtcp2(rv)?;

        Self::finish_new(conn, user_data_box, tls_session, settings)
    }

    /// 接続生成の共通後処理
    ///
    /// TLS セッションと ngtcp2_conn を結び付け、トランスポートパラメータを TLS に
    /// 設定する。失敗した場合は ngtcp2_conn を解放する。
    fn finish_new(
        conn: *mut ngtcp2_conn,
        user_data_box: Box<ConnectionUserData>,
        mut tls_session: TlsSession,
        settings: &Settings,
    ) -> Result<Self> {
        // keep-alive は ngtcp2_settings の項目ではないため、
        // 接続の作成後に個別に設定する
        if let Some(timeout) = settings.keep_alive_timeout {
            // SAFETY: conn は生成済みで有効
            unsafe {
                ngtcp2_conn_set_keep_alive_timeout(conn, timeout.as_nanos() as u64);
            }
        }

        // conn_ref を作成する (TLS コールバックから ngtcp2_conn を取得するために必要)
        let mut conn_ref = Box::new(ConnRef {
            inner: ngtcp2_crypto_conn_ref {
                get_conn: Some(conn_ref_get_conn_callback),
                user_data: conn as *mut c_void,
            },
        });

        // SSL に conn_ref を設定する
        // SSL_set_app_data は SSL_set_ex_data(ssl, 0, data) のマクロ
        // SAFETY: tls_session と conn_ref は Self が生存する限り有効
        unsafe {
            aws_lc_sys::SSL_set_ex_data(
                tls_session.as_ptr(),
                0,
                &mut conn_ref.inner as *mut ngtcp2_crypto_conn_ref as *mut c_void,
            );
            ngtcp2_conn_set_tls_native_handle(conn, tls_session.as_void_ptr());
        }

        // ローカルのトランスポートパラメータを TLS に設定する。
        //
        // aws-lc では SSL_set_quic_transport_params が設定されていないと
        // ClientHello の quic_transport_parameters 拡張が保存されない
        // (ext_quic_transport_params_parse_clienthello の実装による)。
        // ngtcp2_crypto は通常 HANDSHAKE 鍵のインストール時に設定するが、
        // サーバーではそれは ClientHello 処理の後になるため事前に設定する必要がある。
        let mut tp_buf = [0u8; 512];
        // SAFETY: conn は有効。tp_buf は書き込み可能な領域
        let tp_len = unsafe {
            ngtcp2_conn_encode_local_transport_params(conn, tp_buf.as_mut_ptr(), tp_buf.len())
        };
        if tp_len < 0 {
            // SAFETY: conn は生成済みでまだ Self が所有していないため解放する
            unsafe { ngtcp2_conn_del(conn) };
            return Err(Error::from_ngtcp2(tp_len as libc::c_int));
        }
        if let Err(e) = tls_session.set_quic_transport_params(&tp_buf[..tp_len as usize]) {
            // SAFETY: 同上
            unsafe { ngtcp2_conn_del(conn) };
            return Err(e);
        }

        // サーバーが 0-RTT を受け入れる場合、0-RTT の受理条件
        // (early data context) を設定する (RFC 9001 Section 4.6.1)。
        //
        // aws-lc は、チケットを発行した接続と 0-RTT を再開した接続でこの値が
        // 一致する場合にだけ early data を受け入れる (quic_ticket_compatible)。
        // 0-RTT で送れるデータ量を決めるパラメータだけをエンコードするため、
        // original_dcid のように接続ごとに変わる値は含まれない
        // (ngtcp2_conn_encode_0rtt_transport_params2 の実装による)。
        // 接続を作った直後 (ClientHello を処理する前) に設定する必要がある。
        if tls_session.accepts_early_data() {
            let mut ctx_buf = [0u8; 512];
            // SAFETY: conn は有効。ctx_buf は書き込み可能な領域
            let ctx_len = unsafe {
                ngtcp2_conn_encode_0rtt_transport_params2(conn, ctx_buf.as_mut_ptr(), ctx_buf.len())
            };
            if ctx_len < 0 {
                // SAFETY: conn は生成済みでまだ Self が所有していないため解放する
                unsafe { ngtcp2_conn_del(conn) };
                return Err(Error::from_ngtcp2(ctx_len as libc::c_int));
            }
            if let Err(e) = tls_session.set_quic_early_data_context(&ctx_buf[..ctx_len as usize]) {
                // SAFETY: 同上
                unsafe { ngtcp2_conn_del(conn) };
                return Err(e);
            }
        }

        Ok(Self {
            inner: conn,
            user_data: user_data_box,
            tls_session: Some(tls_session),
            _conn_ref: Some(conn_ref),
        })
    }

    /// 受信した UDP ペイロードを処理する
    ///
    /// 1 つの UDP データグラムをそのまま渡す。`data` が複数の QUIC パケットを
    /// 含んでいてもよい (RFC 9000 Section 12.2)。
    ///
    /// `path` にはパケットを受信したローカルアドレスと送信元アドレスを渡す。
    /// ngtcp2 はこれを使って接続のマイグレーションを検出する
    /// (RFC 9000 Section 9)。
    ///
    /// # Errors
    ///
    /// ngtcp2 がパケットを受理できない場合にエラーを返す。回復可能なエラーは
    /// [`Error::classify_connection_error`] で判別できる。
    ///
    /// 回復可能 (`Ignore`) 以外のエラーが返った場合、[`Connection::write_pkt`] で
    /// パケットの送信を続けてはならない。ngtcp2 の契約 (`ngtcp2_conn_read_pkt` の
    /// ドキュメント) では、致命的なエラーでは
    /// [`Connection::write_connection_close`] で終端パケットを書き、終了状態
    /// (closing / draining) では何も送らない。
    pub fn read_pkt(
        &mut self,
        path: &PathInfo,
        pkt_info: &PacketInfo,
        data: &[u8],
        ts: u64,
    ) -> Result<()> {
        let (local_sockaddr, local_len) = sockaddr_to_raw(&path.local);
        let (remote_sockaddr, remote_len) = sockaddr_to_raw(&path.remote);

        let path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &local_sockaddr as *const _ as *mut _,
                addrlen: local_len,
            },
            remote: ngtcp2_addr {
                addr: &remote_sockaddr as *const _ as *mut _,
                addrlen: remote_len,
            },
            user_data: ptr::null_mut(),
        };

        let pi = ngtcp2_pkt_info { ecn: pkt_info.ecn };

        // SAFETY: self.inner は有効。path と pi と data は呼び出し中のみ有効で、
        // ngtcp2 は処理中だけ参照する。
        let rv = unsafe {
            ngtcp2_conn_read_pkt_versioned(
                self.inner,
                &path,
                NGTCP2_PKT_INFO_VERSION as c_int,
                &pi,
                data.as_ptr(),
                data.len(),
                ts,
            )
        };

        check_ngtcp2(rv as c_int)
    }

    /// 送信する QUIC パケットを 1 つ書き出す
    ///
    /// 戻り値は `(書き込んだバイト数, ECN 情報, 送信先の経路)`。0 が返るまで
    /// 繰り返し呼び出し、書き出した分を UDP で送信する。
    ///
    /// 経路は `written > 0` の場合に必ず `Some` になる。接続のマイグレーション中は
    /// 経路検証のパケットだけ別のアドレスへ送る必要があるため、呼び出し側は
    /// この経路へ送ること (RFC 9000 Section 9.3)。
    ///
    /// # Errors
    ///
    /// ngtcp2 がパケットを生成できない場合にエラーを返す。
    pub fn write_pkt(
        &mut self,
        buf: &mut [u8],
        ts: u64,
    ) -> Result<(usize, PacketInfo, Option<PathInfo>)> {
        let mut pi = ngtcp2_pkt_info { ecn: 0 };

        // ngtcp2 は path に出力パス情報を書き込むため、
        // addr フィールドに有効な書き込み可能バッファを設定する必要がある
        let mut local_addr: libc::sockaddr_storage =
            // SAFETY: sockaddr_storage は全てのビットパターンが有効な POD
            unsafe { std::mem::zeroed() };
        let mut remote_addr: libc::sockaddr_storage =
            // SAFETY: 同上
            unsafe { std::mem::zeroed() };

        let mut path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &mut local_addr as *mut _ as *mut _,
                addrlen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            },
            remote: ngtcp2_addr {
                addr: &mut remote_addr as *mut _ as *mut _,
                addrlen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            },
            user_data: ptr::null_mut(),
        };

        // SAFETY: self.inner は有効。buf は書き込み可能。path と pi は
        // 呼び出し中のみ有効で、ngtcp2 は出力先としてのみ使う。
        let rv = unsafe {
            ngtcp2_conn_write_pkt_versioned(
                self.inner,
                &mut path,
                NGTCP2_PKT_INFO_VERSION as c_int,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                ts,
            )
        };

        if rv < 0 {
            return Err(Error::from_ngtcp2(rv as c_int));
        }

        // パケットを書き出した場合、ngtcp2 は送信先の経路を path に書き戻す。
        // SAFETY: path は呼び出し中だけ有効な領域で、ngtcp2 が書き込んだ値を
        // ここでコピーする。
        let path = if rv > 0 {
            unsafe { path_info_from_raw(&path) }
        } else {
            None
        };

        Ok((rv as usize, PacketInfo { ecn: pi.ecn }, path))
    }

    /// 新しい経路へマイグレーションを開始する (RFC 9000 Section 9)
    ///
    /// クライアント専用。`path` の検証を開始し、成功したら新しい経路へ移る。
    /// 検証が終わるまでは元の経路が使われ続ける
    /// (RFC 9000 Section 9.3)。
    ///
    /// 検証の結果は [`ConnectionEvent::PathValidated`] で通知される。
    ///
    /// # Errors
    ///
    /// マイグレーションが無効な場合、ハンドシェイクが確認される前の場合、
    /// 未使用のコネクション ID が無い場合、`path.local` が現在のローカル
    /// アドレスと同じ場合にエラーを返す。
    pub fn initiate_migration(&mut self, path: &PathInfo, ts: u64) -> Result<()> {
        let raw = raw_path(path);
        // SAFETY: self.inner は有効。raw は呼び出し中のみ有効で、
        // ngtcp2 は処理中だけ参照する。
        let rv = unsafe { ngtcp2_conn_initiate_migration(self.inner, &raw.path, ts) };
        check_ngtcp2(rv as c_int)
    }

    /// 新しい経路へ即座にマイグレーションする (RFC 9000 Section 9)
    ///
    /// [`Connection::initiate_migration`] と異なり、検証の完了を待たずに
    /// 新しい経路を使い始める。検証自体は行われ、失敗した場合は
    /// [`ConnectionEvent::PathValidated`] で `success = false` が通知される。
    ///
    /// ソケットを 1 つしか持たない実装 (ローカルアドレスを切り替えると
    /// 元の経路へ送れなくなる実装) ではこちらを使う。
    ///
    /// # Errors
    ///
    /// [`Connection::initiate_migration`] と同じ。
    pub fn initiate_immediate_migration(&mut self, path: &PathInfo, ts: u64) -> Result<()> {
        let raw = raw_path(path);
        // SAFETY: initiate_migration と同じ
        let rv = unsafe { ngtcp2_conn_initiate_immediate_migration(self.inner, &raw.path, ts) };
        check_ngtcp2(rv as c_int)
    }

    /// 現在の経路を返す (RFC 9000 Section 9)
    ///
    /// マイグレーションが完了すると新しい経路になる。ngtcp2 が経路を
    /// 報告できない場合は `None`。
    pub fn get_path(&self) -> Option<PathInfo> {
        // SAFETY: self.inner は有効。返る path は ngtcp2 が管理する領域で、
        // ここでコピーする。
        unsafe { path_info_from_raw(ngtcp2_conn_get_path2(self.inner)) }
    }

    /// ピアが RETIRE_CONNECTION_ID で使用を終了した CID を取り出す
    ///
    /// サーバー実装はルーティングテーブルから取り除くために使用する
    /// (RFC 9000 Section 5.1.2)。一度取り出した CID は再度返さない。
    pub fn poll_retired_cids(&mut self) -> Vec<ConnectionId> {
        std::mem::take(&mut self.user_data.retired_cids)
    }

    /// qlog の出力を取り出す
    ///
    /// [`Settings::qlog`] を有効にした接続で、ngtcp2 が出力した qlog の
    /// データ断片を返す。取り出した分は破棄されるため、アプリケーションが
    /// ファイルなどへ書き出すこと。
    ///
    /// qlog は JSON Text Sequence (RFC 7464) の形式で出力される。
    pub fn poll_qlog_data(&mut self) -> Option<Vec<u8>> {
        if self.user_data.qlog_data.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut self.user_data.qlog_data))
    }

    /// サーバーが NEW_TOKEN フレームで受け取ったトークンを取り出す
    /// (RFC 9000 Section 8.1.4)
    ///
    /// クライアントは取り出したトークンを保存し、次の接続で
    /// [`Settings::address_validation_token`] に設定して使う。使うと
    /// サーバーは Retry を送らずに接続を受け入れられる。
    ///
    /// 一度取り出したトークンは再度返らない。
    pub fn take_new_token(&mut self) -> Option<Vec<u8>> {
        self.user_data.new_tokens.pop_front()
    }

    /// NEW_TOKEN フレームでトークンを送る (RFC 9000 Section 8.1.4)
    ///
    /// サーバー専用。アドレスを検証できたクライアントに対して、次の接続で
    /// Retry を省略させるために送る。トークンは [`crate::generate_new_token`]
    /// で生成する。
    ///
    /// # Errors
    ///
    /// クライアントで呼んだ場合、または ngtcp2 がトークンを受け付けなかった
    /// 場合にエラーを返す。
    pub fn submit_new_token(&mut self, token: &[u8]) -> Result<()> {
        // SAFETY: self.inner は有効。token は呼び出し中のみ参照され、
        // ngtcp2 は内部でコピーする。
        let rv = unsafe { ngtcp2_conn_submit_new_token(self.inner, token.as_ptr(), token.len()) };
        check_ngtcp2(rv as c_int)
    }

    /// ストリームにデータを書き込む
    ///
    /// ngtcp2 examples に従い、`NGTCP2_WRITE_STREAM_FLAG_MORE` を使用しない。
    /// これにより渡したデータから 1 つのパケットを完成させて返す。
    ///
    /// 戻り値は `(パケットサイズ, 書き込んだデータ量, 送信先の経路, ECN 情報)`。
    /// `パケットサイズ` が 0 の場合はパケットが生成されなかったことを意味する。
    ///
    /// # Errors
    ///
    /// - [`Error::StreamDataBlocked`][]: ストリームがフロー制御でブロックされている
    /// - [`Error::StreamShutWr`][]: ストリームの書き込みがシャットダウンされている
    pub fn write_stream(
        &mut self,
        buf: &mut [u8],
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        ts: u64,
    ) -> Result<(usize, Option<usize>, Option<PathInfo>, PacketInfo)> {
        self.write_stream_with_flags(buf, stream_id, data, fin, ts, 0)
    }

    /// ストリームにデータを書き込む (フラグ指定付き)
    ///
    /// `flags` に [`shiguredo_ngtcp2_sys::NGTCP2_WRITE_STREAM_FLAG_MORE`] を指定すると、
    /// 1 つのパケットに複数ストリームのデータを詰められる (ngtcp2 は
    /// [`shiguredo_ngtcp2_sys::NGTCP2_ERR_WRITE_MORE`] を返して続きを要求する)。
    ///
    /// `data` はストリームの未送信の先頭から続くバイト列を渡すこと。ngtcp2 は
    /// 再送のために書き出したデータを参照し続けるが、ACK されるまでの保持は
    /// この実装が行うため、呼び出し元が `data` を生かしておく必要はない
    /// (`ngtcp2_conn_writev_stream` が要求するバッファの寿命はこの実装が負う)。
    /// 書ききれなかった末尾は保持しないため、次の呼び出しで渡し直すこと。
    ///
    /// # Errors
    ///
    /// [`Connection::write_stream`] と同じ。
    pub fn write_stream_with_flags(
        &mut self,
        buf: &mut [u8],
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        ts: u64,
        flags: u32,
    ) -> Result<(usize, Option<usize>, Option<PathInfo>, PacketInfo)> {
        let mut pi = ngtcp2_pkt_info { ecn: 0 };
        let mut datalen: ngtcp2_ssize = -1;

        // ngtcp2 は path に出力パス情報を書き込むため有効なバッファが必要
        let mut local_addr: libc::sockaddr_storage =
            // SAFETY: sockaddr_storage は全てのビットパターンが有効な POD
            unsafe { std::mem::zeroed() };
        let mut remote_addr: libc::sockaddr_storage =
            // SAFETY: 同上
            unsafe { std::mem::zeroed() };

        let mut path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &mut local_addr as *mut _ as *mut _,
                addrlen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            },
            remote: ngtcp2_addr {
                addr: &mut remote_addr as *mut _ as *mut _,
                addrlen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            },
            user_data: ptr::null_mut(),
        };

        // ngtcp2 は STREAM フレームを再送するとき、ここで渡したバッファを
        // そのまま参照する。呼び出し元のバッファは呼び出し後に解放されうるため、
        // ACK されるまで保持する領域へ写してから渡す
        // (`ngtcp2_conn_writev_stream` の契約)。
        let entry = self
            .user_data
            .in_flight_stream_data
            .entry(stream_id)
            .or_insert_with(|| InFlightStreamData {
                offset: 0,
                data: Vec::new(),
                start: 0,
            });
        let appended = entry.append(data);
        // 渡すのは今回追加した範囲だけにする。未 ACK のデータは既に ngtcp2 が
        // 書き出し済みで、渡し直すと現在のオフセットに二重に書き込まれる
        let (ptr, len) = {
            let offered = &entry.data[appended.clone()];
            (offered.as_ptr() as *mut u8, offered.len())
        };

        let vec = ngtcp2_vec { base: ptr, len };

        // ngtcp2 examples に従い、FIN をフラグに合成する
        let mut flags = flags;
        if fin {
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }

        // SAFETY: self.inner は有効。buf は書き込み可能。vec は
        // in_flight_stream_data が保持する領域を指し、ACK されるまで有効。
        let rv = unsafe {
            ngtcp2_conn_writev_stream_versioned(
                self.inner,
                &mut path,
                NGTCP2_PKT_INFO_VERSION as c_int,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                &mut datalen,
                flags,
                stream_id,
                &vec,
                1,
                ts,
            )
        };

        let data_written = if datalen >= 0 {
            Some(datalen as usize)
        } else {
            None
        };

        // 書き出されなかった末尾は呼び出し元が次の呼び出しで渡し直すため、
        // 保持しない (保持すると同じデータが二重に残る)
        if let Some(entry) = self.user_data.in_flight_stream_data.get_mut(&stream_id) {
            let written = data_written.unwrap_or(0);
            entry.truncate_unwritten(appended.start.saturating_sub(entry.start) + written);
        }

        // ngtcp2 examples に従い、識別が必要なエラーを個別に扱う
        if rv == NGTCP2_ERR_WRITE_MORE as ngtcp2_ssize {
            // データはバッファに追加されたがパケットはまだ生成されていない
            return Ok((0, data_written, None, PacketInfo { ecn: pi.ecn }));
        }
        if rv == NGTCP2_ERR_STREAM_DATA_BLOCKED as ngtcp2_ssize {
            return Err(Error::StreamDataBlocked(stream_id));
        }
        if rv == NGTCP2_ERR_STREAM_SHUT_WR as ngtcp2_ssize {
            return Err(Error::StreamShutWr(stream_id));
        }
        if rv < 0 {
            return Err(Error::from_ngtcp2(rv as c_int));
        }

        // パケットを書き出した場合、ngtcp2 は送信先の経路を path に書き戻す
        // SAFETY: ngtcp2 が書き込んだ値をここでコピーする
        let packet_path = if rv > 0 {
            unsafe { path_info_from_raw(&path) }
        } else {
            None
        };

        Ok((
            rv as usize,
            data_written,
            packet_path,
            PacketInfo { ecn: pi.ecn },
        ))
    }

    /// 双方向ストリームを開く (RFC 9000 Section 2.1)
    ///
    /// # Errors
    ///
    /// ピアが許可した双方向ストリーム数の上限に達している場合などにエラーを返す。
    pub fn open_bidi_stream(&mut self) -> Result<StreamId> {
        let mut stream_id: i64 = 0;
        // SAFETY: self.inner は有効。stream_id は書き込み可能
        let rv =
            unsafe { ngtcp2_conn_open_bidi_stream(self.inner, &mut stream_id, ptr::null_mut()) };
        check_ngtcp2(rv)?;
        Ok(stream_id)
    }

    /// 単方向ストリームを開く (RFC 9000 Section 2.1)
    ///
    /// # Errors
    ///
    /// ピアが許可した単方向ストリーム数の上限に達している場合などにエラーを返す。
    pub fn open_uni_stream(&mut self) -> Result<StreamId> {
        let mut stream_id: i64 = 0;
        // SAFETY: self.inner は有効。stream_id は書き込み可能
        let rv =
            unsafe { ngtcp2_conn_open_uni_stream(self.inner, &mut stream_id, ptr::null_mut()) };
        check_ngtcp2(rv)?;
        Ok(stream_id)
    }

    /// ストリームの送受信両方向をシャットダウンする
    ///
    /// RESET_STREAM と STOP_SENDING を送る (RFC 9000 Section 19.4 / 19.5)。
    ///
    /// # Errors
    ///
    /// ngtcp2 がシャットダウンを受け付けない場合にエラーを返す。
    pub fn shutdown_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        // SAFETY: self.inner は有効
        let rv = unsafe { ngtcp2_conn_shutdown_stream(self.inner, 0, stream_id, error_code) };
        check_ngtcp2(rv)
    }

    /// ストリームの書き込み側をシャットダウンする
    ///
    /// RESET_STREAM を送る (RFC 9000 Section 19.4)。
    ///
    /// # Errors
    ///
    /// ngtcp2 がシャットダウンを受け付けない場合にエラーを返す。
    pub fn shutdown_stream_write(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        // SAFETY: self.inner は有効
        let rv = unsafe { ngtcp2_conn_shutdown_stream_write(self.inner, 0, stream_id, error_code) };
        check_ngtcp2(rv)
    }

    /// ストリームの書き込み側をシャットダウンし、送信済みのデータの配信を保証する
    /// (draft-ietf-quic-reliable-stream-reset)
    ///
    /// [`Connection::shutdown_stream_write`] との違いは、まだ ACK をもらっていない
    /// 送信中のデータを破棄せず、リセットの時点までに渡したデータを届けてから
    /// 送信側を閉じるところにある。ピアは RESET_STREAM ではなく RESET_STREAM_AT を
    /// 受け取り、リセットより前に送られたデータを欠落なく受け取れる。
    ///
    /// この保証が働くのはピアが `reset_stream_at` を通知している場合だけである
    /// ([`Connection::supports_reset_stream_at`] で確認できる)。通知していない
    /// ピアに対しては ngtcp2 が RESET_STREAM を送り、未送信のデータは破棄される
    /// ([`Connection::shutdown_stream_write`] と同じ挙動)。
    ///
    /// ピアが通知していない場合もエラーにはならないが、保証は得られない。
    /// 保証が要る場合は呼び出し前に [`Connection::supports_reset_stream_at`] を
    /// 確認すること。
    ///
    /// # Errors
    ///
    /// ngtcp2 がシャットダウンを受け付けない場合にエラーを返す。
    pub fn shutdown_stream_write_reliable(
        &mut self,
        stream_id: StreamId,
        error_code: u64,
    ) -> Result<()> {
        // SAFETY: self.inner は有効
        let rv = unsafe {
            ngtcp2_conn_shutdown_stream_write(
                self.inner,
                NGTCP2_SHUT_STREAM_FLAG_FLUSH,
                stream_id,
                error_code,
            )
        };
        check_ngtcp2(rv)
    }

    /// ストリームの読み取り側をシャットダウンする
    ///
    /// STOP_SENDING を送り、ピアからの以降のデータを受け取らない
    /// (RFC 9000 Section 19.5)。受信を途中であきらめる場合に使用する。
    ///
    /// # Errors
    ///
    /// ngtcp2 がシャットダウンを受け付けない場合にエラーを返す。
    pub fn shutdown_stream_read(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        // SAFETY: self.inner は有効
        let rv = unsafe { ngtcp2_conn_shutdown_stream_read(self.inner, 0, stream_id, error_code) };
        check_ngtcp2(rv)
    }

    /// ストリームのフロー制御クレジットを進める (RFC 9000 Section 19.9)
    ///
    /// 受信データを処理し終えたら、その分だけピアに送信許可を与える。
    ///
    /// # Errors
    ///
    /// ngtcp2 が受け付けない場合にエラーを返す。
    pub fn extend_max_stream_offset(&mut self, stream_id: StreamId, datalen: u64) -> Result<()> {
        // SAFETY: self.inner は有効
        let rv = unsafe { ngtcp2_conn_extend_max_stream_offset(self.inner, stream_id, datalen) };
        check_ngtcp2(rv)
    }

    /// 接続全体のフロー制御クレジットを進める (RFC 9000 Section 19.9)
    pub fn extend_max_offset(&mut self, datalen: u64) {
        // SAFETY: self.inner は有効
        unsafe { ngtcp2_conn_extend_max_offset(self.inner, datalen) };
    }

    /// ピアが開ける双方向ストリーム数の上限を `n` 増やす (RFC 9000 Section 19.11)
    ///
    /// MAX_STREAMS フレームを送る。ngtcp2 はストリーム数の上限を自動では
    /// 増やさないため (`ngtcp2_conn_extend_max_streams_bidi` のドキュメント参照)、
    /// ピアのストリームを処理し終えた時点でアプリケーションが呼ぶ必要がある。
    /// 呼ばない限りピアは `initial_max_streams_bidi` の上限に達した後に
    /// 新しいストリームを開けない。
    pub fn extend_max_streams_bidi(&mut self, n: usize) {
        // SAFETY: self.inner は有効
        unsafe { ngtcp2_conn_extend_max_streams_bidi(self.inner, n) };
    }

    /// ピアが開ける単方向ストリーム数の上限を `n` 増やす (RFC 9000 Section 19.11)
    ///
    /// [`Connection::extend_max_streams_bidi`] の単方向版。
    pub fn extend_max_streams_uni(&mut self, n: usize) {
        // SAFETY: self.inner は有効
        unsafe { ngtcp2_conn_extend_max_streams_uni(self.inner, n) };
    }

    /// 次に処理すべきタイムアウト時刻をナノ秒で取得する
    ///
    /// `u64::MAX` が返る場合、処理すべきタイマーはない。
    pub fn get_expiry(&self) -> u64 {
        // SAFETY: self.inner は有効
        unsafe { ngtcp2_conn_get_expiry(self.inner) }
    }

    /// 期限切れのタイマーを処理する
    ///
    /// # Errors
    ///
    /// ngtcp2 がタイマー処理に失敗した場合にエラーを返す。
    pub fn handle_expiry(&mut self, ts: u64) -> Result<()> {
        // SAFETY: self.inner は有効
        let rv = unsafe { ngtcp2_conn_handle_expiry(self.inner, ts) };
        check_ngtcp2(rv)
    }

    /// 鍵の更新を開始する (RFC 9001 Section 4.6.3)
    ///
    /// 次に [`Connection::write_pkt`] を呼んだ時点で新しい 1-RTT 鍵に切り替わり、
    /// ピアも受信した鍵の世代に合わせて更新する。長期間生きる接続では
    /// 前方秘匿性を保つために定期的な更新が推奨される (RFC 9001 Section 6)。
    ///
    /// # Errors
    ///
    /// 接続がハンドシェイク完了後の状態にない場合は [`Error::InvalidArgument`] を
    /// 返す。ngtcp2 の `conn_initiate_key_update` は POST_HANDSHAKE 状態でないと
    /// assert でプロセスを異常終了させるため、呼び出し側の誤りでプロセスを
    /// 落とさないよう先に状態を確認する。
    ///
    /// それ以外では ngtcp2 が `NGTCP2_ERR_INVALID_STATE` を返す場合がある:
    /// ハンドシェイクがまだ確認されていない (RFC 9001 Section 4.1.2)、
    /// 前の鍵の更新が完了していない、または前の更新の確定から 1 PTO が
    /// 経過していない場合。いずれも一時的な状態なので、時間をおいて
    /// 再試行すればよい。
    pub fn initiate_key_update(&mut self, ts: u64) -> Result<()> {
        if !self.is_handshake_completed()
            || self.is_in_closing_period()
            || self.is_in_draining_period()
        {
            return Err(Error::InvalidArgument(
                "key update requires a connection in the post-handshake state".to_string(),
            ));
        }

        // SAFETY: self.inner は有効。上の確認で ngtcp2 が要求する状態にある
        let rv = unsafe { ngtcp2_conn_initiate_key_update(self.inner, ts) };
        check_ngtcp2(rv)
    }

    /// クロージング期間中かどうかを返す (RFC 9000 Section 10.2)
    pub fn is_in_closing_period(&self) -> bool {
        // SAFETY: self.inner は有効
        unsafe { ngtcp2_conn_in_closing_period(self.inner) != 0 }
    }

    /// ドレイニング期間中かどうかを返す (RFC 9000 Section 10.2)
    pub fn is_in_draining_period(&self) -> bool {
        // SAFETY: self.inner は有効
        unsafe { ngtcp2_conn_in_draining_period(self.inner) != 0 }
    }

    /// この接続で使用されている QUIC バージョンを返す (RFC 9000 Section 6)
    ///
    /// クライアントでは [`Connection::client_new`] に渡したバージョン、
    /// サーバーではクライアントの Initial に含まれていたバージョンを返す。
    /// 互換バージョン交渉 (RFC 9368) が行われた場合は交渉後のバージョンになる。
    ///
    /// ngtcp2 が [`QuicVersion`] で表現できないバージョンを報告した場合は
    /// `None` を返す。
    pub fn negotiated_version(&self) -> Option<QuicVersion> {
        // SAFETY: self.inner は有効。値は読み取るだけで変更しない
        let version = unsafe { ngtcp2_conn_get_negotiated_version(self.inner) };
        QuicVersion::from_u32(version)
    }

    /// 交渉された ALPN プロトコルを返す (RFC 7301 Section 3)
    ///
    /// ハンドシェイクで ALPN が確定するまでは `None` を返す。サーバーでは
    /// 複数の ALPN を登録している場合にどれが選ばれたかを判別するために使う。
    pub fn selected_alpn_protocol(&self) -> Option<Vec<u8>> {
        self.tls_session.as_ref()?.selected_alpn_protocol()
    }

    /// ハンドシェイクが完了したかどうかを返す (RFC 9001 Section 4.1.1)
    pub fn is_handshake_completed(&self) -> bool {
        // SAFETY: self.inner は有効
        unsafe { ngtcp2_conn_get_handshake_completed(self.inner) != 0 }
    }

    /// 0-RTT (early data) を送受信している最中かどうかを返す
    /// (RFC 9001 Section 4.6)
    ///
    /// クライアントでは ClientHello を送ってからハンドシェイクが完了するまでの
    /// 間 true になる。この間 [`Connection::write_stream`] で書いたデータは
    /// 0-RTT パケットで送られる。サーバーでは 0-RTT データを処理している間
    /// true になる。
    pub fn is_in_early_data(&self) -> bool {
        self.tls_session
            .as_ref()
            .is_some_and(|session| session.is_in_early_data())
    }

    /// 0-RTT (early data) がサーバーに受理されたかどうかを返す
    /// (RFC 9001 Section 4.6.2)
    ///
    /// クライアント専用。ハンドシェイクが完了するまでは受理が確定しないため、
    /// 完了前に呼ぶと false になる。サーバーが受理しなかった場合は
    /// [`ConnectionEvent::EarlyDataRejected`] が発生する。
    pub fn is_early_data_accepted(&self) -> bool {
        self.tls_session
            .as_ref()
            .is_some_and(|session| session.is_early_data_accepted())
    }

    /// 0-RTT (early data) が拒否されたかどうかを返す (RFC 9001 Section 4.6.2)
    ///
    /// 拒否された時点で ngtcp2 が 0-RTT で開いたストリームと送信待ちの
    /// データを破棄するため、アプリケーションは開き直して送り直す必要がある。
    pub fn is_early_data_rejected(&self) -> bool {
        // SAFETY: self.inner は有効。値は読み取るだけで変更しない
        unsafe { ngtcp2_conn_get_tls_early_data_rejected2(self.inner) != 0 }
    }

    /// 次回の接続で 0-RTT を送るためのセッション情報を取り出す (クライアント用)
    ///
    /// TLS 1.3 のセッションチケットはハンドシェイクの完了後にサーバーから
    /// 届く (RFC 8446 Section 4.6.1)。そのためハンドシェイク完了後に
    /// パケットをやり取りしたあとに呼び出すこと。チケットがまだ届いていない
    /// 場合と、一度取り出した後は `Ok(None)` を返す。
    ///
    /// 取り出したセッション情報は [`Connection::client_new_with_0rtt`] に
    /// 渡す。0-RTT を送るかどうかを決めるのはアプリケーションであり、
    /// リプレイ攻撃を避けるため必要のない接続では使わないこと
    /// (RFC 9001 Section 9.2)。
    ///
    /// # Errors
    ///
    /// 0-RTT 用のトランスポートパラメータをエンコードできなかった場合に
    /// エラーを返す。
    pub fn take_session_ticket(&mut self) -> Result<Option<SessionTicket>> {
        // ハンドシェイク完了前はサーバーのトランスポートパラメータが無く、
        // 0-RTT で送れるデータ量が決まらないため取り出さない
        if !self.is_handshake_completed() {
            return Ok(None);
        }

        let Some(session) = self
            .tls_session
            .as_mut()
            .and_then(|session| session.take_session_ticket())
        else {
            return Ok(None);
        };

        Ok(Some(SessionTicket::new(
            session,
            self.encode_0rtt_transport_params()?,
        )))
    }

    /// 0-RTT で送れるデータ量を決めるトランスポートパラメータをエンコードする
    ///
    /// クライアントでは前回の接続でサーバーが通知した値から、サーバーでは
    /// 自分のローカルの値から作る (ngtcp2 の
    /// `ngtcp2_conn_encode_0rtt_transport_params2` の契約)。
    pub(crate) fn encode_0rtt_transport_params(&self) -> Result<Vec<u8>> {
        // 0-RTT に必要なパラメータは 512 バイトに収まる
        // (ngtcp2 の example も同じ大きさのバッファを使う)
        let mut buf = [0u8; 512];
        // SAFETY: self.inner は有効。buf は書き込み可能な領域
        let len = unsafe {
            ngtcp2_conn_encode_0rtt_transport_params2(self.inner, buf.as_mut_ptr(), buf.len())
        };
        if len < 0 {
            return Err(Error::from_ngtcp2(len as libc::c_int));
        }
        Ok(buf[..len as usize].to_vec())
    }

    /// keep-alive のタイムアウトを設定する (ナノ秒。0 で無効)
    pub fn set_keep_alive_timeout(&mut self, timeout: u64) {
        // SAFETY: self.inner は有効
        unsafe { ngtcp2_conn_set_keep_alive_timeout(self.inner, timeout) };
    }

    /// 接続が終了した理由を返す
    ///
    /// ピアから CONNECTION_CLOSE を受信した場合、またはローカルで
    /// `write_connection_close` を呼んだ場合に設定される。
    /// 接続がまだ終了していない場合は理由が空の値が返る。
    pub fn get_connection_error(&self) -> ConnectionError {
        // SAFETY: self.inner は有効。返るポインタは接続が保持する領域
        let ccerr = unsafe { ngtcp2_conn_get_ccerr(self.inner) };
        if ccerr.is_null() {
            return ConnectionError {
                error_code: 0,
                reason: String::new(),
                is_application: false,
                has_error: false,
            };
        }
        // SAFETY: ccerr は ngtcp2 が管理する有効な領域
        let ccerr = unsafe { &*ccerr };
        let reason = if ccerr.reason.is_null() || ccerr.reasonlen == 0 {
            String::new()
        } else {
            // SAFETY: reason は reasonlen バイトの有効な領域
            let bytes = unsafe { std::slice::from_raw_parts(ccerr.reason, ccerr.reasonlen) };
            String::from_utf8_lossy(bytes).into_owned()
        };

        ConnectionError {
            error_code: ccerr.error_code,
            reason,
            is_application: ccerr.type_ == ngtcp2_ccerr_type_NGTCP2_CCERR_TYPE_APPLICATION,
            has_error: ccerr.type_ != ngtcp2_ccerr_type_NGTCP2_CCERR_TYPE_IDLE_CLOSE,
        }
    }

    /// 接続全体で送信可能な残りのデータ量を返す (RFC 9000 Section 4.1)
    ///
    /// ピアの `initial_max_data` と MAX_DATA から決まる接続レベルの
    /// フロー制御ウィンドウの残り。0 の場合は MAX_DATA を待つ必要がある。
    pub fn get_max_data_left(&self) -> u64 {
        // SAFETY: self.inner は有効。値は読み取るだけで変更しない
        unsafe { ngtcp2_conn_get_max_data_left2(self.inner) }
    }

    /// ストリームで送信可能な残りのデータ量を返す (RFC 9000 Section 4.1)
    ///
    /// ピアの `initial_max_stream_data_*` と MAX_STREAM_DATA から決まる
    /// ストリームレベルのフロー制御ウィンドウの残り。存在しないストリーム ID を
    /// 渡した場合は 0 を返す。
    pub fn get_max_stream_data_left(&self, stream_id: StreamId) -> u64 {
        // SAFETY: self.inner は有効。値は読み取るだけで変更しない
        unsafe { ngtcp2_conn_get_max_stream_data_left2(self.inner, stream_id) }
    }

    /// 開ける残りの双方向ストリーム数を返す (RFC 9000 Section 4.2)
    ///
    /// 0 の場合は [`Connection::open_bidi_stream`] がエラーになり、ピアの
    /// MAX_STREAMS ([`ConnectionEvent::MaxStreamsBidi`]) を待つ必要がある。
    pub fn get_streams_bidi_left(&self) -> u64 {
        // SAFETY: self.inner は有効。値は読み取るだけで変更しない
        unsafe { ngtcp2_conn_get_streams_bidi_left2(self.inner) }
    }

    /// 開ける残りの単方向ストリーム数を返す (RFC 9000 Section 4.2)
    pub fn get_streams_uni_left(&self) -> u64 {
        // SAFETY: self.inner は有効。値は読み取るだけで変更しない
        unsafe { ngtcp2_conn_get_streams_uni_left2(self.inner) }
    }

    /// 輻輳ウィンドウの残りを返す (RFC 9002 Section 7)
    ///
    /// `cwnd - bytes_in_flight` に相当する。0 の場合は輻輳制御で送信を
    /// 止めなければならず、ACK を待つ必要がある。
    pub fn get_cwnd_left(&self) -> u64 {
        // SAFETY: self.inner は有効。値は読み取るだけで変更しない
        unsafe { ngtcp2_conn_get_cwnd_left2(self.inner) }
    }

    /// 接続の統計情報を返す
    ///
    /// RTT、輻輳ウィンドウ、送受信量、パケット喪失などのスナップショット。
    /// ハンドシェイク前でも呼び出せるが、RTT は観測前まで値が入らない
    /// ([`ConnStats`] の各フィールドのドキュメント参照)。
    pub fn stats(&self) -> ConnStats {
        let mut raw: ngtcp2_conn_info =
            // SAFETY: ngtcp2_conn_info は数値だけの POD
            unsafe { std::mem::zeroed() };
        // SAFETY: self.inner は有効。raw は書き込み可能な領域
        unsafe {
            ngtcp2_conn_get_conn_info2_versioned(
                self.inner,
                NGTCP2_CONN_INFO_VERSION as c_int,
                &mut raw,
            );
        }
        ConnStats::from_raw(&raw)
    }

    /// 発生したイベントを 1 つ取り出す
    ///
    /// イベントは発生順に返る。未処理のイベントがない場合は `None` を返す。
    /// [`Connection::read_pkt`] / [`Connection::write_pkt`] /
    /// [`Connection::handle_expiry`] の呼び出し後に `None` になるまで取り出すこと。
    pub fn poll_event(&mut self) -> Option<ConnectionEvent> {
        self.user_data.events.pop_front()
    }

    /// 未処理のイベントがあるかどうかを返す
    pub fn has_event(&self) -> bool {
        !self.user_data.events.is_empty()
    }

    /// ピアが通知したトランスポートパラメータを返す (RFC 9000 Section 18)
    ///
    /// ハンドシェイクでピアのパラメータが届くまでは `None` を返す。
    ///
    /// # パラメータの向き
    ///
    /// RFC 9000 Section 18.2 の local / remote は**パラメータを送った側**から
    /// 見た向きを指す。そのためピアのパラメータでは、
    /// `initial_max_stream_data_bidi_remote` が「ローカルが開いた双方向
    /// ストリーム」に適用される上限になる。
    pub fn remote_transport_params(&self) -> Option<RemoteTransportParams> {
        // SAFETY: self.inner は有効。返るポインタは接続が保持する領域
        let params = unsafe { ngtcp2_conn_get_remote_transport_params(self.inner) };
        if params.is_null() {
            return None;
        }
        // SAFETY: params は ngtcp2 が管理する有効な領域。
        // RemoteTransportParams は値だけを複製するため参照を持ち越さない。
        Some(RemoteTransportParams::from_raw(unsafe { &*params }))
    }

    /// ピアが RESET_STREAM_AT を受理するかどうかを返す
    /// (draft-ietf-quic-reliable-stream-reset)
    ///
    /// ピアが `reset_stream_at` を通知していない場合、またはトランスポート
    /// パラメータがまだ交換されていない場合は false。true の場合、
    /// [`Connection::shutdown_stream_write_reliable`] が送信中のデータの配信を
    /// 保証する。
    pub fn supports_reset_stream_at(&self) -> bool {
        self.remote_transport_params()
            .is_some_and(|params| params.reset_stream_at)
    }

    /// ピアが DATAGRAM を受信できるかどうかを返す (RFC 9221 Section 3)
    ///
    /// ピアが `max_datagram_frame_size` を通知していない場合、または
    /// トランスポートパラメータがまだ交換されていない場合は false。
    pub fn can_send_datagram(&self) -> bool {
        self.remote_transport_params()
            .is_some_and(|params| params.max_datagram_frame_size > 0)
    }

    /// DATAGRAM を送信する (RFC 9221)
    ///
    /// DATAGRAM は信頼性のない配信であり、順序も再送も保証されない。
    ///
    /// 戻り値は `(書き込んだバイト数, DATAGRAM が受理されたか, 送信先の経路,
    /// ECN 情報)`。経路は `written > 0` の場合に必ず `Some` になる
    /// ([`Connection::write_pkt`] と同じ)。
    ///
    /// # Errors
    ///
    /// ピアが DATAGRAM をサポートしていない場合は `NGTCP2_ERR_INVALID_STATE` を
    /// 返す。
    pub fn write_datagram(
        &mut self,
        buf: &mut [u8],
        data: &[u8],
        ts: u64,
    ) -> Result<(usize, bool, Option<PathInfo>, PacketInfo)> {
        if !self.can_send_datagram() {
            return Err(Error::Ngtcp2(
                "ERR_INVALID_STATE: remote peer does not support DATAGRAM".to_string(),
                NGTCP2_ERR_INVALID_STATE,
            ));
        }

        let mut pi = ngtcp2_pkt_info { ecn: 0 };
        let mut accepted: c_int = 0;

        // ngtcp2 は path に出力パス情報を書き込むため有効なバッファが必要
        let mut local_addr: libc::sockaddr_storage =
            // SAFETY: sockaddr_storage は全てのビットパターンが有効な POD
            unsafe { std::mem::zeroed() };
        let mut remote_addr: libc::sockaddr_storage =
            // SAFETY: 同上
            unsafe { std::mem::zeroed() };

        let mut path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &mut local_addr as *mut _ as *mut _,
                addrlen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            },
            remote: ngtcp2_addr {
                addr: &mut remote_addr as *mut _ as *mut _,
                addrlen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            },
            user_data: ptr::null_mut(),
        };

        let vec = ngtcp2_vec {
            base: data.as_ptr() as *mut _,
            len: data.len(),
        };

        // SAFETY: self.inner は有効。buf は書き込み可能。vec は data を指し、
        // ngtcp2 は呼び出し中だけ参照する。
        let rv = unsafe {
            ngtcp2_conn_writev_datagram_versioned(
                self.inner,
                &mut path,
                NGTCP2_PKT_INFO_VERSION as c_int,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                &mut accepted,
                NGTCP2_WRITE_DATAGRAM_FLAG_NONE,
                0,
                &vec,
                1,
                ts,
            )
        };

        if rv < 0 {
            return Err(Error::from_ngtcp2(rv as c_int));
        }

        // SAFETY: ngtcp2 が書き込んだ値をここでコピーする
        let packet_path = if rv > 0 {
            unsafe { path_info_from_raw(&path) }
        } else {
            None
        };

        Ok((
            rv as usize,
            accepted != 0,
            packet_path,
            PacketInfo { ecn: pi.ecn },
        ))
    }

    /// NEW_CONNECTION_ID フレームで発行した CID を取り出す
    ///
    /// ngtcp2 はピアの `active_connection_id_limit` に応じて追加の CID を発行する。
    /// サーバー実装は発行済み CID をルーティングテーブルに登録し、ピアが DCID として
    /// 使用するパケットを正しく接続に振り分ける (RFC 9000 Section 5.1.1)。
    /// 一度取り出した CID は再度返さない。
    pub fn poll_issued_cids(&mut self) -> Vec<ConnectionId> {
        std::mem::take(&mut self.user_data.issued_cids)
    }

    /// トランスポートエラーの CONNECTION_CLOSE パケットを書き出す
    ///
    /// RFC 9000 Section 19.19 の CONNECTION_CLOSE フレーム (0x1c) を生成する。
    ///
    /// # Errors
    ///
    /// ngtcp2 がパケットを生成できない場合にエラーを返す。
    pub fn write_connection_close(
        &mut self,
        buf: &mut [u8],
        error_code: u64,
        reason: &[u8],
        ts: u64,
    ) -> Result<usize> {
        let mut ccerr: ngtcp2_ccerr =
            // SAFETY: ngtcp2_ccerr は全てのビットパターンが有効な POD
            unsafe { std::mem::zeroed() };
        // SAFETY: ccerr は書き込み可能。reason は呼び出し中のみ参照される
        unsafe {
            ngtcp2_ccerr_default(&mut ccerr);
            ngtcp2_ccerr_set_transport_error(&mut ccerr, error_code, reason.as_ptr(), reason.len());
        }
        self.write_ccerr(buf, &ccerr, ts)
    }

    /// アプリケーションエラーの CONNECTION_CLOSE パケットを書き出す
    ///
    /// RFC 9000 Section 19.19 の CONNECTION_CLOSE フレーム (0x1d) を生成する。
    /// アプリケーション層のエラーで接続を閉じる場合に使用する。
    ///
    /// # Errors
    ///
    /// ngtcp2 がパケットを生成できない場合にエラーを返す。
    pub fn write_connection_close_app(
        &mut self,
        buf: &mut [u8],
        error_code: u64,
        reason: &[u8],
        ts: u64,
    ) -> Result<usize> {
        let mut ccerr: ngtcp2_ccerr =
            // SAFETY: ngtcp2_ccerr は全てのビットパターンが有効な POD
            unsafe { std::mem::zeroed() };
        // SAFETY: ccerr は書き込み可能。reason は呼び出し中のみ参照される
        unsafe {
            ngtcp2_ccerr_default(&mut ccerr);
            ngtcp2_ccerr_set_application_error(
                &mut ccerr,
                error_code,
                reason.as_ptr(),
                reason.len(),
            );
        }
        self.write_ccerr(buf, &ccerr, ts)
    }

    /// CONNECTION_CLOSE を書き出す共通処理
    fn write_ccerr(&mut self, buf: &mut [u8], ccerr: &ngtcp2_ccerr, ts: u64) -> Result<usize> {
        let mut pi = ngtcp2_pkt_info { ecn: 0 };

        // SAFETY: self.inner は有効。buf は書き込み可能。ccerr は呼び出し中のみ参照される
        let rv = unsafe {
            ngtcp2_conn_write_connection_close_versioned(
                self.inner,
                ptr::null_mut(),
                NGTCP2_PKT_INFO_VERSION as c_int,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                ccerr,
                ts,
            )
        };

        if rv < 0 {
            return Err(Error::from_ngtcp2(rv as c_int));
        }

        Ok(rv as usize)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: self.inner は ngtcp2_conn_client_new_versioned /
            // ngtcp2_conn_server_new_versioned で生成した未解放のポインタ
            unsafe { ngtcp2_conn_del(self.inner) };
        }
    }
}

/// `ConnectionId` を `ngtcp2_cid` に変換する
fn cid_to_raw(cid: &ConnectionId) -> ngtcp2_cid {
    let mut raw = ngtcp2_cid {
        datalen: cid.len(),
        data: [0u8; 20],
    };
    raw.data[..cid.len()].copy_from_slice(cid.as_bytes());
    raw
}

/// `PathInfo` を ngtcp2 の `ngtcp2_path` に変換して保持する
///
/// `ngtcp2_path` は `sockaddr_storage` へのポインタを持つため、変換元の
/// ストレージを同じ構造体で保持する。ストレージは `Box` で確保し、
/// 構造体が move されてもアドレスが変わらないようにする。
struct RawPath {
    /// ローカルアドレスのストレージ (`path.local.addr` が指す)
    _local: Box<libc::sockaddr_storage>,
    /// リモートアドレスのストレージ (`path.remote.addr` が指す)
    _remote: Box<libc::sockaddr_storage>,
    /// ngtcp2 に渡す経路
    path: ngtcp2_path,
}

impl RawPath {
    /// `PathInfo` から変換する
    fn new(info: &PathInfo) -> Self {
        let (local, local_len) = sockaddr_to_raw(&info.local);
        let (remote, remote_len) = sockaddr_to_raw(&info.remote);
        let mut local = Box::new(local);
        let mut remote = Box::new(remote);

        Self {
            path: ngtcp2_path {
                local: ngtcp2_addr {
                    addr: local.as_mut() as *mut _ as *mut _,
                    addrlen: local_len,
                },
                remote: ngtcp2_addr {
                    addr: remote.as_mut() as *mut _ as *mut _,
                    addrlen: remote_len,
                },
                user_data: ptr::null_mut(),
            },
            _local: local,
            _remote: remote,
        }
    }
}

/// `PathInfo` を ngtcp2 の `ngtcp2_path` に変換する
///
/// 戻り値のポインタは `raw` が保持するストレージを指すため、`raw` の
/// 生存中だけ有効。
fn raw_path(info: &PathInfo) -> RawPath {
    RawPath::new(info)
}

/// ngtcp2 の `sockaddr` を `SocketAddr` に変換する
///
/// 対応していないアドレスファミリや長さが足りない場合は `None` を返す。
///
/// # Safety
///
/// `addr` は `len` バイト以上の有効な `sockaddr` を指していること。
unsafe fn sockaddr_from_raw(
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    if addr.is_null() {
        return None;
    }

    // SAFETY: 呼び出し側が addr と len の有効性を保証する
    unsafe {
        match (*addr).sa_family as c_int {
            libc::AF_INET => {
                if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                    return None;
                }
                let sin = &*(addr as *const libc::sockaddr_in);
                // s_addr はネットワークバイトオーダー
                let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                Some(SocketAddr::new(ip.into(), u16::from_be(sin.sin_port)))
            }
            libc::AF_INET6 => {
                if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                    return None;
                }
                let sin6 = &*(addr as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                Some(SocketAddr::new(ip.into(), u16::from_be(sin6.sin6_port)))
            }
            _ => None,
        }
    }
}

/// ngtcp2 の `ngtcp2_path` を [`PathInfo`] に変換する
///
/// # Safety
///
/// `path` は有効な `ngtcp2_path` を指しているか、null であること。
unsafe fn path_info_from_raw(path: *const ngtcp2_path) -> Option<PathInfo> {
    if path.is_null() {
        return None;
    }

    // SAFETY: 呼び出し側が path の有効性を保証する
    unsafe {
        let local = sockaddr_from_raw(
            (*path).local.addr as *const libc::sockaddr,
            (*path).local.addrlen,
        )?;
        let remote = sockaddr_from_raw(
            (*path).remote.addr as *const libc::sockaddr,
            (*path).remote.addrlen,
        )?;
        Some(PathInfo { local, remote })
    }
}

/// `SocketAddr` を `sockaddr_storage` に変換する
pub(crate) fn sockaddr_to_raw(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage は全てのビットパターンが有効な POD
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    match addr {
        SocketAddr::V4(v4) => {
            // SAFETY: storage は sockaddr_in を格納できる大きさがあり、
            // sockaddr_in は同じ先頭レイアウトを持つ
            let sin: &mut libc::sockaddr_in =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            // SAFETY: storage は sockaddr_in6 を格納できる大きさがあり、
            // sockaddr_in6 は同じ先頭レイアウトを持つ
            let sin6: &mut libc::sockaddr_in6 =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

/// クライアント用のコールバックを作成する
fn create_client_callbacks() -> ngtcp2_callbacks {
    let mut callbacks: ngtcp2_callbacks =
        // SAFETY: ngtcp2_callbacks は関数ポインタの集合で、全て NULL は有効な初期値。
        // ngtcp2 は任意のコールバックが NULL の場合それを使わない。
        unsafe { std::mem::zeroed() };

    // ngtcp2_crypto_* コールバック (TLS 統合に必須)
    callbacks.client_initial = Some(ngtcp2_crypto_client_initial_cb);
    callbacks.recv_crypto_data = Some(ngtcp2_crypto_recv_crypto_data_cb);
    callbacks.encrypt = Some(ngtcp2_crypto_encrypt_cb);
    callbacks.decrypt = Some(ngtcp2_crypto_decrypt_cb);
    callbacks.hp_mask = Some(ngtcp2_crypto_hp_mask_cb);
    callbacks.recv_retry = Some(ngtcp2_crypto_recv_retry_cb);
    callbacks.update_key = Some(ngtcp2_crypto_update_key_cb);
    callbacks.delete_crypto_aead_ctx = Some(ngtcp2_crypto_delete_crypto_aead_ctx_cb);
    callbacks.delete_crypto_cipher_ctx = Some(ngtcp2_crypto_delete_crypto_cipher_ctx_cb);
    callbacks.get_path_challenge_data = Some(ngtcp2_crypto_get_path_challenge_data_cb);
    callbacks.version_negotiation = Some(ngtcp2_crypto_version_negotiation_cb);

    set_application_callbacks(&mut callbacks);

    // その他の必須コールバック
    callbacks.rand = Some(rand_callback);
    callbacks.get_new_connection_id = Some(get_new_connection_id_callback);

    callbacks
}

/// サーバー用のコールバックを作成する
fn create_server_callbacks() -> ngtcp2_callbacks {
    let mut callbacks: ngtcp2_callbacks =
        // SAFETY: create_client_callbacks と同じ
        unsafe { std::mem::zeroed() };

    // ngtcp2_crypto_* コールバック (TLS 統合に必須)
    callbacks.recv_client_initial = Some(ngtcp2_crypto_recv_client_initial_cb);
    callbacks.recv_crypto_data = Some(ngtcp2_crypto_recv_crypto_data_cb);
    callbacks.encrypt = Some(ngtcp2_crypto_encrypt_cb);
    callbacks.decrypt = Some(ngtcp2_crypto_decrypt_cb);
    callbacks.hp_mask = Some(ngtcp2_crypto_hp_mask_cb);
    callbacks.update_key = Some(ngtcp2_crypto_update_key_cb);
    callbacks.delete_crypto_aead_ctx = Some(ngtcp2_crypto_delete_crypto_aead_ctx_cb);
    callbacks.delete_crypto_cipher_ctx = Some(ngtcp2_crypto_delete_crypto_cipher_ctx_cb);
    callbacks.get_path_challenge_data = Some(ngtcp2_crypto_get_path_challenge_data_cb);
    callbacks.version_negotiation = Some(ngtcp2_crypto_version_negotiation_cb);

    set_application_callbacks(&mut callbacks);

    // その他の必須コールバック
    callbacks.rand = Some(rand_callback);
    callbacks.get_new_connection_id = Some(get_new_connection_id_callback);

    callbacks
}

/// アプリケーションへ通知するコールバックを設定する
///
/// クライアントとサーバーで共通の集合。ngtcp2 のコールバックはどれも
/// `user_data` に [`ConnectionUserData`] を受け取るため、同じ実装を共有できる。
fn set_application_callbacks(callbacks: &mut ngtcp2_callbacks) {
    // ハンドシェイクの進行 (RFC 9001 Section 4.1)
    callbacks.handshake_completed = Some(handshake_completed_callback);
    callbacks.handshake_confirmed = Some(handshake_confirmed_callback);

    // 0-RTT の拒否 (RFC 9001 Section 4.6.2)。
    // ngtcp2 はクライアントでだけこのコールバックを呼ぶ。
    callbacks.tls_early_data_rejected = Some(tls_early_data_rejected_callback);

    // ストリームのライフサイクル (RFC 9000 Section 2 / 3)
    callbacks.stream_open = Some(stream_open_callback);
    // stream_close2 は stream_close より優先される (ngtcp2 の conn_call_stream_close)。
    // 送信側と受信側のエラーコードを区別できるため V5 の 2 を使う。
    callbacks.stream_close2 = Some(stream_close_callback);
    callbacks.stream_reset = Some(stream_reset_callback);
    callbacks.recv_stop_sending = Some(recv_stop_sending_callback);

    // フロー制御の拡張 (RFC 9000 Section 4.1 / 4.2)
    callbacks.extend_max_stream_data = Some(extend_max_stream_data_callback);
    callbacks.extend_max_local_streams_bidi = Some(extend_max_local_streams_bidi_callback);
    callbacks.extend_max_local_streams_uni = Some(extend_max_local_streams_uni_callback);

    // データ受信
    callbacks.recv_stream_data = Some(recv_stream_data_callback);

    // NEW_TOKEN の受信 (RFC 9000 Section 8.1.4)
    callbacks.recv_new_token = Some(recv_new_token_callback);

    // 送信データの ACK。ngtcp2 は再送のためにアプリケーションのバッファを
    // 参照し続けるため、解放してよいタイミングを受け取る
    callbacks.acked_stream_data_offset = Some(acked_stream_data_offset_callback);
    callbacks.recv_datagram = Some(recv_datagram_callback);

    // 接続状態を失ったピアからの通知 (RFC 9000 Section 10.3)。
    // recv_stateless_reset2 は recv_stateless_reset より優先される
    // (ngtcp2 のコールバック仕様) ため V3 の 2 を使う。
    callbacks.recv_stateless_reset2 = Some(recv_stateless_reset_callback);

    // remove_connection_id (RETIRE_CONNECTION_ID による CID の使用終了) を
    // 登録する。サーバー実装はこれを使ってルーティングテーブルから
    // 使われなくなった CID を取り除く。
    callbacks.remove_connection_id = Some(remove_connection_id_callback);

    // 経路の検証 (RFC 9000 Section 8.2)。
    // ピアが新しいアドレスから送ってきた場合と、ローカルから
    // initiate_migration を呼んだ場合に結果が通知される。
    callbacks.path_validation = Some(path_validation_callback);

    // サーバーの優先アドレスの選択 (RFC 9000 Section 9.6)。
    // クライアントでだけ呼ばれる。設定しないと優先アドレスは無視される。
    callbacks.select_preferred_addr = Some(select_preferred_addr_callback);
}

/// サーバーの優先アドレスを選択するコールバック (RFC 9000 Section 9.6)
///
/// サーバーが preferred_address を通知した場合、ngtcp2 はハンドシェイクの
/// 確認後にこのコールバックを呼ぶ。`dest` に選んだ経路を書き込むと、ngtcp2 は
/// その経路の検証を始め、成功すればクライアントは優先アドレスへ移る。
///
/// 移るかどうかはアプリケーションの判断に任されている。ここでは現在の経路と
/// 同じアドレスファミリの優先アドレスがあれば常に選ぶ。ローカルアドレスは
/// 変わらないため `dest->local` は変更しない (ngtcp2 が現在の経路の値を
/// 入れている)。
unsafe extern "C" fn select_preferred_addr_callback(
    conn: *mut ngtcp2_conn,
    dest: *mut ngtcp2_path,
    paddr: *const ngtcp2_preferred_addr,
    _user_data: *mut c_void,
) -> c_int {
    if conn.is_null() || dest.is_null() || paddr.is_null() {
        return 0;
    }

    // SAFETY: conn は呼び出し中だけ有効。現在の経路は同じアドレスファミリを
    // 判定するために読むだけ。アドレスはプラットフォームの sockaddr として
    // 解釈する (バインディングの構造体は生成環境のフィールド配置を持つ)
    let family = unsafe {
        let path = ngtcp2_conn_get_path2(conn);
        if path.is_null() || (*path).local.addr.is_null() {
            return 0;
        }
        let addr = (*path).local.addr as *mut libc::sockaddr;
        (*addr).sa_family as c_int
    };

    // SAFETY: paddr は呼び出し中だけ有効。選択したアドレスは dest へ複写する
    let (addr, addrlen) = unsafe {
        let paddr = &*paddr;
        if family == libc::AF_INET && paddr.ipv4_present != 0 {
            (
                &paddr.ipv4 as *const ngtcp2_sockaddr_in as *const ngtcp2_sockaddr,
                std::mem::size_of::<libc::sockaddr_in>(),
            )
        } else if family == libc::AF_INET6 && paddr.ipv6_present != 0 {
            (
                &paddr.ipv6 as *const ngtcp2_sockaddr_in6 as *const ngtcp2_sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>(),
            )
        } else {
            // 同じアドレスファミリの優先アドレスが無ければ移らない
            // (dest.remote.addrlen が 0 のままなら ngtcp2 は移行しない)
            return 0;
        }
    };

    // SAFETY: dest->remote.addr は ngtcp2_sockaddr_union 以上の大きさを持つ。
    // ngtcp2_addr_copy_byte は addrlen も合わせて書き込む。優先アドレスの
    // バイト列は ngtcp2 がプラットフォームの sockaddr として書き込んだもの
    unsafe {
        ngtcp2_addr_copy_byte(&mut (*dest).remote, addr, addrlen as ngtcp2_socklen);
    }

    0
}

/// 経路の検証が完了したときに呼ばれるコールバック (RFC 9000 Section 8.2)
///
/// 検証の開始時の通知 (`begin_path_validation`) は使わない。ngtcp2 は
/// 検証が成功した場合も失敗した場合もこのコールバックを呼ぶため、
/// 結果だけをイベントとして通知すれば足りる。
unsafe extern "C" fn path_validation_callback(
    _conn: *mut ngtcp2_conn,
    _flags: u32,
    path: *const ngtcp2_path,
    _fallback_path: *const ngtcp2_path,
    res: ngtcp2_path_validation_result,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は Connection::client_new / server_new で渡した
    // ConnectionUserData を指す
    let Some(user_data) = (unsafe { user_data_mut(user_data) }) else {
        return 0;
    };

    // SAFETY: path は ngtcp2 が呼び出し中だけ有効な領域
    let Some(path) = (unsafe { path_info_from_raw(path) }) else {
        return 0;
    };

    let success = res == ngtcp2_path_validation_result_NGTCP2_PATH_VALIDATION_RESULT_SUCCESS;
    user_data
        .events
        .push_back(ConnectionEvent::PathValidated { path, success });

    0
}

/// ピアが RETIRE_CONNECTION_ID で CID の使用を終了したときに呼ばれる
/// コールバック (RFC 9000 Section 5.1.2)
///
/// サーバー実装はルーティングテーブルからこの CID を取り除く。
unsafe extern "C" fn remove_connection_id_callback(
    _conn: *mut ngtcp2_conn,
    cid: *const ngtcp2_cid,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は Connection::client_new / server_new で渡した
    // ConnectionUserData を指す
    let Some(user_data) = (unsafe { user_data_mut(user_data) }) else {
        return 0;
    };

    // SAFETY: cid は ngtcp2 が呼び出し中だけ有効な領域
    let cid = unsafe {
        if cid.is_null() {
            return 0;
        }
        std::slice::from_raw_parts((*cid).data.as_ptr(), (*cid).datalen)
    };
    if let Some(cid) = ConnectionId::new(cid) {
        user_data.retired_cids.push(cid);
    }

    0
}

/// 乱数生成コールバック
///
/// ngtcp2 が接続 ID や鍵素材の生成に使用する。
unsafe extern "C" fn rand_callback(buf: *mut u8, buflen: usize, _rand_ctx: *const ngtcp2_rand_ctx) {
    // SAFETY: buf は呼び出し元から渡された buflen バイトの有効な領域
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, buflen) };
    let _ = aws_lc_rs::rand::fill(slice);
}

/// 新しいコネクション ID を生成するコールバック (RFC 9000 Section 5.1.1)
///
/// ngtcp2 はピアの `active_connection_id_limit` に応じてこのコールバックを呼び、
/// NEW_CONNECTION_ID フレームで配布する CID と Stateless Reset トークンを求める。
unsafe extern "C" fn get_new_connection_id_callback(
    _conn: *mut ngtcp2_conn,
    cid: *mut ngtcp2_cid,
    token: *mut u8,
    cidlen: usize,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: cid と token は ngtcp2 が用意した cidlen バイトと
    // STATELESS_RESET_TOKEN_LEN バイトの有効な領域。user_data は
    // Connection::client_new / server_new で渡した ConnectionUserData。
    unsafe {
        // 新しい CID を生成する
        let cid_slice = std::slice::from_raw_parts_mut((*cid).data.as_mut_ptr(), cidlen);
        if aws_lc_rs::rand::fill(cid_slice).is_err() {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        (*cid).datalen = cidlen;

        let conn_user_data = user_data_mut(user_data);
        let token_slice = std::slice::from_raw_parts_mut(token, STATELESS_RESET_TOKEN_LEN);

        // cidlen が ConnectionId の許容範囲外のときは記録できないため、
        // トークンだけ埋めて戻る (ngtcp2 が cidlen を 20 超で呼ぶことはない)
        let generated = std::slice::from_raw_parts((*cid).data.as_ptr(), cidlen);
        let Some(issued_cid) = ConnectionId::new(generated) else {
            if aws_lc_rs::rand::fill(token_slice).is_err() {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            return 0;
        };

        // Stateless Reset トークンを作る。
        //
        // 秘密が設定されていればそこから決定論的に導出する
        // (RFC 9000 Section 10.3.1)。導出できない場合は乱数で生成するが、
        // その場合は接続状態を失った後に同じトークンを再現できないため
        // Stateless Reset を送れない。
        let secret = conn_user_data
            .as_ref()
            .and_then(|data| data.stateless_reset_secret.clone());
        match secret.and_then(|secret| secret.token(&issued_cid)) {
            Some(derived) => token_slice.copy_from_slice(derived.as_bytes()),
            None => {
                if aws_lc_rs::rand::fill(token_slice).is_err() {
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
        }

        // 発行した CID を記録する。
        // サーバー実装はこの CID をルーティングテーブルに登録し、
        // ピアが DCID として使うパケットを接続に振り分ける (RFC 9000 Section 5.1.1)。
        if let Some(data) = conn_user_data {
            data.issued_cids.push(issued_cid);
        }
    }

    0
}

/// conn_ref から ngtcp2_conn を取得するコールバック
///
/// TLS コールバック (add_handshake_data など) から呼び出される。
/// `conn_ref.user_data` に ngtcp2_conn へのポインタが保存されている。
unsafe extern "C" fn conn_ref_get_conn_callback(
    conn_ref: *mut ngtcp2_crypto_conn_ref,
) -> *mut ngtcp2_conn {
    // SAFETY: conn_ref は有効なポインタで、user_data には
    // finish_new で設定した ngtcp2_conn へのポインタが保存されている
    unsafe { (*conn_ref).user_data as *mut ngtcp2_conn }
}

/// user_data を [`ConnectionUserData`] への可変参照に変換する
///
/// ngtcp2 のコールバックはすべて同じ user_data ポインタを受け取るため、
/// 変換を 1 箇所に集約する。NULL の場合は `None` を返す。
///
/// # Safety
///
/// `user_data` が NULL または [`Connection::client_new`] /
/// [`Connection::server_new`] で渡した [`ConnectionUserData`] を指しており、
/// その生存期間中であること。
unsafe fn user_data_mut(user_data: *mut c_void) -> Option<&'static mut ConnectionUserData> {
    if user_data.is_null() {
        return None;
    }
    // SAFETY: 呼び出し元の保証による
    Some(unsafe { &mut *(user_data as *mut ConnectionUserData) })
}

/// ハンドシェイク完了コールバック (RFC 9001 Section 4.1.1)
unsafe extern "C" fn handshake_completed_callback(
    conn: *mut ngtcp2_conn,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    let Some(conn_user_data) = (unsafe { user_data_mut(user_data) }) else {
        return 0;
    };

    // 0-RTT を送ったのにサーバーが受理しなかった場合をここで確定させる。
    //
    // aws-lc はハンドシェイクの途中で拒否を通知する (ngtcp2_crypto が
    // SSL_ERROR_EARLY_DATA_REJECTED を受けて
    // ngtcp2_conn_tls_early_data_rejected を呼ぶ) が、TLS の実装によっては
    // ハンドシェイク完了まで分からないことがあるため、ngtcp2 の example と
    // 同様にここでも確認する。ngtcp2_conn_tls_early_data_rejected は既に
    // 呼ばれていれば何もしない。
    if conn_user_data.early_data_attempted && !conn.is_null() {
        // SAFETY: conn は有効。値は読み取るだけで変更しない
        let accepted = unsafe {
            let ssl = ngtcp2_conn_get_tls_native_handle2(conn);
            !ssl.is_null()
                && aws_lc_sys::SSL_early_data_accepted(ssl as *const aws_lc_sys::SSL) != 0
        };
        if !accepted {
            // SAFETY: conn は有効。呼び出しの中で tls_early_data_rejected
            // コールバックが呼ばれ、イベントが積まれる。
            unsafe { ngtcp2_conn_tls_early_data_rejected(conn) };
        }
    }

    conn_user_data
        .events
        .push_back(ConnectionEvent::HandshakeCompleted);
    0
}

/// 0-RTT (early data) が拒否されたときのコールバック (RFC 9001 Section 4.6.2)
///
/// サーバーが 0-RTT を受理しなかった場合と、クライアントが 0-RTT を
/// 送らない判断をした場合に呼ばれる。ngtcp2 はこの時点で 0-RTT で開いた
/// ストリームと送信待ちのデータを破棄するため、アプリケーションは
/// ストリームを開き直してデータを送り直す必要がある。
unsafe extern "C" fn tls_early_data_rejected_callback(
    _conn: *mut ngtcp2_conn,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        conn_user_data
            .events
            .push_back(ConnectionEvent::EarlyDataRejected);
    }
    0
}

/// ハンドシェイク確認コールバック (RFC 9001 Section 4.1.2)
unsafe extern "C" fn handshake_confirmed_callback(
    _conn: *mut ngtcp2_conn,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        conn_user_data
            .events
            .push_back(ConnectionEvent::HandshakeConfirmed);
    }
    0
}

/// ストリームオープンコールバック (RFC 9000 Section 2.1)
///
/// ピアが新しいストリームを開いたときに呼ばれる。ローカルが開いた
/// ストリームでは呼ばれない。
unsafe extern "C" fn stream_open_callback(
    _conn: *mut ngtcp2_conn,
    stream_id: i64,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        conn_user_data
            .events
            .push_back(ConnectionEvent::StreamOpened { stream_id });
    }
    0
}

/// ストリームクローズコールバック (RFC 9000 Section 3.3)
///
/// ngtcp2 の `stream_close2` に対応する。送信側と受信側のエラーコードを
/// 別々に受け取るため、どちらの方向がエラーで閉じたかを区別できる。
unsafe extern "C" fn stream_close_callback(
    _conn: *mut ngtcp2_conn,
    flags: u32,
    stream_id: i64,
    rx_app_error_code: u64,
    tx_app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        // ngtcp2 は閉じたストリームのデータを参照しなくなるため解放する
        conn_user_data.closed_stream(stream_id);

        let rx = (flags & NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET != 0)
            .then_some(rx_app_error_code);
        let tx = (flags & NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET != 0)
            .then_some(tx_app_error_code);
        conn_user_data
            .events
            .push_back(ConnectionEvent::StreamClosed {
                stream_id,
                rx_app_error_code: rx,
                tx_app_error_code: tx,
            });
    }
    0
}

/// qlog 出力コールバック
///
/// ngtcp2 の `qlog_write` に対応する。受け取った断片をためて、
/// [`Connection::poll_qlog_data`] で取り出せるようにする。
pub(crate) unsafe extern "C" fn qlog_write_callback(
    user_data: *mut c_void,
    _flags: u32,
    data: *const c_void,
    datalen: usize,
) {
    if data.is_null() || datalen == 0 {
        return;
    }

    // SAFETY: user_data は ConnectionUserData へのポインタ
    let Some(conn_user_data) = (unsafe { user_data_mut(user_data) }) else {
        return;
    };

    // SAFETY: data と datalen は呼び出し元から渡された有効な領域で、
    // ngtcp2 は呼び出し後に解放するためここでコピーする
    let copied = unsafe { std::slice::from_raw_parts(data as *const u8, datalen) };
    conn_user_data.qlog_data.extend_from_slice(copied);
}

/// NEW_TOKEN 受信コールバック (RFC 9000 Section 8.1.4)
///
/// ngtcp2 の `recv_new_token` に対応する。クライアントは受け取ったトークンを
/// 保存し、次の接続の Initial に載せる。
unsafe extern "C" fn recv_new_token_callback(
    _conn: *mut ngtcp2_conn,
    token: *const u8,
    tokenlen: usize,
    user_data: *mut c_void,
) -> c_int {
    if token.is_null() && tokenlen > 0 {
        return 0;
    }

    // SAFETY: user_data は ConnectionUserData へのポインタ
    let Some(conn_user_data) = (unsafe { user_data_mut(user_data) }) else {
        return 0;
    };

    // SAFETY: token と tokenlen は呼び出し元から渡された有効な領域で、
    // ngtcp2 は呼び出し後に解放するためここでコピーする
    let copied = unsafe {
        if tokenlen > 0 {
            std::slice::from_raw_parts(token, tokenlen).to_vec()
        } else {
            Vec::new()
        }
    };

    conn_user_data.new_tokens.push_back(copied);
    0
}

/// 送信済みストリームデータの ACK コールバック
///
/// ngtcp2 の `acked_stream_data_offset` に対応する。アプリケーションが
/// 渡したバッファを解放してよいタイミングを通知する。
unsafe extern "C" fn acked_stream_data_offset_callback(
    _conn: *mut ngtcp2_conn,
    stream_id: i64,
    offset: u64,
    datalen: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        conn_user_data.acked_stream_data(stream_id, offset, datalen);
    }
    0
}

/// RESET_STREAM 受信コールバック (RFC 9000 Section 19.4)
unsafe extern "C" fn stream_reset_callback(
    _conn: *mut ngtcp2_conn,
    stream_id: i64,
    final_size: u64,
    app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        conn_user_data
            .events
            .push_back(ConnectionEvent::StreamReset {
                stream_id,
                final_size,
                app_error_code,
            });
    }
    0
}

/// STOP_SENDING 受信コールバック (RFC 9000 Section 19.5)
///
/// ngtcp2 はこれを受けて自動的に RESET_STREAM を送り返す。
unsafe extern "C" fn recv_stop_sending_callback(
    _conn: *mut ngtcp2_conn,
    stream_id: i64,
    app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        conn_user_data
            .events
            .push_back(ConnectionEvent::StreamStopSending {
                stream_id,
                app_error_code,
            });
    }
    0
}

/// ストリームデータ受信コールバック (RFC 9000 Section 19.8)
///
/// フロー制御クレジットは [`Connection::extend_max_stream_offset`] で
/// アプリケーションが明示的に戻すまで消費されない。
unsafe extern "C" fn recv_stream_data_callback(
    _conn: *mut ngtcp2_conn,
    flags: u32,
    stream_id: i64,
    _offset: u64,
    data: *const u8,
    datalen: usize,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if data.is_null() && datalen > 0 {
        return 0;
    }

    // SAFETY: user_data は client_new / server_new で渡した ConnectionUserData
    let conn_user_data = unsafe { user_data_mut(user_data) };
    let Some(conn_user_data) = conn_user_data else {
        return 0;
    };

    // SAFETY: data と datalen は呼び出し元から渡された有効な領域で、
    // ngtcp2 は呼び出し後に解放するためここでコピーする必要がある
    let copied = unsafe {
        if datalen > 0 {
            std::slice::from_raw_parts(data, datalen).to_vec()
        } else {
            Vec::new()
        }
    };

    conn_user_data
        .events
        .push_back(ConnectionEvent::StreamData {
            stream_id,
            data: copied,
            fin: flags & NGTCP2_STREAM_DATA_FLAG_FIN != 0,
        });

    0
}

/// ストリームデータの送信許可が拡張されたときのコールバック (RFC 9000 Section 19.10)
///
/// ピアの MAX_STREAM_DATA 受信で送信許可が広がった際に呼ばれる
/// (RFC 9000 Section 4.1)。[`Error::StreamDataBlocked`] で止まっていた
/// 送信を再開できることをアプリケーションに伝える。
unsafe extern "C" fn extend_max_stream_data_callback(
    _conn: *mut ngtcp2_conn,
    stream_id: i64,
    max_data: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        conn_user_data
            .events
            .push_back(ConnectionEvent::StreamMaxData {
                stream_id,
                max_data,
            });
    }
    0
}

/// 開ける双方向ストリーム数の上限が拡張されたときのコールバック
/// (RFC 9000 Section 19.11)
unsafe extern "C" fn extend_max_local_streams_bidi_callback(
    _conn: *mut ngtcp2_conn,
    max_streams: u64,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        conn_user_data
            .events
            .push_back(ConnectionEvent::MaxStreamsBidi { max_streams });
    }
    0
}

/// 開ける単方向ストリーム数の上限が拡張されたときのコールバック
/// (RFC 9000 Section 19.11)
unsafe extern "C" fn extend_max_local_streams_uni_callback(
    _conn: *mut ngtcp2_conn,
    max_streams: u64,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は ConnectionUserData へのポインタ
    if let Some(conn_user_data) = unsafe { user_data_mut(user_data) } {
        conn_user_data
            .events
            .push_back(ConnectionEvent::MaxStreamsUni { max_streams });
    }
    0
}

/// DATAGRAM 受信コールバック (RFC 9221)
unsafe extern "C" fn recv_datagram_callback(
    _conn: *mut ngtcp2_conn,
    _flags: u32,
    data: *const u8,
    datalen: usize,
    user_data: *mut c_void,
) -> c_int {
    if data.is_null() && datalen > 0 {
        return 0;
    }

    // SAFETY: user_data は client_new / server_new で渡した ConnectionUserData
    let conn_user_data = unsafe { user_data_mut(user_data) };
    let Some(conn_user_data) = conn_user_data else {
        return 0;
    };

    // SAFETY: data と datalen は呼び出し元から渡された有効な領域で、
    // ngtcp2 は呼び出し後に解放するためここでコピーする必要がある
    let copied = unsafe {
        if datalen > 0 {
            std::slice::from_raw_parts(data, datalen).to_vec()
        } else {
            Vec::new()
        }
    };

    conn_user_data
        .events
        .push_back(ConnectionEvent::Datagram { data: copied });

    0
}

/// Stateless Reset 受信コールバック (RFC 9000 Section 10.3)
///
/// トークンが一致した場合にだけ ngtcp2 が呼ぶ (RFC 9000 Section 10.3.1)。
/// 受信したトークンはアプリケーションに渡さない。トークンを知っている者は
/// 偽の Stateless Reset を作れるため、ログなどに残すべきではない。
unsafe extern "C" fn recv_stateless_reset_callback(
    _conn: *mut ngtcp2_conn,
    _sr: *const ngtcp2_pkt_stateless_reset2,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: user_data は client_new / server_new で渡した ConnectionUserData
    let conn_user_data = unsafe { user_data_mut(user_data) };
    if let Some(data) = conn_user_data {
        data.events
            .push_back(ConnectionEvent::StatelessResetReceived);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 送信済みデータが ACK された分だけ解放されること
    #[test]
    fn test_in_flight_stream_data_ack() {
        let mut data = InFlightStreamData {
            offset: 0,
            data: Vec::new(),
            start: 0,
        };
        let appended = data.append(b"0123456789");
        assert_eq!(appended, 0..10, "追加した範囲が返ること");
        assert_eq!(data.unacked(), b"0123456789", "未 ACK のデータが返ること");

        // 先頭 4 バイトの ACK
        data.ack_until(4);
        assert_eq!(data.unacked(), b"456789", "ACK された分が捨てられること");
        assert_eq!(data.offset, 4, "先頭のオフセットが進むこと");

        // 重複した範囲の ACK は無視される
        data.ack_until(2);
        assert_eq!(data.unacked(), b"456789", "変化しないこと");

        // すべて ACK されると空になり、オフセットは保持される
        data.ack_until(10);
        assert!(data.unacked().is_empty(), "空になること");
        assert_eq!(data.offset, 10, "オフセットは保持されること");

        // 空になった後も続きを追加できる
        data.append(b"abc");
        assert_eq!(data.unacked(), b"abc", "続きを追加できること");
    }

    /// 書き出されなかった末尾が保持されないこと
    #[test]
    fn test_in_flight_stream_data_truncate_unwritten() {
        let mut data = InFlightStreamData {
            offset: 0,
            data: Vec::new(),
            start: 0,
        };
        data.append(b"0123456789");
        // 4 バイトだけ書き出された
        data.truncate_unwritten(4);
        assert_eq!(data.unacked(), b"0123", "書き出した分だけ残ること");

        // 続きを渡し直すと未 ACK の末尾に連結される
        let appended = data.append(b"456789");
        assert_eq!(appended, 4..10, "未 ACK の末尾に追加されること");
        assert_eq!(data.unacked(), b"0123456789", "連結されること");
    }

    /// ストリームが閉じたら送信済みデータを解放すること
    #[test]
    fn test_in_flight_stream_data_closed_stream() {
        let mut user_data = ConnectionUserData::new();
        user_data.in_flight_stream_data.insert(
            0,
            InFlightStreamData {
                offset: 0,
                data: b"abc".to_vec(),
                start: 0,
            },
        );
        user_data.in_flight_stream_data.insert(
            4,
            InFlightStreamData {
                offset: 0,
                data: b"def".to_vec(),
                start: 0,
            },
        );

        user_data.closed_stream(0);
        assert!(
            !user_data.in_flight_stream_data.contains_key(&0),
            "閉じたストリームのデータが消えること"
        );
        assert!(
            user_data.in_flight_stream_data.contains_key(&4),
            "他のストリームのデータは残ること"
        );
    }

    /// ACK の範囲に応じて先頭から解放されること
    #[test]
    fn test_acked_stream_data() {
        let mut user_data = ConnectionUserData::new();
        user_data.in_flight_stream_data.insert(
            0,
            InFlightStreamData {
                offset: 100,
                data: b"abcdef".to_vec(),
                start: 0,
            },
        );

        // 範囲の一部が ACK された
        user_data.acked_stream_data(0, 100, 2);
        let entry = user_data
            .in_flight_stream_data
            .get(&0)
            .expect("エントリが残ること");
        assert_eq!(entry.unacked(), b"cdef", "ACK された分が捨てられること");

        // 保持していないストリームの ACK は無視される
        user_data.acked_stream_data(4, 0, 10);
        assert_eq!(
            user_data.in_flight_stream_data.len(),
            1,
            "知らないストリームは追加しないこと"
        );
    }

    /// ConnectionId が ngtcp2_cid に正しく変換されること
    #[test]
    fn test_cid_to_raw() {
        let cid = ConnectionId::new(&[0x01, 0x02, 0x03, 0x04]).expect("test must succeed");
        let raw = cid_to_raw(&cid);
        assert_eq!(raw.datalen, 4, "CID 長");
        assert_eq!(&raw.data[..4], &[0x01, 0x02, 0x03, 0x04], "CID の内容");
        // 残りはゼロ埋めされること
        assert!(raw.data[4..].iter().all(|b| *b == 0), "残りはゼロ埋め");
    }

    /// IPv4 アドレスが sockaddr_storage に正しく変換されること
    #[test]
    fn test_sockaddr_to_raw_v4() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().expect("test must succeed");
        let (storage, len) = sockaddr_to_raw(&addr);
        assert_eq!(
            len as usize,
            std::mem::size_of::<libc::sockaddr_in>(),
            "sockaddr_in のサイズ"
        );

        // SAFETY: storage は sockaddr_in として初期化済み
        let sin: libc::sockaddr_in = unsafe { *(&storage as *const _ as *const libc::sockaddr_in) };
        assert_eq!(
            sin.sin_family,
            libc::AF_INET as libc::sa_family_t,
            "アドレスファミリ"
        );
        assert_eq!(
            sin.sin_port.to_be(),
            4433,
            "ポート (ネットワークバイトオーダー)"
        );
    }

    /// IPv6 アドレスが sockaddr_storage に正しく変換されること
    #[test]
    fn test_sockaddr_to_raw_v6() {
        let addr: SocketAddr = "[::1]:4433".parse().expect("test must succeed");
        let (storage, len) = sockaddr_to_raw(&addr);
        assert_eq!(
            len as usize,
            std::mem::size_of::<libc::sockaddr_in6>(),
            "sockaddr_in6 のサイズ"
        );

        // SAFETY: storage は sockaddr_in6 として初期化済み
        let sin6: libc::sockaddr_in6 =
            unsafe { *(&storage as *const _ as *const libc::sockaddr_in6) };
        assert_eq!(
            sin6.sin6_family,
            libc::AF_INET6 as libc::sa_family_t,
            "アドレスファミリ"
        );
        assert_eq!(
            sin6.sin6_port.to_be(),
            4433,
            "ポート (ネットワークバイトオーダー)"
        );
    }

    /// アプリケーションへ通知するコールバックが全て設定されること
    ///
    /// クライアントとサーバーで共通の集合。1 つでも未設定だと対応する
    /// [`ConnectionEvent`] が発生しなくなるため、網羅的に確認する。
    fn assert_application_callbacks_set(callbacks: &ngtcp2_callbacks, side: &str) {
        assert!(
            callbacks.handshake_completed.is_some(),
            "{side}: handshake_completed が設定されること"
        );
        assert!(
            callbacks.handshake_confirmed.is_some(),
            "{side}: handshake_confirmed が設定されること"
        );
        assert!(
            callbacks.stream_open.is_some(),
            "{side}: stream_open が設定されること"
        );
        assert!(
            callbacks.stream_close2.is_some(),
            "{side}: stream_close2 が設定されること"
        );
        assert!(
            callbacks.stream_reset.is_some(),
            "{side}: stream_reset が設定されること"
        );
        assert!(
            callbacks.recv_stop_sending.is_some(),
            "{side}: recv_stop_sending が設定されること"
        );
        assert!(
            callbacks.extend_max_stream_data.is_some(),
            "{side}: extend_max_stream_data が設定されること"
        );
        assert!(
            callbacks.extend_max_local_streams_bidi.is_some(),
            "{side}: extend_max_local_streams_bidi が設定されること"
        );
        assert!(
            callbacks.extend_max_local_streams_uni.is_some(),
            "{side}: extend_max_local_streams_uni が設定されること"
        );
        assert!(
            callbacks.recv_stream_data.is_some(),
            "{side}: recv_stream_data が設定されること"
        );
        assert!(
            callbacks.recv_datagram.is_some(),
            "{side}: recv_datagram が設定されること"
        );
        assert!(
            callbacks.recv_stateless_reset2.is_some(),
            "{side}: recv_stateless_reset2 が設定されること"
        );
        assert!(
            callbacks.tls_early_data_rejected.is_some(),
            "{side}: tls_early_data_rejected が設定されること"
        );
    }

    /// クライアント用コールバックに必須のものが設定されること
    #[test]
    fn test_create_client_callbacks() {
        let callbacks = create_client_callbacks();
        assert!(
            callbacks.client_initial.is_some(),
            "client_initial が設定されること"
        );
        assert!(
            callbacks.recv_crypto_data.is_some(),
            "recv_crypto_data が設定されること"
        );
        assert!(callbacks.encrypt.is_some(), "encrypt が設定されること");
        assert!(callbacks.decrypt.is_some(), "decrypt が設定されること");
        assert!(callbacks.hp_mask.is_some(), "hp_mask が設定されること");
        assert!(callbacks.rand.is_some(), "rand が設定されること");
        assert!(
            callbacks.get_new_connection_id.is_some(),
            "get_new_connection_id が設定されること"
        );
        // サーバー専用のコールバックは設定されないこと
        assert!(
            callbacks.recv_client_initial.is_none(),
            "recv_client_initial は設定されないこと"
        );

        assert_application_callbacks_set(&callbacks, "クライアント");
    }

    /// サーバー用コールバックに必須のものが設定されること
    #[test]
    fn test_create_server_callbacks() {
        let callbacks = create_server_callbacks();
        assert!(
            callbacks.recv_client_initial.is_some(),
            "recv_client_initial が設定されること"
        );
        assert!(
            callbacks.recv_crypto_data.is_some(),
            "recv_crypto_data が設定されること"
        );
        assert!(callbacks.encrypt.is_some(), "encrypt が設定されること");
        assert!(callbacks.decrypt.is_some(), "decrypt が設定されること");
        assert!(callbacks.hp_mask.is_some(), "hp_mask が設定されること");
        assert!(callbacks.rand.is_some(), "rand が設定されること");
        assert!(
            callbacks.get_new_connection_id.is_some(),
            "get_new_connection_id が設定されること"
        );
        // クライアント専用のコールバックは設定されないこと
        assert!(
            callbacks.client_initial.is_none(),
            "client_initial は設定されないこと"
        );

        assert_application_callbacks_set(&callbacks, "サーバー");
    }

    /// user_data が NULL のときはイベントを積まずに成功すること
    ///
    /// ngtcp2 は user_data を渡さない呼び出し経路を持たないが、コールバックは
    /// extern "C" であり NULL を渡されてもパニックしてはいけない。
    #[test]
    fn test_user_data_mut_rejects_null() {
        assert!(
            // SAFETY: NULL を渡すこと自体は安全。中身を参照しないことを確認する
            unsafe { user_data_mut(ptr::null_mut()) }.is_none(),
            "NULL の user_data は None になること"
        );
    }

    /// セッション情報がバイト列から復元できること
    ///
    /// アプリケーションはセッション情報を保存して次回の起動で使うため、
    /// 公開 API でバイト列から作り直せる必要がある。
    #[test]
    fn test_session_ticket_roundtrip() {
        let ticket = SessionTicket::new(vec![1, 2, 3], vec![4, 5]);
        assert_eq!(ticket.session(), &[1, 2, 3], "セッションのバイト列");
        assert_eq!(
            ticket.transport_params(),
            &[4, 5],
            "トランスポートパラメータのバイト列"
        );

        let restored = SessionTicket::new(
            ticket.session().to_vec(),
            ticket.transport_params().to_vec(),
        );
        assert_eq!(restored, ticket, "復元したセッション情報が一致すること");
    }

    /// セッション情報の Debug に内容を出さないこと
    ///
    /// セッションは接続の再開に使えるため、ログに残さない。
    #[test]
    fn test_session_ticket_debug_hides_contents() {
        let ticket = SessionTicket::new(vec![0xde, 0xad], vec![0xbe, 0xef, 0x00]);
        assert_eq!(
            format!("{ticket:?}"),
            "SessionTicket { session_len: 2, transport_params_len: 3 }",
            "長さだけを出力すること"
        );
    }

    /// ハンドシェイク前は early data の状態が初期値であること
    ///
    /// クライアント接続を作っただけでパケットをやり取りしていない状態では、
    /// 0-RTT は始まっていない。
    #[test]
    fn test_early_data_state_before_handshake() {
        let tls_ctx = crate::TlsContext::new_client_with_options(&[b"hq-interop"], false)
            .expect("TLS コンテキストを作れること");
        let session = tls_ctx
            .create_session()
            .expect("TLS セッションを作れること");
        let dcid = ConnectionId::random(16).expect("DCID を生成できること");
        let scid = ConnectionId::random(16).expect("SCID を生成できること");
        let local: SocketAddr = "127.0.0.1:1".parse().expect("リテラルアドレスは有効");
        let remote: SocketAddr = "127.0.0.1:2".parse().expect("リテラルアドレスは有効");

        let mut conn = Connection::client_new(
            &dcid,
            &scid,
            local,
            remote,
            QuicVersion::V1,
            "localhost",
            session,
            &TransportParams::new(),
            &Settings::new(0),
        )
        .expect("クライアント接続を作れること");

        assert!(
            !conn.is_in_early_data(),
            "セッションを設定していなければ 0-RTT を送らないこと"
        );
        assert!(
            !conn.is_early_data_accepted(),
            "ハンドシェイク前は受理が確定しないこと"
        );
        assert!(
            !conn.is_early_data_rejected(),
            "0-RTT を試みていないため拒否もされていないこと"
        );
        assert!(
            conn.take_session_ticket()
                .expect("セッション情報を取得できること")
                .is_none(),
            "ハンドシェイク前はセッション情報を取り出せないこと"
        );
    }

    /// 不正なセッション情報では 0-RTT 付きの接続を作れないこと
    #[test]
    fn test_client_new_with_0rtt_rejects_invalid_session() {
        let tls_ctx = crate::TlsContext::new_client_with_options(&[b"hq-interop"], false)
            .expect("TLS コンテキストを作れること");
        let session = tls_ctx
            .create_session()
            .expect("TLS セッションを作れること");
        let dcid = ConnectionId::random(16).expect("DCID を生成できること");
        let scid = ConnectionId::random(16).expect("SCID を生成できること");
        let local: SocketAddr = "127.0.0.1:1".parse().expect("リテラルアドレスは有効");
        let remote: SocketAddr = "127.0.0.1:2".parse().expect("リテラルアドレスは有効");

        // セッションとして解釈できないバイト列を渡す
        let ticket = SessionTicket::new(vec![0xff; 16], vec![0x00]);
        let result = Connection::client_new_with_0rtt(
            &dcid,
            &scid,
            local,
            remote,
            QuicVersion::V1,
            "localhost",
            session,
            &TransportParams::new(),
            &Settings::new(0),
            &ticket,
        );
        let Err(err) = result else {
            panic!("不正なセッション情報は拒否されること");
        };
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "不正なセッション情報は InvalidArgument であること: {err:?}"
        );
    }
}
