//! QUIC クライアントの非同期実装

use std::net::SocketAddr;
use std::time::Duration;

use shiguredo_ngtcp2::{
    ConnStats, Connection, ConnectionErrorKind, ConnectionId, Error, PacketInfo, PathInfo,
    QuicVersion, RemoteTransportParams, Result, SessionTicket, Settings, StreamId, TlsContext,
    TransportParams,
};

use crate::qlog::{QlogWriter, file_name};
use crate::socket::{Socket, timestamp};
use crate::streams::{
    OutgoingPacket, PendingStreams, close_packets, write_control_packets, write_packets,
};
use crate::{ConnectionEvent, DatagramConfig};

/// 受信バッファのサイズ (バイト)
///
/// UDP の最大ペイロード (65535) を収容できる必要がある。
const RECV_BUFFER_SIZE: usize = 65535;

/// 送信バッファのサイズ (バイト)
const SEND_BUFFER_SIZE: usize = 65535;

/// ハンドシェイクの既定タイムアウト
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 接続に使う既定の ALPN プロトコル
///
/// HTTP/3 を載せない素の QUIC の相互運用に使われる `hq-interop`
/// (HTTP/0.9 over QUIC) を使う。
const DEFAULT_ALPN: &[u8] = b"hq-interop";

/// クライアントの設定
///
/// [`ClientConfig::new`] で ALPN を指定して作成し、`with_*` で調整する。
#[derive(Clone)]
pub struct ClientConfig {
    /// ALPN プロトコルリスト (RFC 7301)
    ///
    /// サーバーと一致しない場合はハンドシェイクが失敗する。
    pub alpn_protocols: Vec<Vec<u8>>,
    /// ピアの証明書チェーンとホスト名を検証するかどうか (RFC 9001 Section 4.4)
    ///
    /// true の場合、トラストストアはデフォルトの CA パスと `SSL_CERT_FILE` /
    /// `SSL_CERT_DIR` 環境変数から読み込む。
    pub verify_peer: bool,
    /// トランスポートパラメータ (RFC 9000 Section 18)
    pub transport_params: TransportParams,
    /// DATAGRAM の設定 (RFC 9221)
    pub datagram: DatagramConfig,
    /// ハンドシェイクのタイムアウト
    pub handshake_timeout: Duration,
    /// qlog の出力先ディレクトリ
    ///
    /// 指定すると接続ごとに `<ディレクトリ>/<SCID>.sqlog` を作り、qlog を
    /// 書き出す。`None` の場合は出力しない。
    pub qlog_dir: Option<std::path::PathBuf>,
    /// トラストストアに追加する CA 証明書 (PEM 形式)
    ///
    /// `verify_peer` が true の場合のみ使われる。デフォルトのトラストストアに
    /// **追加** される (置換はしない)。
    pub ca_cert_pem: Vec<String>,
    /// 使用する QUIC バージョン (RFC 9000 Section 6)
    ///
    /// サーバーがこのバージョンをサポートしていない場合は Version Negotiation
    /// パケットが返り、ハンドシェイクは失敗する。本実装は Version Negotiation
    /// によるバージョンの切り替えを行わない。
    pub quic_version: QuicVersion,
    /// 接続設定 (輻輳制御アルゴリズム、初期 RTT、keep-alive など)
    ///
    /// [`Settings::initial_ts`] は接続の作成時に実際の時刻で上書きされるため、
    /// 設定しておく必要はない。
    pub settings: Settings,
}

impl ClientConfig {
    /// ALPN を指定して設定を作成する
    ///
    /// - `verify_peer`: true (証明書を検証する)
    /// - `transport_params`: [`TransportParams::new()`]
    /// - `datagram`: [`DatagramConfig::default()`]
    /// - `handshake_timeout`: 10 秒
    /// - `quic_version`: QUIC v1
    /// - `settings`: [`Settings::new`]`(0)`
    pub fn new(alpn_protocols: &[&[u8]]) -> Self {
        Self {
            alpn_protocols: alpn_protocols.iter().map(|p| p.to_vec()).collect(),
            verify_peer: true,
            transport_params: TransportParams::new(),
            datagram: DatagramConfig::default(),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            qlog_dir: None,
            ca_cert_pem: Vec::new(),
            quic_version: QuicVersion::V1,
            // initial_ts は接続の作成時に上書きされるため 0 でよい
            settings: Settings::new(0),
        }
    }

    /// 使用する QUIC バージョンを設定する (RFC 9000 Section 6)
    pub fn with_quic_version(mut self, quic_version: QuicVersion) -> Self {
        self.quic_version = quic_version;
        self
    }

    /// 接続設定を設定する
    ///
    /// [`Settings::initial_ts`] は接続の作成時に実際の時刻で上書きされる。
    pub fn with_settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    /// 証明書検証の有無を設定する
    pub fn with_verify_peer(mut self, verify_peer: bool) -> Self {
        self.verify_peer = verify_peer;
        self
    }

    /// トランスポートパラメータを設定する
    pub fn with_transport_params(mut self, params: TransportParams) -> Self {
        self.transport_params = params;
        self
    }

    /// DATAGRAM の設定を指定する
    ///
    /// DATAGRAM を有効にする場合は `transport_params` にも
    /// `with_datagram` を設定すること。ピアに通知されない限り送受信できない。
    pub fn with_datagram(mut self, datagram: DatagramConfig) -> Self {
        self.datagram = datagram;
        self
    }

    /// 互換バージョン交渉で提示するバージョンを設定する (RFC 9368)
    ///
    /// 優先順に並べる。自分が選んだバージョン ([`ClientConfig::quic_version`]) を
    /// 含めること。サーバーがこの一覧の中からバージョンを選ぶため、
    /// Version Negotiation パケットをやり取りせずに接続を確立できる。
    pub fn with_preferred_versions(mut self, versions: &[QuicVersion]) -> Self {
        self.settings.preferred_versions = versions.to_vec();
        // 相手に通知する利用可能なバージョンも同じ一覧にする
        self.settings.available_versions = versions.to_vec();
        self
    }

    /// qlog の出力先ディレクトリを設定する
    ///
    /// 接続ごとに `<ディレクトリ>/<SCID>.sqlog` を作り、qlog (JSON Text
    /// Sequence、RFC 7464) を書き出す。ディレクトリが無い場合は作る。
    /// ファイルを開けない場合は qlog を無効にして接続は続ける。
    pub fn with_qlog_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.qlog_dir = Some(dir.into());
        self
    }

    /// ハンドシェイクのタイムアウトを設定する
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// トラストストアに追加する CA 証明書を設定する (PEM 形式)
    ///
    /// 自己署名証明書やプライベート CA を使う場合に指定する。
    /// `verify_peer` が true の場合のみ効果がある。
    pub fn with_ca_cert_pem(mut self, ca_cert_pem: impl Into<String>) -> Self {
        self.ca_cert_pem.push(ca_cert_pem.into());
        self
    }

    /// DATAGRAM の設定を反映したトランスポートパラメータを返す
    fn effective_transport_params(&self) -> TransportParams {
        let params = self.transport_params.clone();
        if self.datagram.is_enabled() {
            params.with_datagram(self.datagram.max_datagram_frame_size)
        } else {
            // DATAGRAM を無効にする場合は 0 を通知する
            params.with_datagram(0)
        }
    }

    /// ALPN プロトコルリストを `&[&[u8]]` に変換する
    fn alpn_refs(&self) -> Vec<&[u8]> {
        self.alpn_protocols.iter().map(|p| p.as_slice()).collect()
    }
}

/// 確立済みの QUIC クライアント接続
///
/// [`Client::connect`] / [`Client::connect_with_config`] が返す。
pub struct ClientConnection {
    socket: Socket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    // TLS コンテキスト (SSL_CTX の所有権を保持する)
    _tls_ctx: TlsContext,
    conn: Connection,
    // 送信待ちのストリームデータ
    pending: PendingStreams,
    // 未処理のイベント
    //
    // Vec の先頭から取り出す。イベント数は高々数十なので O(n) の
    // remove(0) でも問題にならない。
    events: Vec<ConnectionEvent>,
    // 接続の終了を検出済みか
    closed: bool,
    // 受信バッファ
    recv_buf: Box<[u8]>,
    // 送信バッファ
    send_buf: Box<[u8]>,
    // DATAGRAM の設定
    datagram: DatagramConfig,
    // qlog の出力先
    qlog: QlogWriter,
}

impl ClientConnection {
    /// ローカルアドレスを返す
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// リモートアドレスを返す
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// ハンドシェイクが完了しているかどうかを返す (RFC 9001 Section 4.1.1)
    pub fn is_handshake_completed(&self) -> bool {
        self.conn.is_handshake_completed()
    }

    /// 0-RTT (early data) を送信している最中かどうかを返す
    /// (RFC 9001 Section 4.6)
    ///
    /// [`Client::connect_with_early_data`] が返した接続では、ハンドシェイクが
    /// 完了するまで true になる。この間 [`ClientConnection::write_stream`] で
    /// 書いたデータは 0-RTT パケットで送られる。
    pub fn is_in_early_data(&self) -> bool {
        self.conn.is_in_early_data()
    }

    /// 0-RTT (early data) がサーバーに受理されたかどうかを返す
    /// (RFC 9001 Section 4.6.2)
    ///
    /// ハンドシェイクが完了するまでは受理が確定しないため、完了前に呼ぶと
    /// false になる。受理されなかった場合は
    /// [`ConnectionEvent::EarlyDataRejected`] が届く。
    pub fn is_early_data_accepted(&self) -> bool {
        self.conn.is_early_data_accepted()
    }

    /// 0-RTT (early data) が拒否されたかどうかを返す (RFC 9001 Section 4.6.2)
    ///
    /// 拒否された時点で 0-RTT で開いたストリームと送信待ちのデータは破棄される。
    pub fn is_early_data_rejected(&self) -> bool {
        self.conn.is_early_data_rejected()
    }

    /// 次回の接続で 0-RTT を送るためのセッション情報を取り出す
    /// (RFC 9001 Section 4.6)
    ///
    /// TLS 1.3 のセッションチケットはハンドシェイク完了後にサーバーから届く
    /// (RFC 8446 Section 4.6.1)。そのためハンドシェイク完了後に
    /// [`ClientConnection::recv_event`] などでパケットを処理したあとに呼び出す
    /// こと。まだ届いていない場合と、一度取り出した後は `Ok(None)` を返す。
    ///
    /// 取り出したセッション情報は [`Client::connect_with_early_data`] に渡す。
    /// 保存しておけば、次回の接続でハンドシェイクの完了を待たずにデータを
    /// 送れる。
    ///
    /// # Errors
    ///
    /// 0-RTT 用のトランスポートパラメータをエンコードできなかった場合に
    /// エラーを返す。
    pub fn take_session_ticket(&mut self) -> Result<Option<SessionTicket>> {
        self.conn.take_session_ticket()
    }

    /// 交渉された ALPN プロトコルを返す (RFC 7301 Section 3)
    ///
    /// ハンドシェイクが完了した接続では常に `Some` になる。ALPN が一致しない
    /// 場合はハンドシェイク自体が失敗するため、`None` になることはない。
    /// 戻り値はプロトコル名のバイト列で、長さプレフィックスは含まない。
    pub fn selected_alpn_protocol(&self) -> Option<Vec<u8>> {
        self.conn.selected_alpn_protocol()
    }

    /// この接続で使用されている QUIC バージョンを返す (RFC 9000 Section 6)
    ///
    /// 通常は [`ClientConfig::quic_version`] に設定した値。互換バージョン交渉
    /// (RFC 9368) を行った場合は、サーバーが選んだバージョンになる。ngtcp2 が
    /// [`QuicVersion`] で表現できないバージョンを報告した場合は `None`。
    pub fn negotiated_version(&self) -> Option<QuicVersion> {
        self.conn.negotiated_version()
    }

    /// 接続が closing / draining 期間に入っているかを返す (RFC 9000 Section 10.2)
    pub fn is_closed(&self) -> bool {
        self.closed || self.conn.is_in_closing_period() || self.conn.is_in_draining_period()
    }

    /// 送信待ちのデータが残っているかどうかを返す
    ///
    /// [`ClientConnection::write_stream`] で積んだデータのうち、フロー制御や
    /// 輻輳制御でまだ送れていないものが残っている場合に true を返す。
    /// true の間は [`ClientConnection::flush`] または
    /// [`ClientConnection::recv_event`] を繰り返し呼ぶこと。
    pub fn has_pending_data(&self) -> bool {
        !self.pending.is_empty()
    }

    /// 接続の統計情報を返す
    ///
    /// RTT、輻輳ウィンドウ、送受信量、パケット喪失などのスナップショット。
    /// 診断やメトリクスの収集に使う。
    pub fn stats(&self) -> ConnStats {
        self.conn.stats()
    }

    /// 輻輳ウィンドウの残りを返す (RFC 9002 Section 7)
    ///
    /// 0 の場合は輻輳制御で送信を止めなければならず、ACK を待つ必要がある。
    pub fn cwnd_left(&self) -> u64 {
        self.conn.get_cwnd_left()
    }

    /// ストリームで送信可能な残りのデータ量を返す (RFC 9000 Section 4.1)
    ///
    /// 存在しないストリーム ID を渡した場合は 0 を返す。
    pub fn max_stream_data_left(&self, stream_id: StreamId) -> u64 {
        self.conn.get_max_stream_data_left(stream_id)
    }

    /// 接続全体で送信可能な残りのデータ量を返す (RFC 9000 Section 4.1)
    ///
    /// ピアの `initial_max_data` と MAX_DATA から決まる接続レベルの
    /// フロー制御ウィンドウの残り。0 の場合は MAX_DATA を待つ必要がある。
    pub fn max_data_left(&self) -> u64 {
        self.conn.get_max_data_left()
    }

    /// 開ける残りの双方向ストリーム数を返す (RFC 9000 Section 4.2)
    ///
    /// 0 の場合は [`ClientConnection::open_bidi_stream`] がエラーになり、
    /// ピアの MAX_STREAMS ([`ConnectionEvent::MaxStreamsBidi`]) を待つ必要がある。
    pub fn streams_bidi_left(&self) -> u64 {
        self.conn.get_streams_bidi_left()
    }

    /// 開ける残りの単方向ストリーム数を返す (RFC 9000 Section 4.2)
    ///
    /// 0 の場合は [`ClientConnection::open_uni_stream`] がエラーになり、
    /// ピアの MAX_STREAMS ([`ConnectionEvent::MaxStreamsUni`]) を待つ必要がある。
    pub fn streams_uni_left(&self) -> u64 {
        self.conn.get_streams_uni_left()
    }

    /// ピアが通知したトランスポートパラメータを返す (RFC 9000 Section 18)
    ///
    /// ハンドシェイクが完了した接続では常に `Some` になる。
    /// 各フィールドの向きについては [`RemoteTransportParams`] の
    /// ドキュメントを参照。
    pub fn remote_transport_params(&self) -> Option<RemoteTransportParams> {
        self.conn.remote_transport_params()
    }

    /// ピアが通知した `max_datagram_frame_size` を返す (RFC 9221 Section 3)
    ///
    /// ピアが DATAGRAM をサポートしていない場合、またはトランスポート
    /// パラメータがまだ届いていない場合は 0 を返す。
    pub fn remote_max_datagram_frame_size(&self) -> u64 {
        self.remote_transport_params()
            .map_or(0, |params| params.max_datagram_frame_size)
    }

    /// ローカルがピアに通知した `max_datagram_frame_size` を返す (RFC 9221 Section 3)
    ///
    /// [`crate::DatagramConfig`] を無効にしている場合は 0 になる。
    pub fn local_max_datagram_frame_size(&self) -> u64 {
        if self.datagram.is_enabled() {
            self.datagram.max_datagram_frame_size
        } else {
            0
        }
    }

    /// ピアが DATAGRAM を受信できるかどうかを返す
    ///
    /// ハンドシェイクが完了するまではピアのトランスポートパラメータが無いため
    /// false になる。[`Client::connect_with_early_data`] が返した直後の接続では
    /// 0-RTT の間 false になり、DATAGRAM は送れない (ストリームのデータは
    /// 送れる)。
    pub fn can_send_datagram(&self) -> bool {
        self.datagram.is_enabled() && self.conn.can_send_datagram()
    }

    /// ピアが RESET_STREAM_AT を受理するかどうかを返す
    /// (draft-ietf-quic-reliable-stream-reset)
    ///
    /// ピアが `reset_stream_at` を通知していない場合、またはトランスポート
    /// パラメータがまだ届いていない場合は false。true の場合、
    /// [`ClientConnection::reset_stream_reliable`] が送信中のデータの配信を保証する。
    pub fn supports_reset_stream_at(&self) -> bool {
        self.conn.supports_reset_stream_at()
    }

    /// 双方向ストリームを開く (RFC 9000 Section 2.1)
    ///
    /// # Errors
    ///
    /// ピアが許可した双方向ストリーム数の上限に達している場合にエラーを返す。
    pub fn open_bidi_stream(&mut self) -> Result<StreamId> {
        self.conn.open_bidi_stream()
    }

    /// 単方向ストリームを開く (RFC 9000 Section 2.1)
    ///
    /// # Errors
    ///
    /// ピアが許可した単方向ストリーム数の上限に達している場合にエラーを返す。
    pub fn open_uni_stream(&mut self) -> Result<StreamId> {
        self.conn.open_uni_stream()
    }

    /// ストリームにデータを書き込む
    ///
    /// `fin` が true の場合、このデータの後ろで送信側を終端する
    /// (RFC 9000 Section 19.8)。
    ///
    /// この呼び出しはデータを送信待ちに積むだけで、パケットは送らない。
    /// 送信するには [`ClientConnection::flush`] を呼ぶか、送信と受信を
    /// 交互に行う [`ClientConnection::recv_event`] を呼ぶ。
    /// 送信と受信を交互に行わないとピアの ACK や MAX_STREAM_DATA を
    /// 受け取れず、輻輳ウィンドウとフロー制御ウィンドウが伸びないため、
    /// 大きなデータを送る場合は `recv_event` を併用すること。
    ///
    /// フロー制御や輻輳制御で送りきれなかったデータは内部に保持し、次の
    /// `flush` / `recv_event` で再送を試みる。そのため戻り値は常に `data.len()`。
    ///
    /// # Errors
    ///
    /// 接続が閉じている場合にエラーを返す。
    pub fn write_stream(&mut self, stream_id: StreamId, data: &[u8], fin: bool) -> Result<usize> {
        if self.is_closed() {
            return Err(Error::ConnectionClosed);
        }
        self.pending.push(stream_id, data, fin);
        Ok(data.len())
    }

    /// 未処理のイベントを 1 つ取り出す (ノンブロッキング)
    ///
    /// イベントがない場合は `None` を返す。
    pub fn poll_event(&mut self) -> Option<ConnectionEvent> {
        if self.events.is_empty() {
            return None;
        }
        Some(self.events.remove(0))
    }

    /// 送信待ちのデータを送信する
    ///
    /// 送信待ちのストリームデータと、ACK などの制御フレームを書き出す。
    /// フロー制御や輻輳制御で進まなくなった時点で戻る。
    ///
    /// # Errors
    ///
    /// ngtcp2 が回復不能なエラーを返した場合にエラーを返す。ソケットの送信
    /// エラーは接続エラーではないためログのみ出す。
    pub async fn flush(&mut self) -> Result<()> {
        let ts = timestamp();
        let packets = write_packets(&mut self.conn, &mut self.pending, &mut self.send_buf, ts)?;
        // 現在の経路を送信先として取り込む。サーバーの優先アドレスへ移る場合、
        // ngtcp2 は経路の検証に成功した時点で現在の経路を切り替える
        // (RFC 9000 Section 9.6)。送信先が決まる前の経路検証では、この値は
        // 検証前のアドレスのままになる
        if let Some(path) = self.conn.get_path() {
            self.remote_addr = path.remote;
        }
        send_packets(&self.socket, &packets).await;
        self.qlog.write(&mut self.conn);
        Ok(())
    }

    /// イベントを 1 つ待つ
    ///
    /// ソケット受信と ngtcp2 のタイマーのうち、先に到達した方を処理する。
    ///
    /// # Errors
    ///
    /// - [`Error::ConnectionClosed`][]: 接続が既に閉じている
    /// - 接続が回復不能なエラーで終了した場合はそのエラー
    pub async fn recv_event(&mut self) -> Result<ConnectionEvent> {
        if let Some(event) = self.poll_event() {
            return Ok(event);
        }
        if self.is_closed() {
            // 終了イベントをまだ配信していれば先に返す。
            // 例えば Stateless Reset は受信した直後に draining へ移行するため、
            // ここで イベントを積まないと ConnectionClosed が配信されない。
            self.push_connection_closed();
            if let Some(event) = self.poll_event() {
                return Ok(event);
            }
            return Err(Error::ConnectionClosed);
        }

        loop {
            if let Some(event) = self.poll_event() {
                return Ok(event);
            }

            // 接続の終了を送信より先に判定する。
            //
            // draining 状態では ngtcp2_conn_write_pkt が NGTCP2_ERR_DRAINING を
            // 返すため、先に flush すると終了イベントを通知できない。
            if self.conn.is_in_closing_period() || self.conn.is_in_draining_period() {
                self.push_connection_closed();
                if let Some(event) = self.poll_event() {
                    return Ok(event);
                }
                return Err(Error::ConnectionClosed);
            }

            self.flush().await?;
            // 送信側でもコールバックが発生する (MAX_STREAMS の送信など)
            self.drain_events();

            if let Some(event) = self.poll_event() {
                return Ok(event);
            }

            // ngtcp2 のタイマーを待ち時間に変換する
            let now = timestamp();
            let expiry = self.conn.get_expiry();
            let timer_duration = if expiry > now {
                Duration::from_nanos(expiry - now)
            } else {
                // 期限を過ぎているため即座に処理する
                Duration::from_millis(1)
            };

            tokio::select! {
                result = self.socket.recv_from(&mut self.recv_buf) => {
                    match result {
                        Ok((len, from, ecn)) => {
                            // 送信元アドレスでは絞らない。接続の相手が別の
                            // アドレスから送ってくる場合 (経路の変更や優先
                            // アドレスへの移行) があり、受理するかどうかは
                            // ngtcp2 が経路の検証で決める
                            // (RFC 9000 Section 9.3 / 9.6)。復号できない
                            // パケットはここで破棄される。
                            let ts = timestamp();
                            let data = self.recv_buf[..len].to_vec();
                            self.handle_packet(from, &data, ts, ecn);
                        }
                        Err(e) => {
                            return Err(Error::Internal(format!("recv error: {e}")));
                        }
                    }
                }
                _ = tokio::time::sleep(timer_duration) => {
                    let ts = timestamp();
                    // handle_expiry の負エラーはパケット破棄指示と接続終了が
                    // ほとんどで、どちらも次のループで扱う
                    let _ = self.conn.handle_expiry(ts);
                    // タイマー処理でもコールバックが発生する (再送タイムアウトによる
                    // ストリームクローズなど)
                    self.drain_events();
                }
            }
        }
    }

    /// sans-IO 層で発生したイベントを取り込んで変換する
    ///
    /// ngtcp2 のコールバックは `read_pkt` / `write_pkt` / `handle_expiry` の
    /// 内部から同期的に呼ばれる。エラーが返った場合でもコールバックは
    /// 呼ばれているため、成否に関わらず取り出す。
    fn drain_events(&mut self) {
        while let Some(event) = self.conn.poll_event() {
            // 経路の検証に成功したら、以後はその経路を使う
            if let shiguredo_ngtcp2::ConnectionEvent::PathValidated {
                path,
                success: true,
            } = &event
            {
                self.remote_addr = path.remote;
            }
            self.events.push(event.into());
        }
    }

    /// 受信した UDP ペイロードを処理する
    fn handle_packet(&mut self, from: SocketAddr, data: &[u8], ts: u64, ecn: u8) {
        // 受信した ECN コードポイントをそのまま渡す。ngtcp2 はこれを使って
        // ECN の検証と ACK_ECN の送信を行う (RFC 9000 Section 13.4.2)
        let info = PacketInfo { ecn };
        // 経路には実際に受信したアドレスを使う。ピアが別のアドレスへ移った
        // 場合、ngtcp2 はこの値を見て経路の変更を検出する
        // (RFC 9000 Section 9.3)
        let path = PathInfo {
            local: self.local_addr,
            remote: from,
        };
        let result = self.conn.read_pkt(&path, &info, data, ts);

        self.drain_events();

        if let Err(e) = result
            && matches!(e.classify_connection_error(), ConnectionErrorKind::Internal)
            && !matches!(e, Error::StreamDataBlocked(_) | Error::StreamShutWr(_))
        {
            // 実装側の問題。プロトコル違反ではないため CONNECTION_CLOSE は
            // 送らず、接続を破棄する
            self.push_connection_closed();
        }
    }

    /// 接続終了イベントを積む (一度だけ)
    fn push_connection_closed(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;

        let err = self.conn.get_connection_error();
        let kind = if err.has_error {
            if err.is_application {
                ConnectionErrorKind::ApplicationClose
            } else {
                ConnectionErrorKind::TransportClose
            }
        } else {
            ConnectionErrorKind::Terminal
        };

        self.events.push(ConnectionEvent::ConnectionClosed {
            error_code: err.error_code,
            reason: err.reason,
            kind,
        });
    }

    /// ストリームのフロー制御クレジットを進める (RFC 9000 Section 19.9)
    ///
    /// [`ConnectionEvent::StreamData`] で受け取ったデータを処理し終えたら、
    /// `consumed` にそのバイト数を渡す。戻さない限りピアは次のデータを送れない。
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn extend_max_stream_offset(&mut self, stream_id: StreamId, consumed: u64) -> Result<()> {
        self.conn.extend_max_stream_offset(stream_id, consumed)?;
        self.conn.extend_max_offset(consumed);
        Ok(())
    }

    /// ピアが開ける双方向ストリーム数の上限を `n` 増やす (RFC 9000 Section 19.11)
    ///
    /// MAX_STREAMS フレームを送る。ngtcp2 は上限を自動では増やさないため、
    /// ピアのストリームを処理し終えたら呼ぶこと。呼ばない限りピアは
    /// `initial_max_streams_bidi` の上限に達した後に新しいストリームを開けず、
    /// [`ClientConnection::open_bidi_stream`] もエラーになる。
    ///
    /// 次の [`ClientConnection::flush`] / [`ClientConnection::recv_event`] で送信される。
    pub fn extend_max_streams_bidi(&mut self, n: usize) {
        self.conn.extend_max_streams_bidi(n);
    }

    /// ピアが開ける単方向ストリーム数の上限を `n` 増やす (RFC 9000 Section 19.11)
    ///
    /// [`ClientConnection::extend_max_streams_bidi`] の単方向版。
    pub fn extend_max_streams_uni(&mut self, n: usize) {
        self.conn.extend_max_streams_uni(n);
    }

    /// ストリームの送信側をエラーコード付きで中断する (RFC 9000 Section 19.4)
    ///
    /// RESET_STREAM を送り、まだ送っていないデータを破棄する。ピア側には
    /// [`ConnectionEvent::StreamReset`] が届く。
    ///
    /// 送信側を**正常に**終端する (FIN を送る) 場合は
    /// [`ClientConnection::write_stream`] に `fin = true` を渡すこと。
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn reset_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        self.pending.remove(stream_id);
        self.conn.shutdown_stream_write(stream_id, error_code)
    }

    /// ストリームの送信側を中断しつつ、送信済みのデータの配信を保証する
    /// (draft-ietf-quic-reliable-stream-reset)
    ///
    /// [`ClientConnection::reset_stream`] との違いは、まだ ACK をもらっていない
    /// 送信中のデータを破棄せず、リセットの時点までに送ったデータを届けてから
    /// 送信側を閉じるところにある。ピアは RESET_STREAM ではなく RESET_STREAM_AT を
    /// 受け取り、リセットより前に送られたデータを欠落なく受け取れる。
    ///
    /// この保証が働くのはピアが `reset_stream_at` を通知している場合だけである
    /// ([`ClientConnection::supports_reset_stream_at`] で確認できる)。通知して
    /// いないピアに対しては RESET_STREAM が送られ、未送信のデータは破棄される
    /// ([`ClientConnection::reset_stream`] と同じ挙動)。
    ///
    /// [`ClientConnection::write_stream`] で送信待ちに積んだまま送っていない
    /// データは保証の対象外であり、[`ClientConnection::reset_stream`] と同様に
    /// 破棄される。保証の対象に含める場合は、事前に
    /// [`ClientConnection::flush`] を呼んで送信しておくこと。送信待ちが残って
    /// いるかどうかは [`ClientConnection::has_pending_data`] で確認できる。
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn reset_stream_reliable(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        self.pending.remove(stream_id);
        self.conn
            .shutdown_stream_write_reliable(stream_id, error_code)
    }

    /// ストリームの受信側をエラーコード付きで中断する (RFC 9000 Section 19.5)
    ///
    /// STOP_SENDING を送り、ピアからの以降のデータを受け取らない。ピア側には
    /// [`ConnectionEvent::StreamStopSending`] が届き、ngtcp2 が自動的に
    /// RESET_STREAM を送り返す。
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn stop_sending(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        self.conn.shutdown_stream_read(stream_id, error_code)
    }

    /// ストリームの送受信両方向をエラーコード付きで中断する
    /// (RFC 9000 Section 19.4 / 19.5)
    ///
    /// RESET_STREAM と STOP_SENDING を送る。
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn close_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        self.pending.remove(stream_id);
        self.conn.shutdown_stream(stream_id, error_code)
    }

    /// DATAGRAM を送信する (RFC 9221)
    ///
    /// # Errors
    ///
    /// - ピアが DATAGRAM をサポートしていない場合は `NGTCP2_ERR_INVALID_STATE`
    /// - `data` が [`DatagramConfig::max_tx_datagram_size`] を超える場合は
    ///   [`Error::InvalidArgument`]
    pub async fn send_datagram(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.datagram.max_tx_datagram_size {
            return Err(Error::InvalidArgument(format!(
                "datagram size {} exceeds max_tx_datagram_size {}",
                data.len(),
                self.datagram.max_tx_datagram_size
            )));
        }

        let ts = timestamp();
        let (written, accepted, path, info) =
            self.conn.write_datagram(&mut self.send_buf, data, ts)?;
        if !accepted {
            // 輻輳制御などで送れなかった。DATAGRAM は再送しない (RFC 9221 Section 3)
            return Ok(());
        }

        let mut packets = Vec::new();
        if written > 0 {
            packets.push(OutgoingPacket::from_written(
                self.send_buf[..written].to_vec(),
                path,
                info.ecn,
            )?);
        } else {
            packets.extend(write_control_packets(
                &mut self.conn,
                &mut self.send_buf,
                ts,
            )?);
        }

        send_packets(&self.socket, &packets).await;
        Ok(())
    }

    /// 新しいローカルアドレスへ接続を移す (RFC 9000 Section 9)
    ///
    /// ソケットを `local_addr` にバインドし直し、そのアドレスへ即座に
    /// マイグレーションする。経路の検証は ngtcp2 が行い、結果は
    /// [`ConnectionEvent::PathValidated`] で通知される。
    ///
    /// 「即座に」移るのは、このクライアントがソケットを 1 つしか持たず、
    /// バインドし直すと元の経路へ送れなくなるため。検証自体は行われ、
    /// 失敗した場合は `success = false` が通知される。
    ///
    /// # Errors
    ///
    /// ソケットのバインドに失敗した場合、マイグレーションできない場合
    /// (ハンドシェイクが確認される前、未使用のコネクション ID が無い、
    /// 同じローカルアドレスを指定した) にエラーを返す。
    pub async fn migrate(&mut self, local_addr: SocketAddr) -> Result<()> {
        let socket = Socket::bind(local_addr)
            .await
            .map_err(|e| Error::Internal(format!("failed to bind socket: {e}")))?;
        let bound = socket.local_addr();

        let path = PathInfo {
            local: bound,
            remote: self.remote_addr,
        };
        self.conn.initiate_immediate_migration(&path, timestamp())?;

        // 以後の送受信は新しいソケットで行う
        self.socket = socket;
        self.local_addr = bound;

        self.flush().await?;
        Ok(())
    }

    /// サーバーが NEW_TOKEN フレームで配布したトークンを取り出す
    /// (RFC 9000 Section 8.1.4)
    ///
    /// 取り出したトークンは保存しておき、次の接続で
    /// [`Settings::address_validation_token`] に設定して使う。設定すると
    /// サーバーは Retry を送らずに接続を受け入れられる。
    ///
    /// トークンはハンドシェイクの完了後に届くため、パケットを処理したあとに
    /// 呼ぶこと。一度取り出したトークンは再度返らない。
    ///
    /// [`Settings::address_validation_token`]:
    ///     shiguredo_ngtcp2::Settings::address_validation_token
    ///
    /// # Errors
    ///
    /// 接続が閉じている場合にエラーを返す。
    pub fn take_new_token(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.conn.take_new_token())
    }

    /// 鍵の更新を開始する (RFC 9001 Section 4.6.3)
    ///
    /// 次の [`ClientConnection::flush`] / [`ClientConnection::recv_event`] で
    /// 新しい 1-RTT 鍵に切り替わる。長期間生きる接続では前方秘匿性を保つために
    /// 定期的な更新が推奨される (RFC 9001 Section 6)。
    ///
    /// # Errors
    ///
    /// ハンドシェイクが完了していない場合、またはすでに鍵の更新が進行中の場合に
    /// エラーを返す。
    pub fn initiate_key_update(&mut self) -> Result<()> {
        self.conn.initiate_key_update(timestamp())
    }

    /// CONNECTION_CLOSE を送信して接続を閉じる (RFC 9000 Section 10.2)
    ///
    /// `error_code` はアプリケーションエラーコードとして送信する。
    /// 正常終了の場合は 0 を渡す。
    ///
    /// この実装は CONNECTION_CLOSE を 1 回送るだけでピアの応答を待たない。
    /// draining 期間の維持 (RFC 9000 Section 10.2 の SHOULD) は行わない。
    ///
    /// [`Drop`] は非同期処理を行えないため、正常終了時はこのメソッドを呼ぶこと。
    ///
    /// # Errors
    ///
    /// ngtcp2 が CONNECTION_CLOSE を生成できない場合にエラーを返す。
    pub async fn close(&mut self, error_code: u64, reason: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Ok(());
        }

        let ts = timestamp();
        let written =
            self.conn
                .write_connection_close_app(&mut self.send_buf, error_code, reason, ts)?;

        if written > 0 {
            // CONNECTION_CLOSE は接続の現在の経路へ送る。ngtcp2 が複数の
            // パケットを連結して返す場合があるため、パケットごとに送る
            let packets = close_packets(
                &self.send_buf[..written],
                self.local_addr,
                self.remote_addr,
                0,
            );
            send_packets(&self.socket, &packets).await;
        }

        self.closed = true;
        Ok(())
    }

    /// 接続を組み立てる (Client::connect から呼ばれる)
    fn new(
        socket: Socket,
        remote_addr: SocketAddr,
        tls_ctx: TlsContext,
        conn: Connection,
        datagram: DatagramConfig,
        qlog: QlogWriter,
    ) -> Self {
        let local_addr = socket.local_addr();
        Self {
            socket,
            local_addr,
            remote_addr,
            _tls_ctx: tls_ctx,
            conn,
            pending: PendingStreams::new(),
            events: Vec::new(),
            closed: false,
            recv_buf: vec![0u8; RECV_BUFFER_SIZE].into_boxed_slice(),
            send_buf: vec![0u8; SEND_BUFFER_SIZE].into_boxed_slice(),
            datagram,
            qlog,
        }
    }
}

/// QUIC クライアント
///
/// [`Client::connect`] はハンドシェイクが完了するまで駆動し、
/// 完了した [`ClientConnection`] を返す。
pub struct Client;

impl Client {
    /// 指定アドレスに接続してハンドシェイクを完了させる
    ///
    /// ALPN は `hq-interop`、証明書検証は無効、ハンドシェイクのタイムアウトは
    /// 10 秒。ローカルアドレスはリモートアドレスのアドレスファミリに合わせて
    /// 自動選択する。
    ///
    /// # Errors
    ///
    /// ソケットのバインドに失敗した場合、ハンドシェイクがタイムアウトした場合、
    /// ピアが接続を閉じた場合にエラーを返す。
    pub async fn connect(remote_addr: SocketAddr, server_name: &str) -> Result<ClientConnection> {
        let config = ClientConfig::new(&[DEFAULT_ALPN]).with_verify_peer(false);
        let local_addr = default_local_addr(&remote_addr);
        Self::connect_with_config(remote_addr, local_addr, server_name, &config).await
    }

    /// 設定を指定して接続する
    ///
    /// `verify_peer` が true の場合は証明書チェーンとホスト名を検証する
    /// (RFC 9001 Section 4.4)。検証に使うトラストストアはデフォルトの CA パスと
    /// `SSL_CERT_FILE` / `SSL_CERT_DIR` 環境変数、および
    /// [`ClientConfig::with_ca_cert_pem`] で追加した CA に依存する。
    ///
    /// ハンドシェイクが完了するまで待ってから返る。ハンドシェイクの完了前に
    /// データを送る場合は [`Client::connect_with_early_data`] を使う。
    ///
    /// # 検証失敗時の挙動
    ///
    /// TLS の検証に失敗した場合、ngtcp2 は接続エラーを返さずハンドシェイクが
    /// それ以上進まなくなる。そのため呼び出し側には `handshake_timeout` に
    /// よるタイムアウトとして現れる。検証失敗を早く検出したい場合は
    /// `handshake_timeout` を短く設定すること。
    ///
    /// # Errors
    ///
    /// ソケットのバインドに失敗した場合、TLS コンテキストの作成に失敗した場合、
    /// ハンドシェイクが `config.handshake_timeout` 以内に完了しない場合、
    /// ピアが接続を閉じた場合にエラーを返す。
    pub async fn connect_with_config(
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        server_name: &str,
        config: &ClientConfig,
    ) -> Result<ClientConnection> {
        Self::connect_inner(remote_addr, local_addr, server_name, config, None).await
    }

    /// 保存したセッション情報を使って 0-RTT で接続する
    /// (RFC 9001 Section 4.6)
    ///
    /// 前回の接続で [`ClientConnection::take_session_ticket`] が返した
    /// セッション情報を渡すと、ハンドシェイクの完了を待たずに戻る。
    /// 呼び出し側は [`ClientConnection::write_stream`] で 0-RTT のデータを積み、
    /// [`ClientConnection::flush`] で送れる。0-RTT を送っている最中かどうかは
    /// [`ClientConnection::is_in_early_data`] で確認できる。
    ///
    /// サーバーが 0-RTT を受理しなかった場合、ngtcp2 は 0-RTT で開いた
    /// ストリームと送信待ちのデータを破棄し、
    /// [`ConnectionEvent::EarlyDataRejected`] が届く。ハンドシェイク自体は
    /// 通常どおり完了するため、アプリケーションはストリームを開き直して
    /// データを送り直すこと。0-RTT のデータは再送されないことを前提にすること
    /// (RFC 9001 Section 4.6.2)。
    ///
    /// セッションが 0-RTT に対応していない場合 (サーバーが 0-RTT を受け入れない
    /// 設定でチケットを発行した場合など) は、ハンドシェイクの完了まで待って
    /// から返る。このとき [`ClientConnection::is_in_early_data`] は false になる。
    ///
    /// # セキュリティ上の注意
    ///
    /// 0-RTT のデータはリプレイ攻撃に対して脆弱であり (RFC 9001 Section 9.2)、
    /// 同じデータが複数回サーバーに届きうる。リプレイされて困る要求
    /// (状態を変える操作など) を 0-RTT で送ってはいけない。また、0-RTT の
    /// データは前方秘匿性を持たない (RFC 9001 Section 9.2)。
    ///
    /// # Errors
    ///
    /// [`Client::connect_with_config`] と同じ。加えて `ticket` の内容が
    /// 不正な場合にエラーを返す。
    ///
    /// [`ConnectionEvent::EarlyDataRejected`]: crate::ConnectionEvent::EarlyDataRejected
    pub async fn connect_with_early_data(
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        server_name: &str,
        config: &ClientConfig,
        ticket: &SessionTicket,
    ) -> Result<ClientConnection> {
        Self::connect_inner(remote_addr, local_addr, server_name, config, Some(ticket)).await
    }

    /// 接続を作成してハンドシェイクを進める
    ///
    /// `ticket` がある場合は 0-RTT を送れる状態 (またはハンドシェイクが完了した
    /// 状態) になった時点で、無い場合はハンドシェイクが完了した時点で返る。
    async fn connect_inner(
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        server_name: &str,
        config: &ClientConfig,
        ticket: Option<&SessionTicket>,
    ) -> Result<ClientConnection> {
        let alpn = config.alpn_refs();
        let mut tls_ctx = TlsContext::new_client_with_options(&alpn, config.verify_peer)?;
        // 設定された CA 証明書をトラストストアに追加する
        for pem in &config.ca_cert_pem {
            tls_ctx.add_ca_cert_pem(pem)?;
        }
        let tls_session = tls_ctx.create_session()?;

        let socket = Socket::bind(local_addr)
            .await
            .map_err(|e| Error::Internal(format!("failed to bind socket: {e}")))?;
        let bound_local = socket.local_addr();

        let params = config.effective_transport_params();

        let dcid = ConnectionId::random(16)
            .ok_or_else(|| Error::Internal("failed to generate dcid".to_string()))?;
        let scid = ConnectionId::random(16)
            .ok_or_else(|| Error::Internal("failed to generate scid".to_string()))?;

        let ts = timestamp();
        // 接続を作成する時刻で initial_ts を上書きする
        let mut settings = config.settings.clone();
        settings.initial_ts = ts;
        // qlog の出力先が指定されていれば有効にする
        settings.qlog = config.qlog_dir.is_some();

        let conn = match ticket {
            Some(ticket) => Connection::client_new_with_0rtt(
                &dcid,
                &scid,
                bound_local,
                remote_addr,
                config.quic_version,
                server_name,
                tls_session,
                &params,
                &settings,
                ticket,
            )?,
            None => Connection::client_new(
                &dcid,
                &scid,
                bound_local,
                remote_addr,
                config.quic_version,
                server_name,
                tls_session,
                &params,
                &settings,
            )?,
        };

        let qlog = match &config.qlog_dir {
            Some(dir) => QlogWriter::new(dir, &file_name("client-", &scid)),
            None => QlogWriter::disabled(),
        };
        let mut client =
            ClientConnection::new(socket, remote_addr, tls_ctx, conn, config.datagram, qlog);

        // ハンドシェイクを進める。0-RTT を送れるようになった時点、または
        // ハンドシェイクが完了した時点で返る。
        let deadline = tokio::time::Instant::now() + config.handshake_timeout;
        loop {
            client.flush().await?;

            if client.is_in_early_data() || client.is_handshake_completed() {
                return Ok(client);
            }
            if client.is_closed() {
                return Err(Error::ConnectionClosed);
            }

            let now = timestamp();
            let expiry = client.conn.get_expiry();
            let timer_duration = if expiry > now {
                Duration::from_nanos(expiry - now)
            } else {
                Duration::from_millis(1)
            };

            tokio::select! {
                result = client.socket.recv_from(&mut client.recv_buf) => {
                    match result {
                        Ok((len, from, ecn)) => {
                            // ハンドシェイク中も送信元アドレスでは絞らない。
                            // 受理の可否は ngtcp2 が復号と経路の検証で決める
                            let ts = timestamp();
                            let data = client.recv_buf[..len].to_vec();
                            client.handle_packet(from, &data, ts, ecn);
                        }
                        Err(e) => {
                            return Err(Error::Internal(format!("recv error: {e}")));
                        }
                    }
                }
                _ = tokio::time::sleep(timer_duration) => {
                    let ts = timestamp();
                    let _ = client.conn.handle_expiry(ts);
                    // タイマー処理でもコールバックが発生する (0-RTT の拒否など)
                    client.drain_events();
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(Error::Internal("handshake timeout".to_string()));
                }
            }
        }
    }
}

/// パケットを送信する
///
/// 送信先はパケットごとに決まる。接続のマイグレーション中は経路検証の
/// パケットだけ別のアドレスへ送るため (RFC 9000 Section 9.3)。
///
/// 送信エラーは接続エラーではない (ICMP 到達不能などで発生する) ため、
/// ログのみ出す。パケットは失われ、QUIC の再送に任せる。
async fn send_packets(socket: &Socket, packets: &[OutgoingPacket]) {
    for pkt in packets {
        if let Err(e) = socket.send_to(&pkt.data, pkt.remote, pkt.ecn).await {
            eprintln!("[shiguredo_ngtcp2_tokio] send error: {e}");
        }
    }
}

/// リモートアドレスのアドレスファミリに合わせた既定のローカルアドレスを返す
fn default_local_addr(remote_addr: &SocketAddr) -> SocketAddr {
    if remote_addr.is_ipv4() {
        "0.0.0.0:0"
            .parse()
            .expect("literal IPv4 bind address is valid")
    } else {
        "[::]:0"
            .parse()
            .expect("literal IPv6 bind address is valid")
    }
}
