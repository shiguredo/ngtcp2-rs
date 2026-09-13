//! tokio-quiche で動かすドライバ
//!
//! quiche 側を tokio 統合 (tokio-quiche) 経由で動かす。通常のハンドシェイクと
//! ストリームの往復、Retry の処理、サーバーとしての接続の受け入れ
//! (0-RTT の受理と、ピアのマイグレーションの受理を含む) を担当する。
//!
//! tokio-quiche では表現できない 0-RTT の送信とマイグレーションは
//! [`crate::raw_quiche`] が担当する。
//!
//! quiche は BoringSSL を静的リンクするため、このモジュールもテストとは
//! 別プロセスで動かす。

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use boring::ssl::SslContextBuilder;
use boring::ssl::SslMethod;
use boring::ssl::SslVerifyMode;
use tokio::sync::oneshot;
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicResult;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::quic::HandshakeInfo;
use tokio_quiche::quic::QuicheConnection;
use tokio_quiche::quiche;
use tokio_quiche::settings::CertificateKind;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::socket::Socket;
use tokio_stream::StreamExt;

/// quiche が送受信する 1 データグラムの最大サイズ (バイト)
const MAX_DATAGRAM_SIZE: usize = 1350;

/// quiche 側の待ち時間の上限
const QUICHE_TIMEOUT: Duration = Duration::from_secs(20);

/// 相互運用に使う ALPN
const ALPN: &[u8] = b"hq-interop";

/// 相互運用テスト用の共通設定を作る
///
/// ALPN とフロー制御の値はテストで使うデータ量より十分大きく取り、
/// フロー制御で止まらないようにする。
fn base_settings() -> QuicSettings {
    let mut settings = QuicSettings::default();
    settings.alpn = vec![ALPN.to_vec()];
    settings.max_idle_timeout = Some(Duration::from_secs(2));
    settings.max_recv_udp_payload_size = MAX_DATAGRAM_SIZE;
    settings.max_send_udp_payload_size = MAX_DATAGRAM_SIZE;
    settings.initial_max_data = 10_000_000;
    settings.initial_max_stream_data_bidi_local = 1_000_000;
    settings.initial_max_stream_data_bidi_remote = 1_000_000;
    settings.initial_max_stream_data_uni = 1_000_000;
    settings.initial_max_streams_bidi = 100;
    settings.initial_max_streams_uni = 100;
    // サーバーのアドレス検証 (Retry) はここでは使わない。我々のサーバーが
    // Retry を返す側の検証は interop テストで別に行っている
    settings.disable_client_ip_validation = true;
    settings
}

/// クライアントで CA 証明書を読み込むためのフック
///
/// tokio-quiche の設定には CA 証明書を指定する項目が無いため、BoringSSL の
/// SSL_CTX を自前で作ってトラストアンカーを読み込む。読み込む証明書は
/// [`TlsCertificatePaths::cert`] で渡す。
struct ClientCaHook;

impl ConnectionHook for ClientCaHook {
    fn create_custom_ssl_context_builder(
        &self,
        settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        let mut builder = SslContextBuilder::new(SslMethod::tls_client()).ok()?;
        builder.set_ca_file(settings.cert).ok()?;
        builder.set_verify(SslVerifyMode::PEER);
        Some(builder)
    }
}

/// クライアントのアプリケーション
///
/// ハンドシェイクが完了したらストリームを 1 つ開いてデータを送り、エコーを
/// 読み切ったら接続を閉じる。結果は [`oneshot`] で呼び出し元へ渡す。
struct EchoClientApp {
    /// 送るデータ
    payload: Vec<u8>,
    /// 送信済みかどうか
    sent: bool,
    /// 受け取ったデータ
    received: Vec<u8>,
    /// エコーを読み切ったかどうか
    fin: bool,
    /// アプリケーションの処理が終わったかどうか
    done: bool,
    /// 結果を渡すチャネル
    outcome: Option<oneshot::Sender<Result<Vec<u8>, String>>>,
    /// ワーカーが送信パケットを書き込むバッファ
    buffer: Vec<u8>,
}

impl EchoClientApp {
    /// アプリケーションを作る
    fn new(payload: Vec<u8>, outcome: oneshot::Sender<Result<Vec<u8>, String>>) -> Self {
        Self {
            payload,
            sent: false,
            received: Vec::new(),
            fin: false,
            done: false,
            outcome: Some(outcome),
            buffer: vec![0u8; MAX_DATAGRAM_SIZE],
        }
    }

    /// ハンドシェイクが完了していればリクエストを送る
    fn send_request(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        if self.sent || !qconn.is_established() {
            return Ok(());
        }
        qconn.stream_send(0, &self.payload, true)?;
        self.sent = true;
        Ok(())
    }

    /// 結果を呼び出し元へ渡す
    fn finish(&mut self, result: Result<Vec<u8>, String>) {
        if let Some(outcome) = self.outcome.take() {
            let _ = outcome.send(result);
        }
    }
}

impl ApplicationOverQuic for EchoClientApp {
    fn on_conn_established(
        &mut self,
        qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.send_request(qconn)
    }

    fn should_act(&self) -> bool {
        !self.done
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    fn wait_for_data(
        &mut self,
        _qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send {
        // アプリケーション側からワーカーを起こす必要はないため、
        // 完了しない future を返す
        std::future::pending()
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        for stream_id in qconn.readable() {
            loop {
                match qconn.stream_recv(stream_id, &mut buf) {
                    Ok((read, fin)) => {
                        self.received.extend_from_slice(&buf[..read]);
                        if fin {
                            self.fin = true;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }

        if self.fin && !self.done {
            self.done = true;
            // ピア (我々のサーバー) が接続の終了を観測できるよう閉じる
            let _ = qconn.close(false, 0, b"");
            let received = std::mem::take(&mut self.received);
            self.finish(Ok(received));
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.send_request(qconn)
    }

    fn on_conn_close<M: Metrics>(
        &mut self,
        _qconn: &mut QuicheConnection,
        _metrics: &M,
        result: &QuicResult<()>,
    ) {
        // エコーを読み切っていれば process_reads で結果を渡している
        if self.fin {
            return;
        }

        let message = match result {
            Ok(()) => "the connection closed before the echo arrived".to_string(),
            Err(e) => format!("the connection failed: {e}"),
        };
        self.finish(Err(message));
    }
}

/// 我々のクライアントで quiche のサーバーと接続し、データを送ってエコーを受け取る
///
/// 証明書検証は有効にしたまま、`ca_cert_path` の証明書をトラストアンカーとして
/// 読み込む。
pub async fn client_roundtrip(
    server_addr: SocketAddr,
    ca_cert_path: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut settings = base_settings();
    // 自己署名の CA 証明書を検証するため、フックで SSL_CTX を作る
    settings.verify_peer = true;
    let tls_cert = TlsCertificatePaths {
        // クライアントでは cert を CA 証明書として読み込む。
        // private_key は使わない
        cert: ca_cert_path,
        private_key: ca_cert_path,
        kind: CertificateKind::X509,
    };
    let params = ConnectionParams::new_client(
        settings,
        Some(tls_cert),
        Hooks {
            connection_hook: Some(Arc::new(ClientCaHook)),
        },
    );

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("failed to bind: {e}"))?;
    socket
        .connect(server_addr)
        .await
        .map_err(|e| format!("failed to connect the socket: {e}"))?;
    // Socket::from_udp は Socket<Tx, Rx> の関連関数のため、型を明示する
    type TokioSocket = Socket<Arc<tokio::net::UdpSocket>, Arc<tokio::net::UdpSocket>>;
    let socket = TokioSocket::from_udp(socket).map_err(|e| format!("failed to use socket: {e}"))?;

    let (outcome_tx, outcome_rx) = oneshot::channel();
    let app = EchoClientApp::new(payload.to_vec(), outcome_tx);
    tokio_quiche::quic::connect_with_config(socket, Some("localhost"), &params, app)
        .await
        .map_err(|e| format!("failed to connect: {e}"))?;

    // エコーが届くか、接続が閉じるまで待つ
    match tokio::time::timeout(QUICHE_TIMEOUT, outcome_rx).await {
        Ok(Ok(result)) => result,
        // アプリケーションが結果を渡さずに終わった
        Ok(Err(_)) => Err("the connection worker stopped without a result".to_string()),
        Err(_) => Err("timed out while waiting for the echo".to_string()),
    }
}

/// quiche のサーバーで受け入れる接続の設定
#[derive(Clone, Copy)]
pub struct ServerOptions {
    /// 0-RTT (early data) を受理する
    pub early_data: bool,
    /// ピア (クライアント) のマイグレーションを受理する
    pub migration: bool,
}

/// サーバーのアプリケーション
///
/// クライアントが FIN を送ったストリームのデータをそのまま書き戻す。エコーを
/// 返したら結果を標準出力に 1 行で書き出す。
///
/// 終了は親プロセス (テスト) が行う。tokio-quiche のワーカーはピアが
/// CONNECTION_CLOSE を送っても draining が終わるまで終了しないため、
/// 接続の終了を待ってプロセスを終わらせるとアイドルタイムアウトまで待たされる。
struct EchoServerApp {
    /// 受け入れる接続の設定
    options: ServerOptions,
    /// 受け取ったデータ
    received: Vec<u8>,
    /// 0-RTT でデータを受け取ったかどうか
    early_data_received: bool,
    /// ピアのマイグレーション用のコネクション ID を発行済みかどうか
    extra_scid_issued: bool,
    /// 結果を書き出し済みかどうか
    reported: bool,
    /// ピアが閉じたことを書き出し済みかどうか
    close_reported: bool,
    /// ワーカーが送信パケットを書き込むバッファ
    buffer: Vec<u8>,
}

impl EchoServerApp {
    /// アプリケーションを作る
    fn new(options: ServerOptions) -> Self {
        Self {
            options,
            received: Vec::new(),
            early_data_received: false,
            extra_scid_issued: false,
            reported: false,
            close_reported: false,
            buffer: vec![0u8; MAX_DATAGRAM_SIZE],
        }
    }

    /// ピアが新しい経路で使うコネクション ID を 1 つ発行する
    /// (RFC 9000 Section 9.5)
    ///
    /// ピアは新しい経路でこの ID を使う。発行しないとピアは移れない
    /// (quiche はアプリケーションが発行しない限り未使用の ID を持たない)。
    fn issue_extra_scid(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        if !self.options.migration || self.extra_scid_issued || !qconn.is_established() {
            return Ok(());
        }

        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        getrandom::fill(&mut scid).map_err(|e| format!("failed to generate scid: {e}"))?;
        let mut reset_token = [0u8; 16];
        getrandom::fill(&mut reset_token)
            .map_err(|e| format!("failed to generate reset token: {e}"))?;
        qconn.new_scid(
            &quiche::ConnectionId::from_ref(&scid),
            u128::from_be_bytes(reset_token),
            false,
        )?;
        self.extra_scid_issued = true;
        Ok(())
    }

    /// 受け取ったデータとその届き方を標準出力に 1 行で書き出す
    fn report(&mut self) {
        if self.reported {
            return;
        }
        self.reported = true;
        write_report(&format!(
            "{} bytes (early data: {})",
            self.received.len(),
            self.early_data_received
        ));
        self.received.clear();
    }

    /// ピアが接続を閉じたことを標準出力に 1 行で書き出す
    ///
    /// データを受け取った接続だけを対象にする (セッションチケットの取得だけを
    /// 行う接続では書き出さない)。
    fn report_peer_close(&mut self, qconn: &QuicheConnection) {
        if self.close_reported || !self.reported {
            return;
        }

        // ピアが CONNECTION_CLOSE を送ると接続は draining になる。quiche は
        // draining が終わるまで `is_closed()` を true にしないため、draining を
        // 「ピアが閉じた」とみなす
        if qconn.is_draining() {
            self.close_reported = true;
            write_report("peer closed");
            return;
        }

        // ピアの CONNECTION_CLOSE を受け取らないまま接続が終わった場合
        // (アイドルタイムアウトなど)。原因を切り分けられるよう別の行にする
        if qconn.is_closed() || qconn.is_timed_out() {
            self.close_reported = true;
            write_report("connection ended without a peer close");
        }
    }
}

/// 標準出力に 1 行書き出して flush する
///
/// 親プロセス (テスト) がパイプで読むため、明示的に flush する。
fn write_report(line: &str) {
    use std::io::Write;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{line}");
    let _ = handle.flush();
}

impl ApplicationOverQuic for EchoServerApp {
    fn on_conn_established(
        &mut self,
        _qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        Ok(())
    }

    fn should_act(&self) -> bool {
        // ピアが閉じたことを観測するまでアプリケーションを動かし続ける
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    fn wait_for_data(
        &mut self,
        _qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send {
        std::future::pending()
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        for stream_id in qconn.readable() {
            let mut data = Vec::new();
            let mut fin = false;
            loop {
                match qconn.stream_recv(stream_id, &mut buf) {
                    Ok((read, stream_fin)) => {
                        data.extend_from_slice(&buf[..read]);
                        if stream_fin {
                            fin = true;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            }

            if fin {
                // 0-RTT かどうかはデータを受け取った時点でしか判定できない
                if qconn.is_in_early_data() {
                    self.early_data_received = true;
                }
                self.received.extend_from_slice(&data);
                // 受け取ったデータをそのまま書き戻す
                qconn.stream_send(stream_id, &data, true)?;
                self.report();
            }
        }

        self.report_peer_close(qconn);
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.report_peer_close(qconn);
        self.issue_extra_scid(qconn)
    }
}

/// quiche のサーバーとして接続を受け入れ、受け取ったデータをエコーする
///
/// エコーするたびに結果を標準出力に 1 行で書き出す。接続は終了しないため、
/// 呼び出し元 (テスト) が結果を読んでからプロセスを終了させる。
pub async fn server_echo(
    listener: std::net::UdpSocket,
    cert_path: &str,
    key_path: &str,
    options: ServerOptions,
) -> Result<(), String> {
    let mut settings = base_settings();
    if options.early_data {
        settings.enable_early_data = true;
    }
    // 既定ではピアのマイグレーションを拒否する。テストで必要なときだけ許可する
    settings.disable_active_migration = !options.migration;
    let tls_cert = TlsCertificatePaths {
        cert: cert_path,
        private_key: key_path,
        kind: CertificateKind::X509,
    };
    let params = ConnectionParams::new_server(
        settings,
        tls_cert,
        Hooks {
            connection_hook: None,
        },
    );

    let mut stream = tokio_quiche::listen(vec![listener], params, DefaultMetrics)
        .map_err(|e| format!("failed to listen: {e}"))?
        .remove(0);

    // 接続ごとにアプリケーションを起動する
    while let Some(initial) = stream.next().await {
        // ハンドシェイクできない Initial は捨てる
        let Ok(initial) = initial else {
            continue;
        };
        let _conn = initial.start(EchoServerApp::new(options));
    }

    Err("the listener stopped".to_string())
}
