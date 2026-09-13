//! `Connection` の統合テスト
//!
//! sans-IO 層の公開 API だけを 2 つの実 UDP ソケットで駆動し、ハンドシェイク・
//! ストリーム転送・イベントの発生・接続の終了を検証する。
//!
//! tokio はソケット I/O のためにだけ使う。プロトコルの状態遷移はすべて
//! [`Connection`] の公開 API (`read_pkt` / `write_pkt` / `handle_expiry`) で
//! 駆動するため、モックやスタブは使わない。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use shiguredo_ngtcp2::{
    CongestionAlgorithm, Connection, ConnectionEvent, ConnectionId, Error, PacketInfo, PathInfo,
    QuicVersion, SessionTicket, Settings, StatelessResetSecret, TlsContext, TransportParams,
    decode_packet_version, write_stateless_reset,
};
use tokio::net::UdpSocket;

/// 接続に使う ALPN
const ALPN: &[u8] = b"hq-interop";

/// 送信バッファのサイズ
///
/// Initial パケットは 1200 バイト以上で送る必要があるため
/// (RFC 9000 Section 14.1)、それより大きい 1500 を使う。
const SEND_BUFFER_SIZE: usize = 1500;

/// 受信バッファのサイズ (UDP ペイロードの最大値)
const RECV_BUFFER_SIZE: usize = 65535;

/// 交互駆動のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// 1 回の受信待ちに使うタイムアウト
///
/// パケットが無ければ送信だけを行って次の駆動に進む。
const RECV_POLL_TIMEOUT: Duration = Duration::from_millis(2);

/// ngtcp2 に渡すタイムスタンプ (プロセス起動からのナノ秒)
///
/// ngtcp2 のタイムスタンプは単調増加であればよいため、プロセス内で共有する
/// 基準時刻からの経過時間を使う。
fn timestamp() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_nanos() as u64
}

/// テスト用の自己署名証明書 (一時ディレクトリに書き出し済み)
struct TestCert {
    temp_dir: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl TestCert {
    /// `localhost` 用の自己署名証明書を生成する
    fn generate(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!(
            "ngtcp2_conn_test_{}_{}_{}",
            label,
            std::process::id(),
            unique_id
        ));
        std::fs::create_dir_all(&temp_dir).expect("一時ディレクトリを作成できること");

        let cert_path = temp_dir.join("cert.pem");
        let key_path = temp_dir.join("key.pem");

        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("証明書パラメータ");
        let key_pair = rcgen::KeyPair::generate().expect("鍵ペアを生成できること");
        let cert = params
            .self_signed(&key_pair)
            .expect("自己署名証明書を生成できること");

        std::fs::write(&cert_path, cert.pem()).expect("証明書を書き込めること");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("秘密鍵を書き込めること");

        Self {
            temp_dir,
            cert_path,
            key_path,
        }
    }
}

impl Drop for TestCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

/// sans-IO の接続と UDP ソケットを組み合わせたエンドポイント
struct Endpoint {
    socket: UdpSocket,
    local: SocketAddr,
    remote: SocketAddr,
    /// このエンドポイントが発行した最初のコネクション ID
    ///
    /// ピアのパケットの DCID になる。Stateless Reset のトークンを
    /// 検証するテストで使う。
    scid: ConnectionId,
    conn: Connection,
    // SSL_CTX の所有権
    //
    // Connection が保持する SSL は SSL_CTX を参照するため、
    // Endpoint が生きている間は解放してはいけない。
    //
    // 0-RTT ではセッションチケットの暗号鍵が SSL_CTX ごとに作られるため、
    // チケットを発行した接続と同じ SSL_CTX を次の接続でも使う。
    _tls_ctx: Arc<TlsContext>,
    recv_buf: Vec<u8>,
    send_buf: Box<[u8]>,
}

impl Endpoint {
    /// ソケットをバインドしてローカルアドレスを確定させる
    async fn bind() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("ソケットをバインドできること");
        let addr = socket
            .local_addr()
            .expect("ローカルアドレスを取得できること");
        (socket, addr)
    }

    /// クライアントのエンドポイントを作る
    ///
    /// ソケットと TLS コンテキストは呼び出し側が用意したものを使う。
    /// `ticket` を渡すと 0-RTT を送れる状態で接続を作る。
    #[expect(clippy::too_many_arguments)]
    fn new_client(
        socket: UdpSocket,
        local: SocketAddr,
        remote: SocketAddr,
        version: QuicVersion,
        params: &TransportParams,
        settings: &Settings,
        tls_ctx: Arc<TlsContext>,
        ticket: Option<&SessionTicket>,
    ) -> Self {
        let session = tls_ctx
            .create_session()
            .expect("TLS セッションを作れること");
        let dcid = ConnectionId::random(16).expect("DCID を生成できること");
        let scid = ConnectionId::random(16).expect("SCID を生成できること");

        let conn = match ticket {
            Some(ticket) => Connection::client_new_with_0rtt(
                &dcid,
                &scid,
                local,
                remote,
                version,
                "localhost",
                session,
                params,
                settings,
                ticket,
            )
            .expect("0-RTT 付きのクライアント接続を作れること"),
            None => Connection::client_new(
                &dcid,
                &scid,
                local,
                remote,
                version,
                "localhost",
                session,
                params,
                settings,
            )
            .expect("クライアント接続を作れること"),
        };

        Self {
            socket,
            local,
            remote,
            scid,
            conn,
            _tls_ctx: tls_ctx,
            recv_buf: vec![0u8; RECV_BUFFER_SIZE],
            send_buf: vec![0u8; SEND_BUFFER_SIZE].into_boxed_slice(),
        }
    }

    /// サーバーのエンドポイントを作る
    ///
    /// `dcid` はクライアントの SCID、`original_dcid` はクライアントが最初の
    /// Initial で使った DCID (RFC 9000 Section 7.3)。
    /// ソケットと TLS コンテキストは呼び出し側が用意したものを使う。
    #[expect(clippy::too_many_arguments)]
    fn new_server(
        socket: UdpSocket,
        local: SocketAddr,
        remote: SocketAddr,
        version: QuicVersion,
        dcid: &ConnectionId,
        original_dcid: &ConnectionId,
        params: &TransportParams,
        settings: &Settings,
        tls_ctx: Arc<TlsContext>,
    ) -> Self {
        let session = tls_ctx
            .create_session()
            .expect("TLS セッションを作れること");
        let scid = ConnectionId::random(16).expect("SCID を生成できること");

        // サーバーはクライアントの最初の Initial の DCID を
        // トランスポートパラメータで通知する必要がある (RFC 9000 Section 7.3)
        let mut params = params.clone().with_original_dcid(original_dcid);

        // Stateless Reset の秘密が設定されていれば、最初の SCID に対応する
        // トークンをトランスポートパラメータで配布する (RFC 9000 Section 18.2)。
        // これがないとピアは最初の DCID に対する Stateless Reset を受理できない。
        if let Some(secret) = &settings.stateless_reset_secret
            && let Some(token) = secret.token(&scid)
        {
            params = params.with_stateless_reset_token(&token);
        }

        let conn = Connection::server_new(
            dcid, &scid, local, remote, version, session, &params, settings,
        )
        .expect("サーバー接続を作れること");

        Self {
            socket,
            local,
            remote,
            scid,
            conn,
            _tls_ctx: tls_ctx,
            recv_buf: vec![0u8; RECV_BUFFER_SIZE],
            send_buf: vec![0u8; SEND_BUFFER_SIZE].into_boxed_slice(),
        }
    }

    /// エンドポイントを 1 周駆動する
    ///
    /// 受信 → タイマー処理 → 送信の順に進める。これが sans-IO 層の
    /// 正しい使い方であり、呼び出し側がソケットとタイマーを用意する。
    async fn drive(&mut self) {
        // 受信
        if let Ok(Ok((len, from))) =
            tokio::time::timeout(RECV_POLL_TIMEOUT, self.socket.recv_from(&mut self.recv_buf)).await
            && from == self.remote
        {
            let data = self.recv_buf[..len].to_vec();
            let path = PathInfo {
                local: self.local,
                remote: self.remote,
            };
            let _ = self
                .conn
                .read_pkt(&path, &PacketInfo::default(), &data, timestamp());
        }

        // タイマー
        let now = timestamp();
        if self.conn.get_expiry() <= now {
            let _ = self.conn.handle_expiry(now);
        }

        // 送信 (書き出せなくなるまで繰り返す)
        loop {
            match self.conn.write_pkt(&mut self.send_buf, timestamp()) {
                Ok((0, _, _)) => break,
                Ok((written, _, _)) => {
                    let pkt = self.send_buf[..written].to_vec();
                    let _ = self.socket.send_to(&pkt, self.remote).await;
                }
                // CLOSING / DRAINING などは接続の終了を意味するため送信を止める
                Err(_) => break,
            }
        }
    }

    /// 未処理のイベントをすべて取り出す
    fn drain_events(&mut self) -> Vec<ConnectionEvent> {
        let mut events = Vec::new();
        while let Some(event) = self.conn.poll_event() {
            events.push(event);
        }
        events
    }
}

/// 交互駆動のタイムアウトを超えていないことを確認する
fn check_deadline(deadline: Instant, what: &str) {
    assert!(Instant::now() < deadline, "{what} がタイムアウトした");
}

/// クライアントの最初の Initial からバージョンと CID を取り出す
///
/// 解析はライブラリの [`decode_packet_version`] に任せる。テスト側で
/// ヘッダーを手書きパースすると、バージョンごとの差異を検証できないため。
fn parse_initial(data: &[u8], expected: QuicVersion) -> (ConnectionId, ConnectionId) {
    assert!(
        data.len() >= shiguredo_ngtcp2::MIN_INITIAL_DATAGRAM_SIZE,
        "Initial を含むデータグラムは 1200 バイト以上であること: {}",
        data.len()
    );

    let info = decode_packet_version(data).expect("クライアントの Initial を解析できること");
    assert_eq!(
        info.version,
        expected.as_u32(),
        "クライアントは指定したバージョンを使うこと"
    );
    assert!(info.is_initial(), "Initial パケットであること");

    (info.dcid, info.scid)
}

/// ハンドシェイクを完了させたクライアントとサーバーの組を返す
///
/// サーバーはクライアントの最初の Initial を受け取ってからでないと接続を
/// 作れない (CID とトランスポートパラメータの `original_dcid` が必要なため)。
async fn handshake_pair_with(
    cert: &TestCert,
    version: QuicVersion,
    client_params: &TransportParams,
    server_params: &TransportParams,
    client_settings: Settings,
    server_settings: Settings,
) -> (Endpoint, Endpoint) {
    // initial_ts は接続を作成する時刻で上書きする (I/O 層と同じ扱い)
    let mut client_settings = client_settings;
    client_settings.initial_ts = timestamp();
    let mut server_settings = server_settings;
    server_settings.initial_ts = timestamp();
    // 両側のソケットを先に用意してアドレスを確定させる。
    // サーバーのアドレスはクライアントの接続先になり、
    // クライアントのアドレスは Initial の受信元としてサーバーに渡る。
    let (server_socket, server_addr) = Endpoint::bind().await;
    let (client_socket, client_addr) = Endpoint::bind().await;

    let mut client = Endpoint::new_client(
        client_socket,
        client_addr,
        server_addr,
        version,
        client_params,
        &client_settings,
        Arc::new(
            TlsContext::new_client_with_options(&[ALPN], false)
                .expect("TLS コンテキストを作れること"),
        ),
        None,
    );

    // クライアントの Initial を送出する
    client.drive().await;

    // サーバーはクライアントの Initial を受け取ってから接続を作る
    let mut initial_buf = vec![0u8; RECV_BUFFER_SIZE];
    let (len, from) = server_socket
        .recv_from(&mut initial_buf)
        .await
        .expect("クライアントの Initial を受信できること");
    assert_eq!(from, client_addr, "クライアントのアドレスが一致すること");
    let (client_initial_dcid, client_scid) = parse_initial(&initial_buf[..len], version);

    let mut server = Endpoint::new_server(
        server_socket,
        server_addr,
        client_addr,
        version,
        &client_scid,
        &client_initial_dcid,
        server_params,
        &server_settings,
        Arc::new(
            TlsContext::new_server(&cert.cert_path, &cert.key_path, &[ALPN])
                .expect("サーバーの TLS コンテキストを作れること"),
        ),
    );

    // 受信済みの Initial をサーバーの接続に流し込む
    let initial = initial_buf[..len].to_vec();
    let path = PathInfo {
        local: server.local,
        remote: server.remote,
    };
    server
        .conn
        .read_pkt(&path, &PacketInfo::default(), &initial, timestamp())
        .expect("サーバーが Initial を処理できること");

    // 両側がハンドシェイクを完了するまで駆動する
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !(client.conn.is_handshake_completed() && server.conn.is_handshake_completed()) {
        client.drive().await;
        server.drive().await;
        check_deadline(deadline, "ハンドシェイク");
    }

    (client, server)
}

/// 指定したバージョンでハンドシェイクを完了させた組を返す
async fn handshake_pair_with_version(
    cert: &TestCert,
    version: QuicVersion,
    client_params: &TransportParams,
    server_params: &TransportParams,
) -> (Endpoint, Endpoint) {
    handshake_pair_with(
        cert,
        version,
        client_params,
        server_params,
        Settings::new(0),
        Settings::new(0),
    )
    .await
}

/// QUIC v1 と既定の設定でハンドシェイクを完了させた組を返す
async fn handshake_pair(
    cert: &TestCert,
    client_params: &TransportParams,
    server_params: &TransportParams,
) -> (Endpoint, Endpoint) {
    handshake_pair_with_version(cert, QuicVersion::V1, client_params, server_params).await
}

/// 既定のトランスポートパラメータでハンドシェイクが完了すること
///
/// sans-IO 層の `client_new` / `server_new` / `read_pkt` / `write_pkt` /
/// `handle_expiry` / `is_handshake_completed` をひと通り使う。
#[tokio::test]
async fn test_handshake_completes() {
    let cert = TestCert::generate("conn_handshake");
    let params = TransportParams::new();

    let (mut client, mut server) = handshake_pair(&cert, &params, &params).await;

    // イベントがキューに溜まっていること
    assert!(
        client.conn.has_event(),
        "ハンドシェイク後に未処理のイベントがあること"
    );

    // 両側に HandshakeCompleted イベントが発生すること
    assert!(
        client
            .drain_events()
            .iter()
            .any(|event| matches!(event, ConnectionEvent::HandshakeCompleted)),
        "クライアントに HandshakeCompleted が発生すること"
    );
    assert!(
        server
            .drain_events()
            .iter()
            .any(|event| matches!(event, ConnectionEvent::HandshakeCompleted)),
        "サーバーに HandshakeCompleted が発生すること"
    );

    // 取り出したあとは空になること
    assert!(
        !client.conn.has_event(),
        "drain 後に未処理のイベントが無いこと"
    );

    // closing / draining に入っていないこと
    assert!(
        !client.conn.is_in_closing_period() && !client.conn.is_in_draining_period(),
        "ハンドシェイク後に接続が終了していないこと"
    );
}

/// ハンドシェイク後に両側で ALPN が交渉されること (RFC 7301 Section 3)
#[tokio::test]
async fn test_alpn_negotiated_after_handshake() {
    let cert = TestCert::generate("conn_alpn");
    let params = TransportParams::new();

    let (client, server) = handshake_pair(&cert, &params, &params).await;

    assert_eq!(
        client.conn.selected_alpn_protocol().as_deref(),
        Some(ALPN),
        "クライアントが交渉された ALPN を取得できること"
    );
    assert_eq!(
        server.conn.selected_alpn_protocol().as_deref(),
        Some(ALPN),
        "サーバーが交渉された ALPN を取得できること"
    );
}

/// 設定したトランスポートパラメータがピアにそのまま伝わること
///
/// `TransportParams` の効果はピアが受け取る値でしか観測できない
/// (`as_raw` は `pub(crate)`)。そのため特徴的な値を設定してハンドシェイクし、
/// ピアの [`shiguredo_ngtcp2::RemoteTransportParams`] と突き合わせる。
#[tokio::test]
async fn test_transport_params_reach_peer() {
    let cert = TestCert::generate("conn_transport_params");

    // サーバー側だけ特徴的な値を設定する
    let server_params = TransportParams::new()
        .with_initial_max_data(1_234_567)
        .with_initial_max_stream_data_bidi_local(22_222)
        .with_initial_max_stream_data_bidi_remote(33_333)
        .with_initial_max_stream_data_uni(44_444)
        .with_max_streams_bidi(7)
        .with_max_streams_uni(9)
        .with_max_idle_timeout(Duration::from_secs(45))
        .with_max_udp_payload_size(1350)
        .with_active_connection_id_limit(4)
        .with_ack_delay_exponent(5)
        .with_max_ack_delay(Duration::from_millis(10))
        .with_datagram(1234)
        .with_disable_active_migration(true)
        .with_grease_quic_bit(true)
        .with_reset_stream_at(true);

    let (client, server) = handshake_pair(&cert, &TransportParams::new(), &server_params).await;

    // クライアントから見たサーバーのパラメータ
    let remote = client
        .conn
        .remote_transport_params()
        .expect("ピアのパラメータを取得できること");
    assert_eq!(remote.initial_max_data, 1_234_567, "initial_max_data");
    assert_eq!(
        remote.initial_max_stream_data_bidi_local, 22_222,
        "bidi_local"
    );
    assert_eq!(
        remote.initial_max_stream_data_bidi_remote, 33_333,
        "bidi_remote"
    );
    assert_eq!(
        remote.initial_max_stream_data_uni, 44_444,
        "単方向ストリームの上限も伝わることを確認する"
    );
    assert_eq!(remote.initial_max_streams_bidi, 7, "max_streams_bidi");
    assert_eq!(remote.initial_max_streams_uni, 9, "max_streams_uni");
    assert_eq!(
        remote.max_idle_timeout,
        Duration::from_secs(45),
        "max_idle_timeout"
    );
    assert_eq!(remote.max_udp_payload_size, 1350, "max_udp_payload_size");
    assert_eq!(
        remote.active_connection_id_limit, 4,
        "active_connection_id_limit"
    );
    assert_eq!(remote.ack_delay_exponent, 5, "ack_delay_exponent");
    assert_eq!(
        remote.max_ack_delay,
        Duration::from_millis(10),
        "max_ack_delay"
    );
    assert_eq!(
        remote.max_datagram_frame_size, 1234,
        "max_datagram_frame_size"
    );
    assert!(
        remote.disable_active_migration,
        "disable_active_migration が伝わること"
    );
    assert!(remote.grease_quic_bit, "grease_quic_bit が伝わること");
    assert!(
        remote.reset_stream_at,
        "reset_stream_at が伝わること (draft-ietf-quic-reliable-stream-reset)"
    );

    // DATAGRAM の可否もこの値から決まること (RFC 9221 Section 3)
    assert!(
        client.conn.can_send_datagram(),
        "ピアが DATAGRAM を通知していれば送信できること"
    );

    // サーバーから見たクライアントのパラメータは既定値であること
    let client_remote = server
        .conn
        .remote_transport_params()
        .expect("ピアのパラメータを取得できること");
    assert_eq!(
        client_remote.initial_max_streams_bidi, 100,
        "クライアントの既定の max_streams_bidi"
    );
    assert_eq!(
        client_remote.initial_max_data,
        10 * 1024 * 1024,
        "クライアントの既定の initial_max_data"
    );
    assert!(
        !client_remote.grease_quic_bit,
        "クライアントは grease_quic_bit を設定していないこと"
    );
}

/// ハンドシェイクを行わないクライアント接続を作る
///
/// TLS コンテキストも一緒に返す。接続が保持する SSL は SSL_CTX を参照するため、
/// 呼び出し側は両方を同じスコープで生かしておく必要がある。
fn new_idle_client(settings: &Settings) -> (Connection, TlsContext) {
    let tls_ctx =
        TlsContext::new_client_with_options(&[ALPN], false).expect("TLS コンテキストを作れること");
    let session = tls_ctx
        .create_session()
        .expect("TLS セッションを作れること");
    let dcid = ConnectionId::random(16).expect("DCID を生成できること");
    let scid = ConnectionId::random(16).expect("SCID を生成できること");
    let local: SocketAddr = "127.0.0.1:1".parse().expect("リテラルアドレスは有効");
    let remote: SocketAddr = "127.0.0.1:2".parse().expect("リテラルアドレスは有効");

    let conn = Connection::client_new(
        &dcid,
        &scid,
        local,
        remote,
        QuicVersion::V1,
        "localhost",
        session,
        &TransportParams::new(),
        settings,
    )
    .expect("クライアント接続を作れること");

    (conn, tls_ctx)
}

/// original_dcid が無いサーバー接続を作れないこと
///
/// サーバーは original_dcid を通知しなければならない (RFC 9000 Section 7.3)。
/// 守られていない状態で接続を作ると ngtcp2 が assert でプロセスを abort する
/// ため、ライブラリ側でエラーとして弾く。
#[test]
fn test_server_new_without_original_dcid() {
    let cert = TestCert::generate("conn_server_without_original_dcid");
    let tls_ctx = TlsContext::new_server(&cert.cert_path, &cert.key_path, &[ALPN])
        .expect("TLS コンテキストを作れること");
    let session = tls_ctx
        .create_session()
        .expect("TLS セッションを作れること");
    let dcid = ConnectionId::random(16).expect("DCID を生成できること");
    let scid = ConnectionId::random(16).expect("SCID を生成できること");
    let local: SocketAddr = "127.0.0.1:50000".parse().expect("リテラルアドレスは有効");
    let remote: SocketAddr = "127.0.0.1:4433".parse().expect("リテラルアドレスは有効");

    let result = Connection::server_new(
        &dcid,
        &scid,
        local,
        remote,
        QuicVersion::V1,
        session,
        &TransportParams::new(),
        &Settings::new(0),
    );

    assert!(
        matches!(result, Err(Error::InvalidArgument(_))),
        "original_dcid が無いサーバー接続はエラーになること"
    );
}

/// original_dcid を設定したクライアント接続を作れないこと
///
/// クライアントは original_dcid を通知してはならない (RFC 9000 Section 7.3)。
/// 守られていない状態で接続を作ると ngtcp2 が assert でプロセスを abort する
/// ため、ライブラリ側でエラーとして弾く。
#[test]
fn test_client_new_with_original_dcid() {
    let tls_ctx =
        TlsContext::new_client_with_options(&[ALPN], false).expect("TLS コンテキストを作れること");
    let session = tls_ctx
        .create_session()
        .expect("TLS セッションを作れること");
    let dcid = ConnectionId::random(16).expect("DCID を生成できること");
    let scid = ConnectionId::random(16).expect("SCID を生成できること");
    let local: SocketAddr = "127.0.0.1:50000".parse().expect("リテラルアドレスは有効");
    let remote: SocketAddr = "127.0.0.1:4433".parse().expect("リテラルアドレスは有効");
    let params = TransportParams::new().with_original_dcid(&dcid);

    let result = Connection::client_new(
        &dcid,
        &scid,
        local,
        remote,
        QuicVersion::V1,
        "localhost",
        session,
        &params,
        &Settings::new(0),
    );

    assert!(
        matches!(result, Err(Error::InvalidArgument(_))),
        "original_dcid を設定したクライアント接続はエラーになること"
    );
}

/// トランスポートパラメータが届く前はピアのパラメータを取得できないこと
#[tokio::test]
async fn test_remote_transport_params_before_handshake() {
    let (conn, _tls_ctx) = new_idle_client(&Settings::new(0));

    assert_eq!(
        conn.remote_transport_params(),
        None,
        "ハンドシェイク前はピアのパラメータが無いこと"
    );
    assert!(
        !conn.can_send_datagram(),
        "パラメータが無ければ DATAGRAM を送れないこと"
    );
}

/// パケットを交換する前の統計が初期値であること
#[tokio::test]
async fn test_stats_before_handshake() {
    let (conn, _tls_ctx) = new_idle_client(&Settings::new(0));
    let stats = conn.stats();

    assert_eq!(stats.packets_sent, 0, "まだ何も送信していないこと");
    assert_eq!(stats.packets_received, 0, "まだ何も受信していないこと");
    assert_eq!(stats.packets_lost, 0, "喪失は無いこと");
    assert_eq!(
        stats.min_rtt, None,
        "RTT を観測するまでは最小 RTT が無いこと"
    );
    // RFC 9002 Section 3: 観測前は初期 RTT を使う
    assert_eq!(
        stats.smoothed_rtt,
        shiguredo_ngtcp2::DEFAULT_INITIAL_RTT,
        "平滑化 RTT は初期値であること"
    );
    assert_eq!(
        stats.rttvar,
        shiguredo_ngtcp2::DEFAULT_INITIAL_RTT / 2,
        "RTT の平均偏差は初期 RTT の半分であること"
    );
    assert!(stats.cwnd > 0, "輻輳ウィンドウは初期化されていること");
}

/// QUIC v1 の既定のハンドシェイクで交渉バージョンが v1 であること
#[tokio::test]
async fn test_negotiated_version_is_v1() {
    let cert = TestCert::generate("conn_version_v1");
    let params = TransportParams::new();

    let (client, server) = handshake_pair(&cert, &params, &params).await;

    assert_eq!(
        client.conn.negotiated_version(),
        Some(QuicVersion::V1),
        "クライアントの交渉バージョンが v1 であること"
    );
    assert_eq!(
        server.conn.negotiated_version(),
        Some(QuicVersion::V1),
        "サーバーの交渉バージョンが v1 であること"
    );
}

/// QUIC v2 でもハンドシェイクが完了し、交渉バージョンが v2 であること (RFC 9369)
///
/// QUIC v2 は Initial の鍵導出とヘッダー保護のラベルが v1 と異なるため、
/// 両側で同じバージョンを使って初めて成立する。
#[tokio::test]
async fn test_handshake_with_quic_v2() {
    let cert = TestCert::generate("conn_version_v2");
    let params = TransportParams::new();

    let (client, server) =
        handshake_pair_with_version(&cert, QuicVersion::V2, &params, &params).await;

    assert_eq!(
        client.conn.negotiated_version(),
        Some(QuicVersion::V2),
        "クライアントの交渉バージョンが v2 であること"
    );
    assert_eq!(
        server.conn.negotiated_version(),
        Some(QuicVersion::V2),
        "サーバーの交渉バージョンが v2 であること"
    );
}

/// ハンドシェイク後にクライアントへ HandshakeConfirmed が届くこと
///
/// サーバーには届かない (ngtcp2 は HANDSHAKE_DONE を受信したクライアントだけで
/// `handshake_confirmed` コールバックを呼ぶ)。
#[tokio::test]
async fn test_handshake_confirmed_on_client_only() {
    let cert = TestCert::generate("conn_confirmed");
    let params = TransportParams::new();

    let (mut client, mut server) = handshake_pair(&cert, &params, &params).await;

    // サーバーの HANDSHAKE_DONE を受け取るまで駆動する
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut confirmed = client
        .drain_events()
        .iter()
        .any(|event| matches!(event, ConnectionEvent::HandshakeConfirmed));
    while !confirmed {
        client.drive().await;
        server.drive().await;
        confirmed = client
            .drain_events()
            .iter()
            .any(|event| matches!(event, ConnectionEvent::HandshakeConfirmed));
        check_deadline(deadline, "ハンドシェイクの確認");
    }

    // サーバー側には発生しないこと
    assert!(
        !server
            .drain_events()
            .iter()
            .any(|event| matches!(event, ConnectionEvent::HandshakeConfirmed)),
        "サーバーに HandshakeConfirmed は発生しないこと"
    );
}

/// ストリームデータが双方向に届き、イベントが発生すること
#[tokio::test]
async fn test_stream_data_roundtrip() {
    let cert = TestCert::generate("conn_stream");
    let params = TransportParams::new();

    let (mut client, mut server) = handshake_pair(&cert, &params, &params).await;
    let _ = client.drain_events();
    let _ = server.drain_events();

    // クライアントが双方向ストリームを開いて FIN 付きでデータを送る
    let stream_id = client
        .conn
        .open_bidi_stream()
        .expect("ストリームを開けること");
    assert_eq!(
        client.conn.get_streams_bidi_left(),
        99,
        "デフォルトの initial_max_streams_bidi (100) から 1 減ること"
    );

    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let (written, datalen, _, _) = client
        .conn
        .write_stream(&mut send_buf, stream_id, b"hello", true, timestamp())
        .expect("ストリームに書き込めること");
    assert_eq!(datalen, Some(5), "5 バイトが受理されること");
    assert!(written > 0, "パケットが生成されること");
    client
        .socket
        .send_to(&send_buf[..written], client.remote)
        .await
        .expect("送信できること");

    // サーバーが StreamOpened と StreamData を受け取るまで駆動する
    let mut opened = false;
    let mut received: Vec<u8> = Vec::new();
    let mut fin = false;
    while !fin {
        server.drive().await;
        client.drive().await;
        for event in server.drain_events() {
            match event {
                ConnectionEvent::StreamOpened { stream_id: sid } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    opened = true;
                }
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    fin: f,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    received.extend_from_slice(&data);
                    fin = f;
                    // フロー制御クレジットを戻す
                    server
                        .conn
                        .extend_max_stream_offset(sid, data.len() as u64)
                        .expect("クレジットを戻せること");
                    server.conn.extend_max_offset(data.len() as u64);
                }
                _ => {}
            }
        }
        check_deadline(deadline, "ストリームデータの受信");
    }

    assert!(opened, "StreamOpened が発生すること");
    assert_eq!(received, b"hello", "受信データが一致すること");

    // サーバーが同じストリームに FIN 付きで応答する
    let (written, datalen, _, _) = server
        .conn
        .write_stream(&mut send_buf, stream_id, b"world", true, timestamp())
        .expect("サーバーがストリームに書き込めること");
    assert_eq!(datalen, Some(5), "5 バイトが受理されること");
    server
        .socket
        .send_to(&send_buf[..written], server.remote)
        .await
        .expect("送信できること");

    // 両側で StreamClosed が発生するまで駆動する
    let mut client_closed = false;
    let mut server_closed = false;
    let mut client_received: Vec<u8> = Vec::new();
    while !(client_closed && server_closed) {
        client.drive().await;
        server.drive().await;
        for event in client.drain_events() {
            match event {
                ConnectionEvent::StreamData { data, .. } => {
                    client_received.extend_from_slice(&data);
                    client
                        .conn
                        .extend_max_stream_offset(stream_id, data.len() as u64)
                        .expect("クレジットを戻せること");
                }
                ConnectionEvent::StreamClosed {
                    stream_id: sid,
                    rx_app_error_code,
                    tx_app_error_code,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    assert_eq!(rx_app_error_code, None, "受信側は正常終了であること");
                    assert_eq!(tx_app_error_code, None, "送信側は正常終了であること");
                    client_closed = true;
                }
                _ => {}
            }
        }
        for event in server.drain_events() {
            if let ConnectionEvent::StreamClosed { stream_id: sid, .. } = event {
                assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                server_closed = true;
            }
        }
        check_deadline(deadline, "ストリームのクローズ");
    }

    assert_eq!(client_received, b"world", "クライアントの受信データ");
}

/// `extend_max_streams_bidi` がピアのストリーム数の上限を増やすこと
///
/// ngtcp2 は上限を自動では増やさないため、明示的な拡張が必要
/// (RFC 9000 Section 19.11)。
#[tokio::test]
async fn test_extend_max_streams_bidi() {
    let cert = TestCert::generate("conn_max_streams");
    // クライアントが開ける双方向ストリームを 1 本に制限する
    let client_params = TransportParams::new();
    let server_params = TransportParams::new().with_max_streams_bidi(1);

    let (mut client, mut server) = handshake_pair(&cert, &client_params, &server_params).await;
    let _ = client.drain_events();
    let _ = server.drain_events();

    // 1 本目は開けるが 2 本目は開けないこと
    client.conn.open_bidi_stream().expect("1 本目は開けること");
    assert_eq!(
        client.conn.get_streams_bidi_left(),
        0,
        "残りが 0 になること"
    );
    let err = client
        .conn
        .open_bidi_stream()
        .expect_err("上限を超えてストリームを開けないこと");
    assert!(
        matches!(err, Error::Ngtcp2(_, _)),
        "ngtcp2 のエラーが返ること: {err:?}"
    );

    // サーバーが上限を 1 増やす
    server.conn.extend_max_streams_bidi(1);

    // クライアントが MaxStreamsBidi を受け取るまで駆動する
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut extended = None;
    while extended.is_none() {
        server.drive().await;
        client.drive().await;
        for event in client.drain_events() {
            if let ConnectionEvent::MaxStreamsBidi { max_streams } = event {
                extended = Some(max_streams);
            }
        }
        check_deadline(deadline, "MAX_STREAMS の受信");
    }
    assert_eq!(extended, Some(2), "上限が 2 に増えること");
    assert_eq!(
        client.conn.get_streams_bidi_left(),
        1,
        "拡張後に残りが 1 になること"
    );
    client
        .conn
        .open_bidi_stream()
        .expect("拡張後は 2 本目を開けること");
}

/// `shutdown_stream_read` がピアに STOP_SENDING として伝わること
/// (RFC 9000 Section 19.5)
#[tokio::test]
async fn test_shutdown_stream_read_sends_stop_sending() {
    let cert = TestCert::generate("conn_stop_sending");
    let params = TransportParams::new();

    let (mut client, mut server) = handshake_pair(&cert, &params, &params).await;
    let _ = client.drain_events();
    let _ = server.drain_events();

    let stream_id = client
        .conn
        .open_bidi_stream()
        .expect("ストリームを開けること");
    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let (written, _, _, _) = client
        .conn
        .write_stream(&mut send_buf, stream_id, b"data", false, timestamp())
        .expect("ストリームに書き込めること");
    client
        .socket
        .send_to(&send_buf[..written], client.remote)
        .await
        .expect("送信できること");

    // サーバーがデータを受け取ってから受信側を中断する
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut got_data = false;
    while !got_data {
        server.drive().await;
        client.drive().await;
        for event in server.drain_events() {
            if let ConnectionEvent::StreamData { .. } = event {
                got_data = true;
            }
        }
        check_deadline(deadline, "ストリームデータの受信");
    }

    server
        .conn
        .shutdown_stream_read(stream_id, 7)
        .expect("受信側を中断できること");

    // クライアントが StreamStopSending を受け取るまで駆動する
    let mut stopped = None;
    while stopped.is_none() {
        server.drive().await;
        client.drive().await;
        for event in client.drain_events() {
            if let ConnectionEvent::StreamStopSending {
                stream_id: sid,
                app_error_code,
            } = event
            {
                assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                stopped = Some(app_error_code);
            }
        }
        check_deadline(deadline, "STOP_SENDING の受信");
    }
    assert_eq!(stopped, Some(7), "エラーコード 7 が伝わること");
}

/// CONNECTION_CLOSE がピアに伝わり、終了理由を読み取れること
/// (RFC 9000 Section 10.2)
#[tokio::test]
async fn test_write_connection_close_reaches_peer() {
    let cert = TestCert::generate("conn_close");
    let params = TransportParams::new();

    let (mut client, mut server) = handshake_pair(&cert, &params, &params).await;

    // クライアントがアプリケーションエラーの CONNECTION_CLOSE を送る
    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let written = client
        .conn
        .write_connection_close_app(&mut send_buf, 42, b"bye", timestamp())
        .expect("CONNECTION_CLOSE を書き出せること");
    assert!(written > 0, "パケットが生成されること");
    client
        .socket
        .send_to(&send_buf[..written], client.remote)
        .await
        .expect("送信できること");

    // ローカルも closing 状態になること
    assert!(
        client.conn.is_in_closing_period() || client.conn.is_in_draining_period(),
        "CONNECTION_CLOSE を送った側も終了状態になること"
    );

    // サーバーが受信して draining に入るまで駆動する
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !server.conn.is_in_draining_period() {
        server.drive().await;
        check_deadline(deadline, "CONNECTION_CLOSE の受信");
    }

    let err = server.conn.get_connection_error();
    assert_eq!(err.error_code, 42, "エラーコードが伝わること");
    assert_eq!(err.reason, "bye", "理由文字列が伝わること");
    assert!(err.is_application, "アプリケーションエラーであること");
    assert!(err.has_error, "CONNECTION_CLOSE による終了であること");
}

/// `poll_issued_cids` が発行した CID を 1 回だけ返すこと
///
/// ngtcp2 はピアの `active_connection_id_limit` (既定値 8) に合わせて
/// NEW_CONNECTION_ID で追加の CID を発行する (RFC 9000 Section 5.1.1)。
#[tokio::test]
async fn test_poll_issued_cids_returns_each_cid_once() {
    let cert = TestCert::generate("conn_issued_cids");
    let params = TransportParams::new();

    let (_client, mut server) = handshake_pair(&cert, &params, &params).await;

    let issued = server.conn.poll_issued_cids();
    assert!(
        !issued.is_empty(),
        "ハンドシェイク後に追加の CID を発行していること"
    );
    assert!(
        issued.iter().all(|cid| !cid.is_empty()),
        "発行された CID が空でないこと"
    );

    // 取り出した CID は再度返さないこと
    assert!(
        server.conn.poll_issued_cids().is_empty(),
        "2 回目の呼び出しでは空になること"
    );
}

/// keep-alive のタイムアウトを設定するとアイドル時にパケットが生成されること
///
/// ngtcp2 は最後にパケットを書いた時刻から `timeout` 経過した後の
/// `write_pkt` で keep-alive のパケットを生成する (ngtcp2 の
/// `conn_keep_alive_expired` による)。
#[tokio::test]
async fn test_keep_alive_timeout_emits_packet() {
    let cert = TestCert::generate("conn_keep_alive");
    let params = TransportParams::new();

    let (mut client, server) = handshake_pair(&cert, &params, &params).await;
    drop(server);

    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let step = Duration::from_millis(100).as_nanos() as u64;

    // 送信キューを空にする。
    //
    // ACK は遅延させるため (RFC 9000 Section 13.2.1)、現在の時刻で
    // write_pkt が 0 を返しても、少し進めた時刻では遅延 ACK が出る。
    // 何も出ない状態が 2 回続くまで時刻を刻み進める。刻み幅は keep-alive の
    // タイムアウトより十分短くするため、空になった直後は期限が来ない。
    let mut ts = timestamp();
    let mut idle_rounds = 0;
    for _ in 0..100 {
        let (written, _, _) = client
            .conn
            .write_pkt(&mut send_buf, ts)
            .expect("write_pkt が成功すること");
        idle_rounds = if written == 0 { idle_rounds + 1 } else { 0 };
        if idle_rounds >= 2 {
            break;
        }
        ts += step;
    }
    assert!(idle_rounds >= 2, "送信キューが空になること");

    // keep-alive を 1 秒に設定する。基準時刻は最後にパケットを書いた時刻で、
    // 上のループの刻み (100 ms) より十分長いため 1 秒後で確実に期限が来る。
    let one_second = Duration::from_secs(1).as_nanos() as u64;
    client.conn.set_keep_alive_timeout(one_second);

    // タイムアウト前は何も生成されないこと
    let (written, _, _) = client
        .conn
        .write_pkt(&mut send_buf, ts + step)
        .expect("write_pkt が成功すること");
    assert_eq!(
        written, 0,
        "keep-alive のタイムアウト前はパケットを生成しないこと"
    );

    // タイムアウト後は keep-alive パケットが生成されること
    let (written, _, _) = client
        .conn
        .write_pkt(&mut send_buf, ts + one_second * 2)
        .expect("write_pkt が成功すること");
    assert!(
        written > 0,
        "keep-alive のタイムアウト後はパケットを生成すること"
    );
}

/// BBRv2 を指定してもハンドシェイクが完了すること
///
/// 輻輳制御アルゴリズムは [`Settings`] で指定し、ngtcp2 の
/// `settings.cc_algo` に反映される。
#[tokio::test]
async fn test_handshake_with_bbr2() {
    let cert = TestCert::generate("conn_settings_bbr2");
    let params = TransportParams::new();

    let mut settings = Settings::new(0);
    settings.congestion_algorithm = CongestionAlgorithm::Bbr2;

    let (client, server) = handshake_pair_with(
        &cert,
        QuicVersion::V1,
        &params,
        &params,
        settings.clone(),
        settings,
    )
    .await;

    assert!(
        client.conn.is_handshake_completed() && server.conn.is_handshake_completed(),
        "BBRv2 でもハンドシェイクが完了すること"
    );
}

/// 小さな `max_tx_udp_payload_size` を設定するとパケットがその長さに収まること
#[tokio::test]
async fn test_max_tx_udp_payload_size_limits_packet() {
    let cert = TestCert::generate("conn_settings_payload");
    let params = TransportParams::new();

    // 既定の 1350 より小さい 1200 を指定する
    let mut settings = Settings::new(0);
    settings.max_tx_udp_payload_size = 1200;

    let (mut client, _server) = handshake_pair_with(
        &cert,
        QuicVersion::V1,
        &params,
        &params,
        settings,
        Settings::new(0),
    )
    .await;

    // 送信すべきパケットを出し切り、大きなストリームデータで
    // ペイロード上限が効いていることを確認する
    let mut send_buf = [0u8; 4096];
    let mut max_written = 0usize;
    for _ in 0..32 {
        let (written, _, _) = client
            .conn
            .write_pkt(&mut send_buf, timestamp())
            .expect("write_pkt が成功すること");
        if written == 0 {
            break;
        }
        max_written = max_written.max(written);
    }

    // Initial パケットは 1200 バイト以上でなければならないため
    // (RFC 9000 Section 14.1)、上限は 1200 ちょうどになる
    assert!(
        max_written <= 1200,
        "パケットが max_tx_udp_payload_size を超えないこと: {max_written}"
    );
}

/// `Settings` の keep-alive が接続の作成時に適用されること
#[tokio::test]
async fn test_keep_alive_timeout_from_settings() {
    let cert = TestCert::generate("conn_settings_keep_alive");
    let params = TransportParams::new();

    let one_second = Duration::from_secs(1);
    let mut settings = Settings::new(0);
    settings.keep_alive_timeout = Some(one_second);

    let (mut client, server) = handshake_pair_with(
        &cert,
        QuicVersion::V1,
        &params,
        &params,
        settings,
        Settings::new(0),
    )
    .await;
    drop(server);

    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let step = Duration::from_millis(100).as_nanos() as u64;

    // 送信キューを空にする。ACK は遅延させるため (RFC 9000 Section 13.2.1)、
    // 何も出ない状態が 2 回続くまで時刻を進める
    let mut ts = timestamp();
    let mut idle_rounds = 0;
    for _ in 0..100 {
        let (written, _, _) = client
            .conn
            .write_pkt(&mut send_buf, ts)
            .expect("write_pkt が成功すること");
        idle_rounds = if written == 0 { idle_rounds + 1 } else { 0 };
        if idle_rounds >= 2 {
            break;
        }
        ts += step;
    }
    assert!(idle_rounds >= 2, "送信キューが空になること");

    // タイムアウト前は何も生成されないこと
    let (written, _, _) = client
        .conn
        .write_pkt(&mut send_buf, ts + step)
        .expect("write_pkt が成功すること");
    assert_eq!(
        written, 0,
        "keep-alive のタイムアウト前はパケットを生成しないこと"
    );

    // タイムアウト後は keep-alive パケットが生成されること
    let (written, _, _) = client
        .conn
        .write_pkt(&mut send_buf, ts + one_second.as_nanos() as u64 * 2)
        .expect("write_pkt が成功すること");
    assert!(
        written > 0,
        "keep-alive のタイムアウト後はパケットを生成すること"
    );
}

/// `Settings` のハンドシェイクタイムアウトを過ぎると接続が失敗すること
///
/// ngtcp2 は `initial_ts` + `handshake_timeout` を過ぎても TLS ハンドシェイクが
/// 完了していなければ `NGTCP2_ERR_HANDSHAKE_TIMEOUT` を返す。
#[tokio::test]
async fn test_handshake_timeout_from_settings() {
    // initial_ts = 0、タイムアウト 1 ミリ秒
    let mut settings = Settings::new(0);
    settings.handshake_timeout = Some(Duration::from_millis(1));

    let (mut conn, _tls_ctx) = new_idle_client(&settings);

    // 期限 (1 ミリ秒) を大きく過ぎた時刻でタイマーを処理する
    let err = conn
        .handle_expiry(10_000_000)
        .expect_err("ハンドシェイクがタイムアウトすること");
    assert!(
        err.to_string().contains("HANDSHAKE_TIMEOUT"),
        "ハンドシェイクのタイムアウトが報告されること: {err}"
    );
}

/// タイムアウトを設定しなければハンドシェイクは失敗しないこと
#[tokio::test]
async fn test_no_handshake_timeout_by_default() {
    let settings = Settings::new(0);
    assert_eq!(
        settings.handshake_timeout, None,
        "既定ではタイムアウトが無効であること"
    );

    let (mut conn, _tls_ctx) = new_idle_client(&settings);

    // initial_ts から 5 秒後 (トランスポートパラメータのアイドルタイムアウト
    // 30 秒より前) ではハンドシェイクのタイムアウトが起きないこと。
    // 他のエラー (アイドルタイムアウトなど) はこのテストの対象外。
    let five_seconds = Duration::from_secs(5).as_nanos() as u64;
    let err = conn.handle_expiry(five_seconds).err();
    assert!(
        !err.as_ref()
            .is_some_and(|e| e.to_string().contains("HANDSHAKE_TIMEOUT")),
        "タイムアウトが無効ならハンドシェイクのタイムアウトは起きないこと: {err:?}"
    );
}

/// 統計情報がハンドシェイクとデータ転送のトラフィックを反映すること
#[tokio::test]
async fn test_stats_report_traffic() {
    let cert = TestCert::generate("conn_stats");
    let params = TransportParams::new();

    let (mut client, mut server) = handshake_pair(&cert, &params, &params).await;

    // ハンドシェイクだけで両側にトラフィックが記録されること
    let after_handshake = client.conn.stats();
    assert!(
        after_handshake.packets_sent > 0,
        "送信パケット数が記録されること"
    );
    assert!(
        after_handshake.bytes_sent > 0,
        "送信バイト数が記録されること"
    );
    assert!(
        after_handshake.packets_received > 0,
        "受信パケット数が記録されること"
    );
    assert!(
        after_handshake.bytes_received > 0,
        "受信バイト数が記録されること"
    );
    assert!(
        after_handshake.cwnd > 0,
        "輻輳ウィンドウが初期化されていること"
    );
    assert_eq!(
        after_handshake.packets_lost, 0,
        "ループバックではパケットを喪失しないこと"
    );
    assert_eq!(
        after_handshake.ssthresh, None,
        "喪失を検出していなければスロースタッシュのしきい値は無いこと"
    );
    // ハンドシェイクで RTT を観測していること (RFC 9002 Section 3)
    assert!(
        after_handshake.min_rtt.is_some(),
        "ハンドシェイクで RTT を観測すること"
    );
    assert!(
        after_handshake.latest_rtt > Duration::ZERO,
        "直近の RTT が記録されること"
    );
    assert!(
        after_handshake.smoothed_rtt > Duration::ZERO,
        "平滑化された RTT が記録されること"
    );

    // データを転送すると送信量が増えること
    let stream_id = client
        .conn
        .open_bidi_stream()
        .expect("ストリームを開けること");
    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let (written, datalen, _, _) = client
        .conn
        .write_stream(&mut send_buf, stream_id, &[0x41u8; 512], true, timestamp())
        .expect("ストリームに書き込めること");
    assert_eq!(datalen, Some(512), "512 バイトが受理されること");
    client
        .socket
        .send_to(&send_buf[..written], client.remote)
        .await
        .expect("送信できること");

    let after_send = client.conn.stats();
    assert!(
        after_send.bytes_sent > after_handshake.bytes_sent,
        "データ転送で送信バイト数が増えること"
    );
    assert!(
        after_send.packets_sent >= after_handshake.packets_sent,
        "データ転送で送信パケット数が増えること"
    );

    // サーバーが受信するとサーバー側の統計に反映されること
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut received = 0usize;
    while received < 512 {
        server.drive().await;
        client.drive().await;
        for event in server.drain_events() {
            if let ConnectionEvent::StreamData { data, .. } = event {
                received += data.len();
            }
        }
        check_deadline(deadline, "ストリームデータの受信");
    }
    assert!(
        server.conn.stats().bytes_received > 0,
        "サーバー側の受信バイト数が記録されること"
    );
}

/// ストリームのフロー制御の残量が書き込みとピアの通知を反映すること
/// (RFC 9000 Section 4.1)
#[tokio::test]
async fn test_max_stream_data_left() {
    let cert = TestCert::generate("conn_stream_data_left");
    // クライアントが開く双方向ストリームの上限は、サーバーの
    // initial_max_stream_data_bidi_remote で決まる (RFC 9000 Section 18.2)
    let server_params = TransportParams::new().with_initial_max_stream_data_bidi_remote(4096);
    let client_params = TransportParams::new();

    let (mut client, _server) = handshake_pair(&cert, &client_params, &server_params).await;

    let stream_id = client
        .conn
        .open_bidi_stream()
        .expect("ストリームを開けること");
    assert_eq!(
        client.conn.get_max_stream_data_left(stream_id),
        4096,
        "初期値はピアが通知した上限であること"
    );

    // 100 バイト書き込むと残りが減ること
    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let (_written, datalen, _, _) = client
        .conn
        .write_stream(&mut send_buf, stream_id, &[0x42u8; 100], false, timestamp())
        .expect("ストリームに書き込めること");
    assert_eq!(datalen, Some(100), "100 バイトが受理されること");
    assert_eq!(
        client.conn.get_max_stream_data_left(stream_id),
        4096 - 100,
        "書き込んだ分だけ残りが減ること"
    );

    // 開いていないストリームは 0 であること
    assert_eq!(
        client.conn.get_max_stream_data_left(8),
        0,
        "存在しないストリームの残りは 0 であること"
    );

    // 輻輳ウィンドウの残りも取得できること
    assert!(
        client.conn.get_cwnd_left() > 0,
        "輻輳ウィンドウの残りが取得できること"
    );
}

/// クライアントが Stateless Reset を受け取ると接続を終了すること
///
/// サーバーは最初の SCID に対応する Stateless Reset トークンを
/// トランスポートパラメータで配布する (RFC 9000 Section 18.2)。
/// クライアントはそのトークンと一致する Stateless Reset だけを受理する
/// (RFC 9000 Section 10.3.1)。
#[tokio::test]
async fn test_client_accepts_stateless_reset() {
    let cert = TestCert::generate("conn_stateless_reset");
    let secret = StatelessResetSecret::generate().expect("秘密を生成できること");
    let params = TransportParams::new();

    let mut server_settings = Settings::new(0);
    server_settings.stateless_reset_secret = Some(secret.clone());

    let (mut client, server) = handshake_pair_with(
        &cert,
        QuicVersion::V1,
        &params,
        &params,
        Settings::new(0),
        server_settings,
    )
    .await;

    assert!(
        !client.conn.is_in_draining_period() && !client.conn.is_in_closing_period(),
        "Stateless Reset を受け取る前は接続が生きていること"
    );

    // サーバーの SCID (= クライアントの DCID) に対する Stateless Reset を作る
    let token = secret
        .token(&server.scid)
        .expect("サーバーの SCID からトークンを導出できること");
    let mut reset = [0u8; SEND_BUFFER_SIZE];
    let written =
        write_stateless_reset(&mut reset, &token, 1200).expect("Stateless Reset を書き出せること");
    assert!(written > 0, "パケットが生成されること");

    // サーバーのアドレスから届いたものとしてクライアントに渡す
    let path = PathInfo {
        local: client.local,
        remote: client.remote,
    };
    // Stateless Reset の受信は接続の終了を意味するため、read_pkt の戻り値は
    // エラーでも成功でもよい。終了状態になったことを確認する。
    let _ = client.conn.read_pkt(
        &path,
        &PacketInfo::default(),
        &reset[..written],
        timestamp(),
    );

    assert!(
        client.conn.is_in_draining_period() || client.conn.is_in_closing_period(),
        "Stateless Reset を受け取ると接続が終了状態になること"
    );

    // イベントとして通知されること
    let events = client.drain_events();
    assert!(
        events.contains(&ConnectionEvent::StatelessResetReceived),
        "StatelessResetReceived が発生すること: {events:?}"
    );
}

/// トークンが一致しない Stateless Reset は無視すること
///
/// Stateless Reset は認証されないパケットなので、トークンが一致しなければ
/// 受け入れてはいけない (RFC 9000 Section 10.3.1)。
#[tokio::test]
async fn test_client_ignores_stateless_reset_with_wrong_token() {
    let cert = TestCert::generate("conn_stateless_reset_wrong");
    let secret = StatelessResetSecret::generate().expect("秘密を生成できること");
    let attacker_secret = StatelessResetSecret::generate().expect("秘密を生成できること");
    let params = TransportParams::new();

    let mut server_settings = Settings::new(0);
    server_settings.stateless_reset_secret = Some(secret.clone());

    let (mut client, server) = handshake_pair_with(
        &cert,
        QuicVersion::V1,
        &params,
        &params,
        Settings::new(0),
        server_settings,
    )
    .await;

    // 別の秘密から導出したトークンで Stateless Reset を作る
    let wrong_token = attacker_secret
        .token(&server.scid)
        .expect("トークンを導出できること");
    let mut reset = [0u8; SEND_BUFFER_SIZE];
    let written = write_stateless_reset(&mut reset, &wrong_token, 1200)
        .expect("Stateless Reset を書き出せること");

    let path = PathInfo {
        local: client.local,
        remote: client.remote,
    };
    let _ = client.conn.read_pkt(
        &path,
        &PacketInfo::default(),
        &reset[..written],
        timestamp(),
    );

    assert!(
        !client.conn.is_in_draining_period() && !client.conn.is_in_closing_period(),
        "トークンが一致しない Stateless Reset は無視すること"
    );
    assert!(
        !client
            .drain_events()
            .contains(&ConnectionEvent::StatelessResetReceived),
        "トークンが一致しなければイベントも発生しないこと"
    );
}

/// ハンドシェイクが完了する前は鍵の更新を開始できないこと
///
/// ngtcp2 はこの状態で呼ばれると assert でプロセスを異常終了させるため、
/// ラッパーがエラーを返さなければならない。
#[tokio::test]
async fn test_key_update_before_handshake_fails() {
    let (mut conn, _tls_ctx) = new_idle_client(&Settings::new(0));

    let err = conn
        .initiate_key_update(0)
        .expect_err("ハンドシェイク前は鍵の更新を開始できないこと");
    assert!(
        matches!(err, Error::InvalidArgument(_)),
        "InvalidArgument が返ること: {err:?}"
    );
}

/// 接続を閉じたあとは鍵の更新を開始できないこと
///
/// closing / draining 状態でも ngtcp2 は assert で異常終了するため、
/// ラッパーがエラーを返さなければならない。
#[tokio::test]
async fn test_key_update_after_close_fails() {
    let cert = TestCert::generate("conn_key_update_closed");
    let params = TransportParams::new();

    let (mut client, server) = handshake_pair(&cert, &params, &params).await;
    drop(server);

    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let _ = client
        .conn
        .write_connection_close_app(&mut send_buf, 0, b"", timestamp())
        .expect("CONNECTION_CLOSE を書き出せること");
    assert!(
        client.conn.is_in_closing_period() || client.conn.is_in_draining_period(),
        "CONNECTION_CLOSE のあとは終了状態であること"
    );

    let err = client
        .conn
        .initiate_key_update(timestamp())
        .expect_err("終了状態では鍵の更新を開始できないこと");
    assert!(
        matches!(err, Error::InvalidArgument(_)),
        "InvalidArgument が返ること: {err:?}"
    );
}

/// ngtcp2 が鍵の更新を受け付けるまで待つ
///
/// ハンドシェイクの確認前と、前の更新の確定から 1 PTO が経過するまでは
/// `NGTCP2_ERR_INVALID_STATE` で拒否される (ngtcp2 の
/// `conn_initiate_key_update` 参照)。いずれも一時的な状態なので再試行する。
async fn initiate_key_update(conn: &mut Connection) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if conn.initiate_key_update(timestamp()).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "鍵の更新を開始できること (NGTCP2_ERR_INVALID_STATE が解消しない)"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// 鍵を更新したあとも接続が生きてデータが転送できること
/// (RFC 9001 Section 4.6.3)
///
/// 鍵の更新は次の `write_pkt` で新しい 1-RTT 鍵に切り替わり、ピアは
/// 受信した鍵の世代に合わせて追従する。
#[tokio::test]
async fn test_key_update_keeps_connection_alive() {
    let cert = TestCert::generate("conn_key_update");
    let params = TransportParams::new();

    let (mut client, mut server) = handshake_pair(&cert, &params, &params).await;

    // ハンドシェイクが確認されるまで駆動する。ngtcp2 は確認前の
    // 鍵の更新を拒否する (RFC 9001 Section 4.1.2)
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut confirmed = client
        .drain_events()
        .iter()
        .any(|event| matches!(event, ConnectionEvent::HandshakeConfirmed));
    while !confirmed {
        client.drive().await;
        server.drive().await;
        confirmed = client
            .drain_events()
            .iter()
            .any(|event| matches!(event, ConnectionEvent::HandshakeConfirmed));
        check_deadline(deadline, "ハンドシェイクの確認");
    }

    // クライアントが鍵の更新を開始する
    initiate_key_update(&mut client.conn).await;

    // 更新後にストリームデータを送る。
    // 鍵の切り替えは ngtcp2 が書き出しのタイミングで行うため
    // (ngtcp2 の conn_prepare_key_update 参照)、更新の開始直後に
    // パケットが生成されるとは限らない。ここではデータが
    // 転送できることで接続が生きていることを確認する。
    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let stream_id = client
        .conn
        .open_bidi_stream()
        .expect("ストリームを開けること");
    let payload = b"after key update";
    let (written, datalen, _, _) = client
        .conn
        .write_stream(&mut send_buf, stream_id, payload, true, timestamp())
        .expect("ストリームに書き込めること");
    assert_eq!(datalen, Some(payload.len()), "全バイトが受理されること");
    client
        .socket
        .send_to(&send_buf[..written], client.remote)
        .await
        .expect("送信できること");

    // サーバーが終端まで読めること
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut received = Vec::new();
    let mut fin = false;
    while !fin {
        server.drive().await;
        client.drive().await;
        for event in server.drain_events() {
            if let ConnectionEvent::StreamData {
                stream_id: sid,
                data,
                fin: f,
            } = event
            {
                assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                received.extend_from_slice(&data);
                fin = f;
            }
        }
        check_deadline(deadline, "鍵の更新後のデータ受信");
    }

    assert_eq!(received, payload, "鍵の更新後もデータが届くこと");
}

/// クライアントの最初の Initial を受け取ってサーバーのエンドポイントを作る
///
/// サーバーはクライアントの最初の Initial を受け取ってからでないと接続を
/// 作れない (CID とトランスポートパラメータの `original_dcid` が必要なため)。
/// 最初のデータグラムだけをここで読み込み、続き (0-RTT など) はソケットに
/// 残すため、以降の `drive` で処理される。
async fn accept_client(
    server_socket: UdpSocket,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    version: QuicVersion,
    params: &TransportParams,
    settings: &Settings,
    tls_ctx: Arc<TlsContext>,
) -> Endpoint {
    let mut buf = vec![0u8; RECV_BUFFER_SIZE];
    let (len, from) = server_socket
        .recv_from(&mut buf)
        .await
        .expect("クライアントの Initial を受信できること");
    assert_eq!(from, client_addr, "クライアントのアドレスが一致すること");
    let (original_dcid, client_scid) = parse_initial(&buf[..len], version);

    let mut server = Endpoint::new_server(
        server_socket,
        server_addr,
        client_addr,
        version,
        &client_scid,
        &original_dcid,
        params,
        settings,
        tls_ctx,
    );

    // 受信済みの Initial をサーバーの接続に流し込む
    let initial = buf[..len].to_vec();
    let path = PathInfo {
        local: server.local,
        remote: server.remote,
    };
    server
        .conn
        .read_pkt(&path, &PacketInfo::default(), &initial, timestamp())
        .expect("サーバーが Initial を処理できること");

    server
}

/// 0-RTT でハンドシェイク完了前にデータを送れること (RFC 9001 Section 4.6)
///
/// 1 回目の接続でセッション情報を保存し、2 回目の接続でハンドシェイクの
/// 完了前にデータを送る。サーバーがハンドシェイクを完了する前にそのデータを
/// 受信することで、1-RTT に格上げされていないことを確認する。
/// 0-RTT が使われたことは `is_in_early_data` でも確認する。
#[tokio::test]
async fn test_early_data_stream_before_handshake() {
    let cert = TestCert::generate("conn_early_data");
    let params = TransportParams::new();

    // サーバーの TLS コンテキストは 2 回の接続で共有する。セッションチケットの
    // 暗号鍵は SSL_CTX ごとに作られるため、共有しないとチケットを再開できない。
    let server_tls_ctx = Arc::new({
        let mut tls_ctx = TlsContext::new_server(&cert.cert_path, &cert.key_path, &[ALPN])
            .expect("サーバーの TLS コンテキストを作れること");
        tls_ctx
            .set_accept_early_data(true)
            .expect("0-RTT の受け入れを有効にできること");
        tls_ctx
    });
    let client_tls_ctx = Arc::new(
        TlsContext::new_client_with_options(&[ALPN], false).expect("TLS コンテキストを作れること"),
    );

    let mut settings = Settings::new(0);
    settings.initial_ts = timestamp();

    // 1 回目の接続: セッション情報を保存する
    let ticket = {
        let (server_socket, server_addr) = Endpoint::bind().await;
        let (client_socket, client_addr) = Endpoint::bind().await;
        let mut client = Endpoint::new_client(
            client_socket,
            client_addr,
            server_addr,
            QuicVersion::V1,
            &params,
            &settings,
            Arc::clone(&client_tls_ctx),
            None,
        );

        // クライアントの Initial を送出してからサーバーの接続を作る
        client.drive().await;
        let mut server = accept_client(
            server_socket,
            server_addr,
            client_addr,
            QuicVersion::V1,
            &params,
            &settings,
            Arc::clone(&server_tls_ctx),
        )
        .await;

        let deadline = Instant::now() + TEST_TIMEOUT;
        while !(client.conn.is_handshake_completed() && server.conn.is_handshake_completed()) {
            client.drive().await;
            server.drive().await;
            check_deadline(deadline, "1 回目のハンドシェイク");
        }
        assert!(
            !client.conn.is_in_early_data(),
            "セッションを設定していない接続は 0-RTT を送らないこと"
        );

        // サーバーはハンドシェイク完了後に NewSessionTicket を送る
        // (RFC 8446 Section 4.6.1)。クライアントが受け取るまで駆動する。
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            client.drive().await;
            server.drive().await;
            if let Some(ticket) = client
                .conn
                .take_session_ticket()
                .expect("セッション情報を取得できること")
            {
                break ticket;
            }
            check_deadline(deadline, "セッションチケットの受信");
        }
    };

    assert!(
        !ticket.session().is_empty(),
        "セッションチケットが保存されること"
    );
    assert!(
        !ticket.transport_params().is_empty(),
        "0-RTT 用のトランスポートパラメータが保存されること"
    );

    // 2 回目の接続: 保存したセッション情報で 0-RTT を送る
    let (server_socket, server_addr) = Endpoint::bind().await;
    let (client_socket, client_addr) = Endpoint::bind().await;
    let mut client = Endpoint::new_client(
        client_socket,
        client_addr,
        server_addr,
        QuicVersion::V1,
        &params,
        &settings,
        Arc::clone(&client_tls_ctx),
        Some(&ticket),
    );

    // クライアントの Initial と 0-RTT のデータを送る
    client.drive().await;
    assert!(
        client.conn.is_in_early_data(),
        "セッションを設定すると 0-RTT を送れる状態になること"
    );
    assert!(
        !client.conn.is_handshake_completed(),
        "0-RTT を送る時点でハンドシェイクが完了していないこと"
    );

    let stream_id = client
        .conn
        .open_bidi_stream()
        .expect("ストリームを開けること");
    let payload = b"early data";
    let mut send_buf = [0u8; SEND_BUFFER_SIZE];
    let (written, datalen, _, _) = client
        .conn
        .write_stream(&mut send_buf, stream_id, payload, true, timestamp())
        .expect("0-RTT のデータを書き込めること");
    assert_eq!(datalen, Some(payload.len()), "全バイトが受理されること");
    client
        .socket
        .send_to(&send_buf[..written], client.remote)
        .await
        .expect("0-RTT のパケットを送信できること");

    let mut server = accept_client(
        server_socket,
        server_addr,
        client_addr,
        QuicVersion::V1,
        &params,
        &settings,
        Arc::clone(&server_tls_ctx),
    )
    .await;

    // サーバーが 0-RTT のデータを受信するまで駆動する。サーバーの
    // ハンドシェイクが完了するのはクライアントの Finished を処理した後なので、
    // 完了前にデータが届いたことを確認できる。
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut received = Vec::new();
    let mut received_before_handshake = false;
    while received.len() < payload.len() {
        client.drive().await;
        server.drive().await;
        for event in server.drain_events() {
            if let ConnectionEvent::StreamData {
                stream_id: sid,
                data,
                fin,
            } = event
            {
                assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                assert!(fin, "FIN まで届くこと");
                if !server.conn.is_handshake_completed() {
                    received_before_handshake = true;
                }
                received.extend_from_slice(&data);
            }
        }
        check_deadline(deadline, "0-RTT のデータ受信");
    }

    assert_eq!(received, payload, "0-RTT のデータがサーバーに届くこと");
    assert!(
        received_before_handshake,
        "サーバーはハンドシェイク完了前に 0-RTT のデータを受信すること"
    );

    // ハンドシェイクを完了させ、0-RTT が受理されたことを確認する
    while !client.conn.is_handshake_completed() {
        client.drive().await;
        server.drive().await;
        check_deadline(deadline, "2 回目のハンドシェイク");
    }
    let rejected = client
        .drain_events()
        .iter()
        .any(|event| matches!(event, ConnectionEvent::EarlyDataRejected));
    assert!(!rejected, "0-RTT が拒否されないこと");
    assert!(
        client.conn.is_early_data_accepted(),
        "サーバーが 0-RTT を受理したこと"
    );
    assert!(
        !client.conn.is_early_data_rejected(),
        "0-RTT が拒否されていないこと"
    );
}

/// サーバーが 0-RTT を有効にしていなければ 0-RTT を送らないこと
///
/// サーバーが 0-RTT を有効にしていない場合、チケットに early data の対応が
/// 含まれないため、クライアントは 0-RTT を試みない (RFC 9001 Section 4.6.1)。
/// ハンドシェイクは通常どおり完了する。
#[tokio::test]
async fn test_early_data_not_offered_without_server_support() {
    let cert = TestCert::generate("conn_early_data_disabled");
    let params = TransportParams::new();

    // 0-RTT を有効にしていないサーバーの TLS コンテキスト
    let server_tls_ctx = Arc::new(
        TlsContext::new_server(&cert.cert_path, &cert.key_path, &[ALPN])
            .expect("サーバーの TLS コンテキストを作れること"),
    );
    let client_tls_ctx = Arc::new(
        TlsContext::new_client_with_options(&[ALPN], false).expect("TLS コンテキストを作れること"),
    );

    let mut settings = Settings::new(0);
    settings.initial_ts = timestamp();

    // 1 回目の接続でチケットを受け取る
    let (server_socket, server_addr) = Endpoint::bind().await;
    let (client_socket, client_addr) = Endpoint::bind().await;
    let mut client = Endpoint::new_client(
        client_socket,
        client_addr,
        server_addr,
        QuicVersion::V1,
        &params,
        &settings,
        Arc::clone(&client_tls_ctx),
        None,
    );
    client.drive().await;
    let mut server = accept_client(
        server_socket,
        server_addr,
        client_addr,
        QuicVersion::V1,
        &params,
        &settings,
        Arc::clone(&server_tls_ctx),
    )
    .await;

    let deadline = Instant::now() + TEST_TIMEOUT;
    while !(client.conn.is_handshake_completed() && server.conn.is_handshake_completed()) {
        client.drive().await;
        server.drive().await;
        check_deadline(deadline, "1 回目のハンドシェイク");
    }

    let deadline = Instant::now() + TEST_TIMEOUT;
    let ticket = loop {
        client.drive().await;
        server.drive().await;
        check_deadline(deadline, "セッションチケットの受信");
        if let Some(ticket) = client
            .conn
            .take_session_ticket()
            .expect("セッション情報を取得できること")
        {
            break ticket;
        }
    };

    // 受け取ったチケットで接続しても 0-RTT は送らない
    let (server_socket, server_addr) = Endpoint::bind().await;
    let (client_socket, client_addr) = Endpoint::bind().await;
    let mut client = Endpoint::new_client(
        client_socket,
        client_addr,
        server_addr,
        QuicVersion::V1,
        &params,
        &settings,
        Arc::clone(&client_tls_ctx),
        Some(&ticket),
    );
    client.drive().await;
    assert!(
        !client.conn.is_in_early_data(),
        "サーバーが 0-RTT を有効にしていなければ 0-RTT を送らないこと"
    );

    // ハンドシェイクは通常どおり完了する
    let mut server = accept_client(
        server_socket,
        server_addr,
        client_addr,
        QuicVersion::V1,
        &params,
        &settings,
        Arc::clone(&server_tls_ctx),
    )
    .await;
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !(client.conn.is_handshake_completed() && server.conn.is_handshake_completed()) {
        client.drive().await;
        server.drive().await;
        check_deadline(deadline, "2 回目のハンドシェイク");
    }
    assert!(
        !client.conn.is_early_data_accepted(),
        "0-RTT は受理されていないこと"
    );
    assert!(
        !client.conn.is_early_data_rejected(),
        "0-RTT を試みていないため拒否もされていないこと"
    );
}

/// `shutdown_stream_write_reliable` が失われたデータを再送してから
/// RESET_STREAM_AT を送ること (draft-ietf-quic-reliable-stream-reset)
///
/// 送信したデータをネットワーク上で失わせた状態でリセットすると、RESET_STREAM
/// では未確認のデータを破棄してしまうためピアに届かない。RESET_STREAM_AT では
/// リセットの時点までのデータを届けることが約束されるため、ピアはデータを
/// 受け取ってからリセットを知る。
#[tokio::test]
async fn test_reliable_reset_delivers_lost_data() {
    let cert = TestCert::generate("conn_reliable_reset");
    // 双方が reset_stream_at を通知する
    let params = TransportParams::new().with_reset_stream_at(true);

    let (mut client, mut server) = handshake_pair(&cert, &params, &params).await;
    let _ = client.drain_events();
    let _ = server.drain_events();

    assert!(
        client.conn.supports_reset_stream_at(),
        "ピアが通知した reset_stream_at が読めること"
    );
    assert!(
        server.conn.supports_reset_stream_at(),
        "サーバー側からも読めること"
    );

    let stream_id = client
        .conn
        .open_bidi_stream()
        .expect("ストリームを開けること");

    // 送信したパケットをサーバーに届けずに捨てる (パケット損失の再現)。
    // クライアントは ACK を受け取らないため、このデータは未確認のまま残る
    let payload = b"reliable reset payload";
    let ts = timestamp();
    let (written, _, _, _) = client
        .conn
        .write_stream(&mut client.send_buf, stream_id, payload, false, ts)
        .expect("ストリームに書き込めること");
    assert!(written > 0, "データを含むパケットが書き出されること");

    // 失われたデータを再送させたうえでリセットする
    client
        .conn
        .shutdown_stream_write_reliable(stream_id, 42)
        .expect("信頼性のあるリセットを要求できること");

    // サーバーがデータとリセットを受け取るまで駆動する
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut received = Vec::new();
    let mut reset = None;
    while reset.is_none() || received.len() < payload.len() {
        client.drive().await;
        server.drive().await;
        for event in server.drain_events() {
            match event {
                ConnectionEvent::StreamData { data, .. } => received.extend_from_slice(&data),
                ConnectionEvent::StreamReset {
                    stream_id: sid,
                    final_size,
                    app_error_code,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    assert_eq!(
                        final_size,
                        payload.len() as u64,
                        "リセットの時点までのデータが配信対象になること"
                    );
                    reset = Some(app_error_code);
                }
                _ => {}
            }
        }
        check_deadline(deadline, "信頼性のあるリセットの反映");
    }

    assert_eq!(
        received, payload,
        "リセットの前に送ったデータが欠落せず届くこと"
    );
    assert_eq!(reset, Some(42), "アプリケーションエラーコードが伝わること");
}

/// ピアが `reset_stream_at` を通知していない場合は RESET_STREAM に落ちること
///
/// 保証は得られないが、リセット自体は通常どおり伝わる。ピアが受理できない
/// RESET_STREAM_AT を送らないため、ハンドシェイクも接続も壊れない。
#[tokio::test]
async fn test_reliable_reset_falls_back_without_support() {
    let cert = TestCert::generate("conn_reliable_reset_fallback");
    // クライアントだけが通知する
    let client_params = TransportParams::new().with_reset_stream_at(true);
    let server_params = TransportParams::new();

    let (mut client, mut server) = handshake_pair(&cert, &client_params, &server_params).await;
    let _ = client.drain_events();
    let _ = server.drain_events();

    assert!(
        !client.conn.supports_reset_stream_at(),
        "通知していないピアは false になること"
    );

    let stream_id = client
        .conn
        .open_bidi_stream()
        .expect("ストリームを開けること");
    client
        .conn
        .shutdown_stream_write_reliable(stream_id, 7)
        .expect("保証が得られなくてもリセットできること");

    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut reset = None;
    while reset.is_none() {
        client.drive().await;
        server.drive().await;
        for event in server.drain_events() {
            if let ConnectionEvent::StreamReset {
                stream_id: sid,
                app_error_code,
                ..
            } = event
            {
                assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                reset = Some(app_error_code);
            }
        }
        check_deadline(deadline, "RESET_STREAM の反映");
    }

    assert_eq!(reset, Some(7), "RESET_STREAM として伝わること");
    assert!(
        !server.conn.is_in_closing_period() && !server.conn.is_in_draining_period(),
        "接続は終了しないこと"
    );
}
