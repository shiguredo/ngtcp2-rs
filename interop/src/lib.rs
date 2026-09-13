//! s2n-quic / quiche との相互運用テストの共通ヘルパー
//!
//! このクレートは `shiguredo_ngtcp2_tokio` と、独立した QUIC 実装である
//! s2n-quic (AWS) と quiche (Cloudflare) を 1 つのプロセスに載せ、実際の
//! UDP ソケットで接続させる。Rust 実装同士のテストでは検出できない
//! 「ngtcp2 の使い方だけが誤っている」不具合を検出するのが目的。
//!
//! - `shiguredo_ngtcp2_tokio` のサーバー / クライアントの駆動はこのモジュールが持つ
//! - s2n-quic / quiche 側の駆動は各テストファイルが持つ
//!
//! モックやスタブは使わない。すべて実際の UDP ソケットと実際の TLS で接続する。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use shiguredo_ngtcp2_tokio::{
    Client, ClientConfig, ClientConnection, ConnectionEvent, Server, ServerConfig, SessionTicket,
    StreamId,
};

/// 相互運用に使う ALPN
///
/// HTTP/3 を載せない素の QUIC の相互運用に使われる `hq-interop`
/// (HTTP/0.9 over QUIC)。3 実装すべてが同じ名前を提示できる。
pub const ALPN: &[u8] = b"hq-interop";

/// テスト全体のタイムアウト
pub const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `127.0.0.1` のエフェメラルポートのアドレス
pub fn ephemeral_addr() -> SocketAddr {
    "127.0.0.1:0".parse().expect("リテラルアドレスは有効")
}

/// テスト用の証明書一式 (CA とサーバー証明書)
///
/// `Server::bind` はファイルパスを要求し、s2n-quic / quiche は PEM 文字列や
/// パスを直接受け取れるため、両方を保持する。一時ディレクトリは [`Drop`] で
/// 削除する。
///
/// 自己署名のリーフ証明書をトラストアンカーにするのではなく、CA 証明書と
/// サーバー証明書を分ける。BoringSSL (quiche) は `basicConstraints` が CA でない
/// 証明書をトラストアンカーとして扱わないため、チェーン検証を通せないため。
pub struct TestCert {
    /// 証明書と鍵を書き出した一時ディレクトリ
    dir: PathBuf,
    /// サーバー証明書のパス
    cert_path: PathBuf,
    /// サーバー秘密鍵のパス
    key_path: PathBuf,
    /// CA 証明書のパス
    ca_cert_path: PathBuf,
    /// サーバー証明書 (PEM)
    cert_pem: String,
    /// サーバー秘密鍵 (PEM)
    key_pem: String,
    /// CA 証明書 (PEM)
    ca_cert_pem: String,
}

impl TestCert {
    /// `localhost` 用のサーバー証明書を CA 付きで生成する
    pub fn generate(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "ngtcp2_interop_{}_{}_{}",
            label,
            std::process::id(),
            unique
        ));
        std::fs::create_dir_all(&dir).expect("一時ディレクトリを作成できること");

        // CA 証明書 (自分自身で署名する)
        let mut ca_params = rcgen::CertificateParams::new(Vec::new())
            .expect("CA の証明書パラメータを作成できること");
        // CA とサーバー証明書で DN を分ける。同じ DN にすると検証側が
        // 「自分自身が発行者」と解釈してチェーンを辿れない。
        let mut ca_dn = rcgen::DistinguishedName::new();
        ca_dn.push(rcgen::DnType::CommonName, "ngtcp2-rs interop test CA");
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().expect("CA の鍵ペアを生成できること");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("CA 証明書を生成できること");

        // サーバー証明書 (CA が署名する)
        let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("証明書パラメータを作成できること");
        let mut server_dn = rcgen::DistinguishedName::new();
        server_dn.push(rcgen::DnType::CommonName, "localhost");
        server_params.distinguished_name = server_dn;
        server_params.use_authority_key_identifier_extension = true;
        server_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = rcgen::KeyPair::generate().expect("サーバーの鍵ペアを生成できること");
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("サーバー証明書を生成できること");

        let cert_pem = server_cert.pem();
        let key_pem = server_key.serialize_pem();
        let ca_cert_pem = ca_cert.pem();

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let ca_cert_path = dir.join("ca_cert.pem");
        std::fs::write(&cert_path, &cert_pem).expect("証明書を書き込めること");
        std::fs::write(&key_path, &key_pem).expect("秘密鍵を書き込めること");
        std::fs::write(&ca_cert_path, &ca_cert_pem).expect("CA 証明書を書き込めること");

        Self {
            dir,
            cert_path,
            key_path,
            ca_cert_path,
            cert_pem,
            key_pem,
            ca_cert_pem,
        }
    }

    /// サーバー証明書のパスを返す
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// サーバー秘密鍵のパスを返す
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// CA 証明書のパスを返す
    pub fn ca_cert_path(&self) -> &Path {
        &self.ca_cert_path
    }

    /// サーバー証明書 (PEM) を返す
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// サーバー秘密鍵 (PEM) を返す
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// CA 証明書 (PEM) を返す
    ///
    /// クライアントのトラストアンカーとして使う。
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }
}

impl Drop for TestCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 我々のサーバーを起動する
///
/// `config` に `None` を渡すと既定の設定 (アドレス検証なし) になる。
pub async fn bind_server(cert: &TestCert, config: Option<ServerConfig>) -> Server {
    Server::bind(
        ephemeral_addr(),
        cert.cert_path(),
        cert.key_path(),
        config.or_else(|| Some(ServerConfig::new(&[ALPN]))),
    )
    .await
    .expect("サーバーを起動できること")
}

/// 我々のサーバーが接続 1 つについて観測した結果
pub struct Echoed {
    /// 受け取ったデータ
    pub data: Vec<u8>,
    /// 0-RTT (early data) としてデータを受け取ったかどうか (RFC 9001 Section 4.6)
    ///
    /// 0-RTT かどうかはデータを受け取った時点でしか判定できないため、
    /// 受け取り時に接続が記録した結果を返す。
    pub received_early_data: bool,
    /// 新しい経路の検証に成功したかどうか (RFC 9000 Section 8.2)
    pub path_validated: bool,
    /// 受け取ったデータをエコーとして返したかどうか
    pub echo_sent: bool,
}

/// 我々のサーバーで `count` 接続を受け入れ、接続ごとの結果を返す
///
/// 接続は順に処理する。データを送らない接続 (0-RTT のセッションチケットの
/// 取得だけを行う接続など) は `data` が空になる。
pub async fn accept_and_echo_n(mut server: Server, count: usize) -> Vec<Echoed> {
    let mut results = Vec::with_capacity(count);
    for _ in 0..count {
        results.push(accept_and_echo_one(&mut server).await);
    }
    results
}

/// 我々のサーバーで 1 接続を受け入れ、受け取ったデータをそのまま返す
///
/// クライアントが FIN を送るまで [`ConnectionEvent::StreamData`] を読み続け、
/// 読み終えたら同じストリームに同じデータを FIN 付きで書き戻す。
pub async fn accept_and_echo(server: Server) -> Echoed {
    let mut results = accept_and_echo_n(server, 1).await;
    results.remove(0)
}

/// 我々のサーバーで 1 接続を受け入れ、ピアが接続を閉じるまで駆動する
///
/// [`accept_and_echo`] はエコーを返した時点で駆動を止めるが、マイグレーション
/// では新しい経路の検証と、古い経路へ送ってしまったデータの再送に時間がかかる。
/// 経路が切り替わるまで駆動し続ける必要があるテストではこちらを使う。
pub async fn accept_and_echo_until_closed(mut server: Server) -> Echoed {
    let mut conn = server
        .accept()
        .await
        .expect("accept が成功すること")
        .expect("接続が受け入れられること");
    drive_until_closed(&mut conn, true).await
}

/// 接続を 1 つ受け入れ、FIN までデータを読んでエコーを返す
async fn accept_and_echo_one(server: &mut Server) -> Echoed {
    let mut conn = server
        .accept()
        .await
        .expect("accept が成功すること")
        .expect("接続が受け入れられること");
    drive_until_closed(&mut conn, false).await
}

/// 接続を駆動し、FIN まで読んだデータをエコーで返す
///
/// `until_closed` が true の場合はエコーを返した後もピアが閉じるまで駆動する。
async fn drive_until_closed(
    conn: &mut shiguredo_ngtcp2_tokio::AcceptedConnection,
    until_closed: bool,
) -> Echoed {
    let mut received = Vec::new();
    let mut path_validated = false;
    let mut echo_sent = false;
    loop {
        let event = conn
            .recv_event()
            .await
            .expect("サーバーがイベントを受信できること");
        match event {
            ConnectionEvent::StreamData {
                stream_id,
                data,
                fin,
            } => {
                // 処理し終えたデータの分だけフロー制御クレジットを戻す
                conn.extend_max_stream_offset(stream_id, data.len() as u64)
                    .expect("フロー制御クレジットを戻せること");
                received.extend_from_slice(&data);
                if fin {
                    echo_back(conn, stream_id, &received).await;
                    echo_sent = true;
                    if !until_closed {
                        break;
                    }
                }
            }
            // ピアが新しいアドレスから送ってきた経路の検証に成功した
            ConnectionEvent::PathValidated { success: true, .. } => path_validated = true,
            ConnectionEvent::ConnectionClosed { .. } => break,
            _ => {}
        }
    }

    Echoed {
        data: received,
        // データを受け取った時点の判定結果を接続から取り出す
        received_early_data: conn.received_early_data(),
        path_validated,
        echo_sent,
    }
}

/// 受け取ったデータを同じストリームに FIN 付きで書き戻す
async fn echo_back(
    conn: &mut shiguredo_ngtcp2_tokio::AcceptedConnection,
    stream_id: StreamId,
    data: &[u8],
) {
    conn.write_stream(stream_id, data, true)
        .expect("エコーを送信待ちに積めること");
    conn.flush().await.expect("エコーを送信できること");
}

/// 証明書検証を有効にしたクライアント設定を返す
///
/// `ca_cert_pem` をトラストストアに追加して自己署名証明書を検証する。検証を
/// 無効にすると TLS 統合の誤りを検出できなくなるため。
fn client_config(ca_cert_pem: &str) -> ClientConfig {
    ClientConfig::new(&[ALPN])
        .with_verify_peer(true)
        .with_ca_cert_pem(ca_cert_pem)
}

/// サーバーが返したデータを FIN まで読み切る
///
/// 受け取ったデータの ACK を返すため、最後に flush する。返さないとピアは
/// ストリームの完了 (FIN の ACK) を待ち続ける。
async fn read_until_fin(conn: &mut ClientConnection) -> Vec<u8> {
    let mut received = Vec::new();
    let mut fin = false;
    while !fin {
        let event = conn
            .recv_event()
            .await
            .expect("クライアントがイベントを受信できること");
        if let ConnectionEvent::StreamData {
            stream_id,
            data,
            fin: f,
        } = event
        {
            conn.extend_max_stream_offset(stream_id, data.len() as u64)
                .expect("フロー制御クレジットを戻せること");
            received.extend_from_slice(&data);
            fin = f;
        }
    }

    conn.flush().await.expect("ACK を送信できること");
    received
}

/// セッションチケットが届くまで接続を駆動する (RFC 8446 Section 4.6.1)
async fn fetch_session_ticket(conn: &mut ClientConnection) -> SessionTicket {
    loop {
        if let Some(ticket) = conn
            .take_session_ticket()
            .expect("セッション情報を取得できること")
        {
            return ticket;
        }
        // チケットはサーバーが自発的に送るため、イベントが無くてもパケットの
        // 処理は進む。ここではイベントを待つだけでよい
        conn.recv_event()
            .await
            .expect("クライアントがイベントを受信できること");
    }
}

/// 我々のクライアントで接続し、データを送ってエコーを受け取る
pub async fn client_roundtrip(
    server_addr: SocketAddr,
    ca_cert_pem: &str,
    payload: &[u8],
) -> Vec<u8> {
    let config = client_config(ca_cert_pem);
    let mut conn = Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &config)
        .await
        .expect("クライアントが接続できること");

    let stream_id = conn.open_bidi_stream().expect("ストリームを開けること");
    conn.write_stream(stream_id, payload, true)
        .expect("送信待ちに積めること");
    conn.flush().await.expect("データを送信できること");

    let echoed = read_until_fin(&mut conn).await;
    // quiche のサーバーが接続の終了を観測できるよう閉じる
    conn.close(0, b"done").await.expect("接続を閉じられること");
    echoed
}

/// 0-RTT (early data) の往復結果
pub struct EarlyDataEcho {
    /// サーバーが返したエコー
    pub echoed: Vec<u8>,
    /// サーバーが 0-RTT を受理したかどうか
    pub accepted: bool,
}

/// セッションチケットを取得してから 0-RTT で接続し、エコーを受け取る
///
/// 1 回目の接続でチケットを保存し、2 回目の接続でハンドシェイクの完了を
/// 待たずにデータを送る (RFC 9001 Section 4.6)。
pub async fn client_roundtrip_early_data(
    server_addr: SocketAddr,
    ca_cert_pem: &str,
    payload: &[u8],
) -> EarlyDataEcho {
    let config = client_config(ca_cert_pem);

    // 1 回目の接続でセッションチケットを取得する
    let mut conn = Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &config)
        .await
        .expect("1 回目の接続ができること");
    let ticket = fetch_session_ticket(&mut conn).await;
    conn.close(0, b"done")
        .await
        .expect("1 回目の接続を閉じられること");

    // 2 回目の接続でハンドシェイクの完了前にデータを送る
    let mut conn = Client::connect_with_early_data(
        server_addr,
        ephemeral_addr(),
        "localhost",
        &config,
        &ticket,
    )
    .await
    .expect("0-RTT で接続できること");
    assert!(
        conn.is_in_early_data(),
        "0-RTT を送れる状態であること (サーバーが early data を受理する設定)"
    );

    let stream_id = conn.open_bidi_stream().expect("ストリームを開けること");
    conn.write_stream(stream_id, payload, true)
        .expect("0-RTT のデータを送信待ちに積めること");
    conn.flush().await.expect("0-RTT のデータを送信できること");

    // ハンドシェイクの完了を待ち、0-RTT が受理されたかどうかを観測する
    while !conn.is_handshake_completed() {
        conn.recv_event()
            .await
            .expect("クライアントがイベントを受信できること");
    }
    let accepted = conn.is_early_data_accepted();

    let echoed = read_until_fin(&mut conn).await;
    conn.close(0, b"done")
        .await
        .expect("2 回目の接続を閉じられること");

    EarlyDataEcho { echoed, accepted }
}

/// 接続を維持したままローカルアドレスを変え、移った先の経路でエコーを受け取る
///
/// 経路の検証 (RFC 9000 Section 8.2) が完了してからデータを送るため、エコーが
/// 届けば移った先の経路がピアに受理されたことになる。
pub async fn client_roundtrip_with_migration(
    server_addr: SocketAddr,
    ca_cert_pem: &str,
    payload: &[u8],
) -> Vec<u8> {
    let config = client_config(ca_cert_pem);
    let mut conn = Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &config)
        .await
        .expect("クライアントが接続できること");

    // クライアントはハンドシェイクの確認 (HANDSHAKE_DONE) の後でなければ
    // マイグレーションを開始できない (RFC 9000 Section 9)
    loop {
        if let ConnectionEvent::HandshakeConfirmed = conn
            .recv_event()
            .await
            .expect("クライアントがイベントを受信できること")
        {
            break;
        }
    }

    // 新しいローカルアドレスへ移る。経路の検証は ngtcp2 が行う。
    //
    // ピアが発行した未使用のコネクション ID が届いていないと移れないため
    // (RFC 9000 Section 9.5)、イベントを処理しながら繰り返し試す。失敗しても
    // ソケットは差し替わらないので、やり直しても問題ない。
    let mut migrated = false;
    for _ in 0..10 {
        match conn.migrate(ephemeral_addr()).await {
            Ok(()) => {
                migrated = true;
                break;
            }
            Err(_) => {
                conn.recv_event()
                    .await
                    .expect("クライアントがイベントを受信できること");
            }
        }
    }
    assert!(migrated, "新しいローカルアドレスへ移れること");

    // 検証が完了するまで駆動する
    loop {
        match conn
            .recv_event()
            .await
            .expect("クライアントがイベントを受信できること")
        {
            ConnectionEvent::PathValidated { success: true, .. } => break,
            ConnectionEvent::PathValidated { success: false, .. } => {
                panic!("新しい経路の検証に失敗した")
            }
            _ => {}
        }
    }

    // 移った先の経路でデータを送る
    let stream_id = conn.open_bidi_stream().expect("ストリームを開けること");
    conn.write_stream(stream_id, payload, true)
        .expect("送信待ちに積めること");
    conn.flush().await.expect("データを送信できること");

    let echoed = read_until_fin(&mut conn).await;
    // quiche のサーバーが接続の終了を観測できるよう閉じる
    conn.close(0, b"done").await.expect("接続を閉じられること");
    echoed
}
