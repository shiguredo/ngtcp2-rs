//! ハンドシェイクの e2e テスト
//!
//! 実 UDP ソケットでクライアントとサーバーを接続し、ハンドシェイクが
//! 完了することと、ALPN の不一致で失敗することを検証する。

use std::time::Duration;

use shiguredo_ngtcp2::Error;
use shiguredo_ngtcp2_tokio::{Client, ClientConfig, ConnectionEvent, Server, ServerConfig};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;
#[path = "helpers/pair.rs"]
mod pair;

use certs::TestCert;
use pair::{Pair, bind_server, connect_with_server, ephemeral_addr};

/// テスト用のクライアント設定を返す (証明書検証なし)
fn insecure_client_config() -> ClientConfig {
    ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false)
}

/// サーバーを起動してアドレスを返す
async fn start_server(cert: &TestCert, config: Option<ServerConfig>) -> std::net::SocketAddr {
    let mut server = Server::bind(
        "127.0.0.1:0".parse().expect("テスト用アドレスは有効"),
        cert.cert_path(),
        cert.key_path(),
        config,
    )
    .await
    .expect("サーバーを起動できること");
    let addr = server.local_addr();

    tokio::spawn(async move {
        // 接続を 1 つ受け入れたら、以降も poll し続けてクライアントの
        // パケット (ACK など) に応答する
        if let Ok(Some(mut conn)) = server.accept().await {
            loop {
                match conn.recv_event().await {
                    Ok(ConnectionEvent::ConnectionClosed { .. }) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    });

    addr
}

/// クライアントがサーバーに接続してハンドシェイクが完了すること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_handshake_completes() {
    let cert = TestCert::generate("handshake");
    let server_addr = start_server(&cert, None).await;

    let result = timeout(Duration::from_secs(15), async {
        let mut client = Client::connect(server_addr, "localhost")
            .await
            .expect("クライアントが接続できること");
        assert!(
            client.is_handshake_completed(),
            "ハンドシェイクが完了していること"
        );
        assert!(!client.is_closed(), "接続が閉じていないこと");
        assert_eq!(client.remote_addr(), server_addr, "リモートアドレス");
        assert_ne!(
            client.local_addr().port(),
            0,
            "ローカルアドレスが割り当てられていること"
        );

        // 正常に閉じられること
        client
            .close(0, b"done")
            .await
            .expect("接続を閉じられること");
        assert!(client.is_closed(), "close 後は閉じていること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// クライアントとサーバーの両方でハンドシェイク完了イベントが届くこと
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_handshake_event_on_both_sides() {
    let cert = TestCert::generate("handshake_event");
    let mut server = Server::bind(
        "127.0.0.1:0".parse().expect("テスト用アドレスは有効"),
        cert.cert_path(),
        cert.key_path(),
        None,
    )
    .await
    .expect("サーバーを起動できること");
    let server_addr = server.local_addr();

    let server_task = tokio::spawn(async move {
        let mut conn = server
            .accept()
            .await
            .expect("accept が成功すること")
            .expect("接続が受け入れられること");

        // ハンドシェイク完了イベントが届くこと
        let event = conn.recv_event().await.expect("イベントを受信できること");
        let handshake_seen = matches!(event, ConnectionEvent::HandshakeCompleted);
        assert!(handshake_seen, "サーバー側で HandshakeCompleted が届くこと");
        assert_eq!(conn.connection_id().len(), 16, "SCID 長");
    });

    let result = timeout(Duration::from_secs(15), async {
        let mut client = Client::connect(server_addr, "localhost")
            .await
            .expect("クライアントが接続できること");
        // クライアントは connect の中でハンドシェイクを完了するため、
        // イベントキューに HandshakeCompleted が残っている
        let event = client.recv_event().await.expect("イベントを受信できること");
        assert!(
            matches!(event, ConnectionEvent::HandshakeCompleted),
            "クライアント側で HandshakeCompleted が届くこと: {event:?}"
        );
        client.close(0, b"").await.expect("接続を閉じられること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
    server_task.await.expect("サーバータスクが完了すること");
}

/// ALPN が一致しない場合はハンドシェイクが失敗すること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_handshake_fails_on_alpn_mismatch() {
    let cert = TestCert::generate("alpn_mismatch");
    // サーバーは hq-interop のみを受け付ける
    let server_addr = start_server(&cert, Some(ServerConfig::new(&[b"hq-interop"]))).await;

    // クライアントは別の ALPN を提示する
    let config = ClientConfig::new(&[b"unknown-proto"])
        .with_verify_peer(false)
        .with_handshake_timeout(Duration::from_secs(5));

    let result = timeout(Duration::from_secs(15), async {
        Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &config).await
    })
    .await;

    let outcome = result.expect("テストがタイムアウトしないこと");
    assert!(
        outcome.is_err(),
        "ALPN 不一致ではハンドシェイクが失敗すること"
    );
}

/// 接続先が存在しない場合はハンドシェイクがタイムアウトすること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_handshake_timeout() {
    // 応答しないアドレスに接続する (誰もバインドしていないポート)
    let dead_addr: std::net::SocketAddr = "127.0.0.1:1".parse().expect("テスト用アドレスは有効");

    let config = insecure_client_config().with_handshake_timeout(Duration::from_millis(500));

    let start = std::time::Instant::now();
    let result = timeout(
        Duration::from_secs(15),
        Client::connect_with_config(dead_addr, ephemeral_addr(), "localhost", &config),
    )
    .await
    .expect("テストがタイムアウトしないこと");

    assert!(result.is_err(), "応答がなければエラーになること");
    assert!(
        start.elapsed() >= Duration::from_millis(400),
        "タイムアウトまで待つこと: {:?}",
        start.elapsed()
    );

    // 内部エラーとしてタイムアウトが報告されること
    match result.err().expect("エラーになること") {
        Error::Internal(msg) => {
            assert!(
                msg.contains("timeout"),
                "タイムアウトのメッセージであること: {msg}"
            );
        }
        other => panic!("Internal エラーになること: {other:?}"),
    }
}

/// サーバーとクライアントを接続する
async fn connect_pair(
    cert: &TestCert,
    server_config: Option<ServerConfig>,
    client_config: ClientConfig,
) -> Pair {
    let server = bind_server(cert.cert_path(), cert.key_path(), server_config).await;
    let (pair, _server) = connect_with_server(server, client_config, "localhost").await;
    pair
}

/// 交渉された ALPN を両側で取得できること (RFC 7301 Section 3)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_alpn_negotiated_on_both_sides() {
    let cert = TestCert::generate("alpn_negotiated");
    let pair = connect_pair(
        &cert,
        Some(ServerConfig::new(&[b"hq-interop"])),
        ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false),
    )
    .await;

    let result = timeout(Duration::from_secs(15), async {
        assert_eq!(
            pair.client.selected_alpn_protocol().as_deref(),
            Some(b"hq-interop".as_slice()),
            "クライアントが交渉結果を取得できること"
        );
        assert_eq!(
            pair.server.selected_alpn_protocol().as_deref(),
            Some(b"hq-interop".as_slice()),
            "サーバーが交渉結果を取得できること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// ALPN はサーバーの登録順で選ばれること
///
/// クライアントが複数のプロトコルを提示した場合、サーバーは自分の登録順で
/// 最初に一致したものを選ぶ (RFC 7301 Section 3.2)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_alpn_server_preference_wins() {
    let cert = TestCert::generate("alpn_preference");
    // サーバーは hq-interop を先に登録し、クライアントは h3 を先に提示する
    let pair = connect_pair(
        &cert,
        Some(ServerConfig::new(&[b"hq-interop", b"h3"])),
        ClientConfig::new(&[b"h3", b"hq-interop"]).with_verify_peer(false),
    )
    .await;

    let result = timeout(Duration::from_secs(15), async {
        assert_eq!(
            pair.server.selected_alpn_protocol().as_deref(),
            Some(b"hq-interop".as_slice()),
            "サーバーの登録順が優先されること"
        );
        assert_eq!(
            pair.client.selected_alpn_protocol().as_deref(),
            Some(b"hq-interop".as_slice()),
            "クライアントにも同じ結果が伝わること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 共通の ALPN が 1 つだけの場合はそれが選ばれること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_alpn_single_common_protocol() {
    let cert = TestCert::generate("alpn_single");
    // サーバーは複数登録し、クライアントは h3 しか提示しない
    let pair = connect_pair(
        &cert,
        Some(ServerConfig::new(&[b"hq-interop", b"h3"])),
        ClientConfig::new(&[b"h3"]).with_verify_peer(false),
    )
    .await;

    let result = timeout(Duration::from_secs(15), async {
        assert_eq!(
            pair.server.selected_alpn_protocol().as_deref(),
            Some(b"h3".as_slice()),
            "共通のプロトコルが選ばれること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}
