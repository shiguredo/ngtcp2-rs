//! s2n-quic (AWS) との相互運用テスト
//!
//! s2n-quic は Rust で書かれた独立した QUIC 実装で、TLS には rustls + aws-lc-rs を
//! 使う。ngtcp2 とは別のコードでハンドシェイク・ストリーム・アドレス検証を
//! 実装しているため、ワイヤー上のやり取りが仕様どおりであることを検証できる。
//!
//! 検証する組み合わせ:
//!
//! - 我々のサーバー ← s2n-quic のクライアント
//! - 我々のサーバー (Retry 有効) ← s2n-quic のクライアント
//! - s2n-quic のサーバー ← 我々のクライアント

use std::net::SocketAddr;

use bytes::Bytes;
use shiguredo_ngtcp2::RetrySecret;
use shiguredo_ngtcp2_interop::{
    ALPN, TEST_TIMEOUT, TestCert, accept_and_echo, bind_server, client_roundtrip,
};
use shiguredo_ngtcp2_tokio::ServerConfig;
use tokio::time::timeout;

/// テスト用の Retry 秘密
const RETRY_SECRET_BYTES: [u8; shiguredo_ngtcp2::RETRY_SECRET_LEN] = [0x5a; 32];

/// s2n-quic のクライアントを構築する
///
/// 自己署名証明書をトラストアンカーとして追加するため、証明書検証は有効なまま
/// 接続する。ALPN は `hq-interop` を提示する。
fn s2n_quic_client(ca_cert_pem: &str) -> s2n_quic::Client {
    let tls = s2n_quic::provider::tls::rustls::client::Client::builder()
        .with_certificate(ca_cert_pem.to_string())
        .expect("自己署名証明書をトラストアンカーに追加できること")
        .with_application_protocols(std::iter::once(ALPN))
        .expect("ALPN を設定できること")
        .build()
        .expect("TLS 設定を構築できること");

    s2n_quic::Client::builder()
        .with_tls(tls)
        .expect("TLS を設定できること")
        .with_io("0.0.0.0:0")
        .expect("ローカルアドレスを設定できること")
        .start()
        .expect("s2n-quic のクライアントを起動できること")
}

/// s2n-quic のクライアントで接続し、双方向ストリームでデータを送受信する
///
/// 送信側を FIN で終端してから、サーバーが返すエコーを読み切る。
async fn s2n_quic_client_roundtrip(
    server_addr: SocketAddr,
    ca_cert_pem: &str,
    payload: &[u8],
) -> Vec<u8> {
    let client = s2n_quic_client(ca_cert_pem);

    let mut conn = client
        .connect(s2n_quic::client::Connect::new(server_addr).with_server_name("localhost"))
        .await
        .expect("s2n-quic のクライアントが接続できること");
    conn.keep_alive(true)
        .expect("keep-alive を有効にできること");

    let stream = conn
        .open_bidirectional_stream()
        .await
        .expect("双方向ストリームを開けること");
    let (mut receive, mut send) = stream.split();
    send.send(Bytes::copy_from_slice(payload))
        .await
        .expect("データを送信できること");
    // FIN を送る。`shutdown` はピアの ACK を待つため、テストでは待たない
    // (`finish` は送信バッファに積んですぐ戻る)
    send.finish().expect("FIN を送信できること");

    let mut received = Vec::new();
    while let Some(chunk) = receive.receive().await.expect("データを受信できること") {
        received.extend_from_slice(&chunk);
    }
    received
}

/// s2n-quic のサーバーを起動し、1 接続でエコーするタスクを立てる
///
/// 戻り値はサーバーのアドレスと、受け取ったデータを受け取るチャネル。
/// タスクの完了を待つのではなくチャネルでデータを渡すのは、s2n-quic の
/// `shutdown` がピアの ACK を待つため、クライアントが駆動を止めると
/// タスクが完了しないことがあるため。
async fn spawn_s2n_quic_server(
    cert: &TestCert,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let tls = s2n_quic::provider::tls::rustls::server::Server::builder()
        .with_certificate(cert.cert_pem().to_string(), cert.key_pem().to_string())
        .expect("証明書と秘密鍵を設定できること")
        .with_application_protocols(std::iter::once(ALPN))
        .expect("ALPN を設定できること")
        .build()
        .expect("TLS 設定を構築できること");

    let mut server = s2n_quic::Server::builder()
        .with_tls(tls)
        .expect("TLS を設定できること")
        .with_io("127.0.0.1:0")
        .expect("ローカルアドレスを設定できること")
        .start()
        .expect("s2n-quic のサーバーを起動できること");
    let addr = server
        .local_addr()
        .expect("サーバーのローカルアドレスを取得できること");

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut conn = server.accept().await.expect("接続が受け入れられること");
        let stream = conn
            .accept_bidirectional_stream()
            .await
            .expect("ストリームを受け入れられること")
            .expect("クライアントがストリームを開くこと");
        let (mut receive, mut send) = stream.split();

        let mut received = Vec::new();
        while let Some(chunk) = receive.receive().await.expect("データを受信できること")
        {
            received.extend_from_slice(&chunk);
        }
        // 受け取ったデータをテストへ渡してからエコーを返す
        let _ = tx.send(received.clone());

        send.send(Bytes::copy_from_slice(&received))
            .await
            .expect("エコーを送信できること");
        // FIN を送り、送信バッファが空になるまで待つ
        // (ピアの ACK を待つ `shutdown` は使わない。ACK が返らないと完了しない)
        send.finish().expect("FIN を送信できること");
        let _ = send.flush().await;
    });

    (addr, rx)
}

/// s2n-quic のクライアントが我々のサーバーとハンドシェイクし、ストリームを往復できること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_server_with_s2n_quic_client() {
    let cert = TestCert::generate("s2n_quic_client");
    let server = bind_server(&cert, None).await;
    let server_addr = server.local_addr();
    let server_task = tokio::spawn(accept_and_echo(server));

    let payload = b"s2n-quic client to ngtcp2 server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed = s2n_quic_client_roundtrip(server_addr, cert.ca_cert_pem(), payload).await;
        let received = server_task.await.expect("サーバータスクが完了すること");

        assert_eq!(
            received.data, payload,
            "s2n-quic のクライアントが送ったデータがサーバーに届くこと"
        );
        assert_eq!(
            echoed, payload,
            "サーバーが返したエコーが s2n-quic のクライアントに届くこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// s2n-quic のクライアントが Retry を処理して我々のサーバーと接続できること
/// (RFC 9000 Section 8.1.2)
///
/// s2n-quic は独立した実装の Retry トークンを検証できないため、ここでは
/// 我々のサーバーが返す Retry を s2n-quic が受理し、トークンを載せた Initial を
/// 送り直せることを検証する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_server_with_s2n_quic_client_retry() {
    let cert = TestCert::generate("s2n_quic_client_retry");
    let config = ServerConfig::new(&[ALPN]).with_retry(RetrySecret::from_bytes(RETRY_SECRET_BYTES));
    let server = bind_server(&cert, Some(config)).await;
    let server_addr = server.local_addr();
    let server_task = tokio::spawn(accept_and_echo(server));

    let payload = b"retry from ngtcp2 server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed = s2n_quic_client_roundtrip(server_addr, cert.ca_cert_pem(), payload).await;
        let received = server_task.await.expect("サーバータスクが完了すること");

        assert_eq!(received.data, payload, "Retry を挟んでもデータが届くこと");
        assert_eq!(echoed, payload, "Retry を挟んでもエコーが届くこと");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 我々のクライアントが s2n-quic のサーバーとハンドシェイクし、ストリームを往復できること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_client_with_s2n_quic_server() {
    let cert = TestCert::generate("s2n_quic_server");
    let (server_addr, server_received) = spawn_s2n_quic_server(&cert).await;

    let payload = b"ngtcp2 client to s2n-quic server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed = client_roundtrip(server_addr, cert.ca_cert_pem(), payload).await;
        let received = server_received
            .await
            .expect("s2n-quic のサーバーがデータを受け取ること");

        assert_eq!(
            received, payload,
            "ngtcp2 のクライアントが送ったデータが s2n-quic のサーバーに届くこと"
        );
        assert_eq!(
            echoed, payload,
            "s2n-quic のサーバーが返したエコーが届くこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}
