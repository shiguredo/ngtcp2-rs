//! 証明書検証の e2e テスト
//!
//! `verify_peer` による証明書チェーン検証とホスト名検証を確認する
//! (RFC 9001 Section 4.4)。自己署名証明書を使うため、テストの実行順に
//! 依存しないよう直列化する。

use std::net::SocketAddr;
use std::time::Duration;

use serial_test::serial;
use shiguredo_ngtcp2_tokio::{Client, ClientConfig, Server, ServerConfig};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;

use certs::TestCert;

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// `127.0.0.1` のエフェメラルポートのアドレス
fn ephemeral_addr() -> SocketAddr {
    "127.0.0.1:0".parse().expect("リテラルアドレスは有効")
}

/// サーバーを起動してアドレスを返す
async fn start_server(cert: &TestCert) -> SocketAddr {
    let mut server = Server::bind(
        ephemeral_addr(),
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"])),
    )
    .await
    .expect("サーバーを起動できること");
    let addr = server.local_addr();

    tokio::spawn(async move {
        // 接続を 1 つ受け入れて駆動し続ける
        if let Ok(Some(mut conn)) = server.accept().await {
            let _ = conn.recv_event().await;
        }
    });

    addr
}

/// CA を登録した上で証明書検証が成功すること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_verify_peer_succeeds_with_trusted_ca() {
    let cert = TestCert::generate("cert_trusted");
    let addr = start_server(&cert).await;

    let config = ClientConfig::new(&[b"hq-interop"])
        .with_verify_peer(true)
        .with_ca_cert_pem(cert.cert_pem());

    let result = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(addr, ephemeral_addr(), "localhost", &config),
    )
    .await
    .expect("テストがタイムアウトしないこと");

    let mut client = result.expect("CA を登録すれば検証が成功すること");
    assert!(
        client.is_handshake_completed(),
        "ハンドシェイクが完了していること"
    );
    client.close(0, b"").await.expect("接続を閉じられること");
}

/// CA を登録していない場合は検証が失敗すること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_verify_peer_fails_without_ca() {
    let cert = TestCert::generate("cert_untrusted");
    let addr = start_server(&cert).await;

    // 自己署名証明書はデフォルトのトラストストアに含まれない。
    //
    // 検証に失敗すると ngtcp2 は接続エラーを返さずハンドシェイクが進まなく
    // なるため、タイムアウトとして現れる。テストを速くするため短くする。
    let config = ClientConfig::new(&[b"hq-interop"])
        .with_verify_peer(true)
        .with_handshake_timeout(Duration::from_secs(2));

    let result = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(addr, ephemeral_addr(), "localhost", &config),
    )
    .await
    .expect("テストがタイムアウトしないこと");

    assert!(
        result.is_err(),
        "信頼できない証明書ではハンドシェイクが失敗すること"
    );
}

/// ホスト名が証明書の SAN と一致しない場合は検証が失敗すること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_verify_peer_fails_on_hostname_mismatch() {
    let cert = TestCert::generate("cert_hostname");
    let addr = start_server(&cert).await;

    // CA は登録するが、証明書の SAN は localhost のみ。
    // 検証失敗はハンドシェイクのタイムアウトとして現れる。
    let config = ClientConfig::new(&[b"hq-interop"])
        .with_verify_peer(true)
        .with_ca_cert_pem(cert.cert_pem())
        .with_handshake_timeout(Duration::from_secs(2));

    let result = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(addr, ephemeral_addr(), "example.invalid", &config),
    )
    .await
    .expect("テストがタイムアウトしないこと");

    assert!(
        result.is_err(),
        "ホスト名が一致しなければハンドシェイクが失敗すること"
    );
}

/// 証明書検証を無効にすれば自己署名証明書でも接続できること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_verify_peer_disabled_accepts_self_signed() {
    let cert = TestCert::generate("cert_insecure");
    let addr = start_server(&cert).await;

    let config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);

    let result = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(addr, ephemeral_addr(), "localhost", &config),
    )
    .await
    .expect("テストがタイムアウトしないこと");

    let mut client = result.expect("検証なしなら接続できること");
    assert!(
        client.is_handshake_completed(),
        "ハンドシェイクが完了していること"
    );
    client.close(0, b"").await.expect("接続を閉じられること");
}

/// ALPN が一致しなければ検証を無効にしていても失敗すること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_alpn_mismatch_fails_even_without_verification() {
    let cert = TestCert::generate("cert_alpn");
    let addr = start_server(&cert).await;

    let config = ClientConfig::new(&[b"unknown-proto"])
        .with_verify_peer(false)
        .with_handshake_timeout(Duration::from_secs(3));

    let result = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(addr, ephemeral_addr(), "localhost", &config),
    )
    .await
    .expect("テストがタイムアウトしないこと");

    assert!(
        result.is_err(),
        "ALPN が一致しなければハンドシェイクが失敗すること"
    );
}
