//! 証明書検証の e2e テスト
//!
//! `verify_peer` による証明書チェーン検証と DNS 名 / IP SAN の照合を確認する
//! (RFC 9001 Section 4.4、RFC 9525 Section 6.4)。自己署名証明書を使うため、テストの実行順に
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
    start_server_on(cert, ephemeral_addr()).await
}

/// IPv4 / IPv6 の指定したアドレスでサーバーを起動する
async fn start_server_on(cert: &TestCert, local: SocketAddr) -> SocketAddr {
    let mut server = Server::bind(
        local,
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

/// IPv4 / IPv6 とも、信頼した証明書の iPAddress SAN が一致すれば接続できること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_verify_peer_succeeds_with_ip_san() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let local: SocketAddr = address.parse().expect("接続先アドレスが有効であること");
        let name = local.ip().to_string();
        // rcgen は IP 文字列から SAN iPAddress を生成する。DNS 名の SAN は含めない。
        let cert = TestCert::generate_with_names("cert_ip", &[&name]);
        let addr = start_server_on(&cert, local).await;
        let config = ClientConfig::new(&[b"hq-interop"])
            .with_verify_peer(true)
            .with_ca_cert_pem(cert.cert_pem());
        let mut client = timeout(
            TEST_TIMEOUT,
            Client::connect_with_config(addr, local, &name, &config),
        )
        .await
        .expect("ハンドシェイクがタイムアウトしないこと")
        .expect("IP SAN が一致すれば証明書検証が成功すること");
        assert!(client.is_handshake_completed(), "IP 直指定で接続できること");
        client.close(0, b"").await.expect("接続を閉じられること");
    }
}

/// IP SAN の不一致や欠落、未信頼の証明書を受け入れないこと
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_verify_peer_rejects_invalid_ip_identity() {
    for (san, name, trusted) in [
        ("127.0.0.2", "127.0.0.1", true),
        ("::2", "::1", true),
        ("localhost", "127.0.0.1", true),
        ("127.0.0.1", "127.0.0.1", false),
    ] {
        let cert = TestCert::generate_with_names("cert_ip_rejected", &[san]);
        let addr = start_server(&cert).await;
        let mut config = ClientConfig::new(&[b"hq-interop"])
            .with_verify_peer(true)
            .with_handshake_timeout(Duration::from_secs(2));
        if trusted {
            config = config.with_ca_cert_pem(cert.cert_pem());
        }
        let result = timeout(
            TEST_TIMEOUT,
            Client::connect_with_config(addr, ephemeral_addr(), name, &config),
        )
        .await
        .expect("テストがタイムアウトしないこと");
        // IP リテラルは引数として受理し、TLS の検証で接続を拒否しなければならない。
        assert!(
            matches!(result, Err(error) if !matches!(error, shiguredo_ngtcp2_tokio::Error::InvalidArgument(_))),
            "SAN の不一致、IP SAN の欠落、未信頼の証明書は TLS の検証で拒否すること"
        );
    }
}

/// 検証を無効にすると、DNS 名の自己署名証明書にも IP 直指定で接続できること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_verify_peer_disabled_accepts_ip_literal() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let local: SocketAddr = address.parse().expect("接続先アドレスが有効であること");
        let cert = TestCert::generate("cert_ip_insecure");
        let addr = start_server_on(&cert, local).await;
        let config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
        let mut client = timeout(
            TEST_TIMEOUT,
            Client::connect_with_config(addr, local, &local.ip().to_string(), &config),
        )
        .await
        .expect("ハンドシェイクがタイムアウトしないこと")
        .expect("検証を無効にした IP 接続が成功すること");
        client.close(0, b"").await.expect("接続を閉じられること");
    }
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
