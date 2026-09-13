//! NEW_TOKEN の e2e テスト (RFC 9000 Section 8.1.3)
//!
//! サーバーはアドレスを検証できた接続に対して NEW_TOKEN フレームでトークンを
//! 配布する。クライアントは次の接続の Initial にトークンを載せることで、
//! サーバーの Retry を省略できる。トークンは配布したアドレスに束縛されるため、
//! 別のアドレスから提示すると拒否される。
//!
//! Retry を送ったかどうかは、サーバーが通知する `retry_source_connection_id`
//! (RFC 9000 Section 7.3) の有無で判定する。Retry を送った場合は必ず通知され、
//! 送っていない場合は通知されてはならない。

use std::net::SocketAddr;
use std::time::Duration;

use shiguredo_ngtcp2::{AddressValidationToken, RETRY_SECRET_LEN, RetrySecret};
use shiguredo_ngtcp2_tokio::{
    Client, ClientConfig, ClientConnection, ConnectionEvent, Server, ServerConfig,
};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;

use certs::TestCert;

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// テスト用の秘密
const RETRY_SECRET_BYTES: [u8; RETRY_SECRET_LEN] = [0x6e; 32];

/// `127.0.0.1` のエフェメラルポートのアドレス
fn ephemeral_addr() -> SocketAddr {
    "127.0.0.1:0".parse().expect("リテラルアドレスは有効")
}

/// 我々のサーバーを起動する
async fn bind_server(cert: &TestCert, config: ServerConfig) -> Server {
    Server::bind(
        ephemeral_addr(),
        cert.cert_path(),
        cert.key_path(),
        Some(config),
    )
    .await
    .expect("サーバーを起動できること")
}

/// Retry と NEW_TOKEN の配布を有効にしたサーバー設定を返す
fn new_token_server_config() -> ServerConfig {
    ServerConfig::new(&[b"hq-interop"])
        .with_retry(RetrySecret::from_bytes(RETRY_SECRET_BYTES))
        .with_new_token(true)
}

/// 証明書検証を無効にしたクライアント設定を返す
fn insecure_client_config() -> ClientConfig {
    ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false)
}

/// トークンを提示するクライアント設定を返す
fn client_config_with_token(token: &[u8]) -> ClientConfig {
    let mut config = insecure_client_config();
    config.settings.address_validation_token = AddressValidationToken::from_packet(token.to_vec());
    config
}

/// サーバーを駆動し続けるタスクを立てる
///
/// Retry も NEW_TOKEN もパケットの受信処理の中で扱われるため、`accept` を
/// 回し続ける。
fn spawn_server(mut server: Server) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let _ = server.accept().await;
        }
    })
}

/// サーバーが配布した NEW_TOKEN を受け取るまで接続を駆動する
///
/// NEW_TOKEN の受信はイベントとして通知されないため、パケットを処理しながら
/// 定期的に取り出しを試みる。
async fn wait_for_new_token(conn: &mut ClientConnection) -> Vec<u8> {
    loop {
        if let Some(token) = conn.take_new_token().expect("トークンを取り出せること") {
            return token;
        }
        // イベントが無くてもパケットの処理は進む
        match timeout(Duration::from_millis(20), conn.recv_event()).await {
            Ok(Ok(ConnectionEvent::ConnectionClosed { reason, .. })) => {
                panic!("NEW_TOKEN を受け取る前に接続が閉じられた: {reason}")
            }
            Ok(Err(e)) => panic!("NEW_TOKEN を受け取る前に接続が失敗した: {e}"),
            Ok(Ok(_)) | Err(_) => {}
        }
    }
}

/// NEW_TOKEN のトークンで Retry を省略できること (RFC 9000 Section 8.1.3)
///
/// トークンを持たない接続では Retry が返り、配布されたトークンを同じ
/// アドレスから提示すると Retry が省略される。トークンは配布した IP
/// アドレスに束縛される (ngtcp2 の実装) ため、別の IP から提示すると
/// 接続できない。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_new_token_skips_retry() {
    let cert = TestCert::generate("new_token");
    let server = bind_server(&cert, new_token_server_config()).await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        // 1 回目の接続: トークンを持たないため Retry が返る
        let mut first = Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &{
            insecure_client_config()
        })
        .await
        .expect("1 回目の接続ができること");
        assert!(
            first
                .remote_transport_params()
                .expect("トランスポートパラメータを取得できること")
                .retry_scid
                .is_some(),
            "トークンを持たない接続では Retry が返ること"
        );

        // サーバーが配布した NEW_TOKEN を受け取り、次の接続で使う
        let token = wait_for_new_token(&mut first).await;
        let first_addr = first.local_addr();
        first
            .close(0, b"done")
            .await
            .expect("1 回目の接続を閉じられること");
        // 同じアドレスを次の接続で使うためソケットを解放する
        drop(first);

        // 2 回目の接続: 同じアドレスからトークンを提示する
        let mut second = Client::connect_with_config(
            server_addr,
            first_addr,
            "localhost",
            &client_config_with_token(&token),
        )
        .await
        .expect("トークンを提示した接続ができること");
        assert!(
            second
                .remote_transport_params()
                .expect("トランスポートパラメータを取得できること")
                .retry_scid
                .is_none(),
            "NEW_TOKEN のトークンを提示した接続では Retry が返らないこと"
        );
        second
            .close(0, b"done")
            .await
            .expect("2 回目の接続を閉じられること");
        drop(second);

        // 3 回目の接続: トークンを別の IP アドレスから提示する。
        //
        // ngtcp2 のトークンは IP アドレスに束縛される (ポートは含まない)。
        // ポートが変わっても NAT による付け替えなどで正当に起こりうるため、
        // 別の IP アドレスを用意して拒否されることを確認する。
        let different_addr: std::net::SocketAddr =
            "127.0.0.2:0".parse().expect("テスト用アドレスは有効");
        let different = Client::connect_with_config(
            server_addr,
            different_addr,
            "localhost",
            &client_config_with_token(&token),
        )
        .await;
        assert!(
            different.is_err(),
            "トークンは配布した IP アドレスに束縛されるため、別の IP からは接続できないこと"
        );
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// サーバーが発行した NEW_TOKEN のトークンが同じ秘密で検証できること
///
/// クライアントが受け取るトークンは、サーバーが配布したものと同一の形式
/// (ngtcp2 の regular token) であることを確認する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_new_token_matches_server_secret() {
    let cert = TestCert::generate("new_token_secret");
    let server = bind_server(&cert, new_token_server_config()).await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let mut client =
            Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &{
                insecure_client_config()
            })
            .await
            .expect("接続ができること");
        let token = wait_for_new_token(&mut client).await;

        // サーバーと同じ秘密でトークンを検証できること
        shiguredo_ngtcp2::verify_new_token(
            &RetrySecret::from_bytes(RETRY_SECRET_BYTES),
            &token,
            client.local_addr(),
            Duration::from_secs(3600),
            // テストからサーバーと同じ時刻の基準を使えないため 0 を渡す。
            // ngtcp2 は「現在時刻 - 生成時刻 < 有効期間」だけを検査する
            // (生成時刻が 0 でも有効期間内であれば通る)。
            0,
        )
        .expect("サーバーが配布したトークンを同じ秘密で検証できること");

        client
            .close(0, b"done")
            .await
            .expect("接続を閉じられること");
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}
