//! クライアントとサーバーを接続するヘルパー
//!
//! `Server::accept` と `Client::connect_with_config` は互いにパケットを
//! やり取りするため、同時に駆動する必要がある。片方だけを await すると
//! ハンドシェイクが進まない。この手順は複数の e2e テストで共通のため
//! ここにまとめる。
//!
//! このファイルは複数のテストバイナリから `#[path]` で取り込まれるため、
//! どのバイナリでも全ての項目を使うこと (未使用の項目は dead code として
//! 警告になり、CI の `-D warnings` で失敗する)。

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use shiguredo_ngtcp2_tokio::{
    AcceptedConnection, Client, ClientConfig, ClientConnection, ConnectionEvent, Server,
    ServerConfig,
};
use tokio::time::timeout;

/// 接続確立に許すタイムアウト
const PAIR_TIMEOUT: Duration = Duration::from_secs(20);

/// `127.0.0.1` のエフェメラルポートのアドレス
pub(crate) fn ephemeral_addr() -> SocketAddr {
    "127.0.0.1:0".parse().expect("リテラルアドレスは有効")
}

/// 接続済みのクライアントとサーバー
pub(crate) struct Pair {
    /// サーバー側の接続ハンドル
    pub(crate) server: AcceptedConnection,
    /// クライアント側の接続
    pub(crate) client: ClientConnection,
}

/// エフェメラルポートにサーバーをバインドする
pub(crate) async fn bind_server(
    cert_path: &Path,
    key_path: &Path,
    config: Option<ServerConfig>,
) -> Server {
    Server::bind(ephemeral_addr(), cert_path, key_path, config)
        .await
        .expect("サーバーを起動できること")
}

/// 起動済みのサーバーにクライアントを接続する
///
/// ハンドシェイク完了後に両側の `HandshakeCompleted` を消費した状態で返す。
/// サーバー本体も返すのは、`Server::connection_ids` などでサーバーの状態を
/// 検証したいテストがあるため。不要な場合はそのまま破棄してよい
/// (接続ハンドルがソケットを `Arc` で共有している)。
pub(crate) async fn connect_with_server(
    mut server: Server,
    client_config: ClientConfig,
    server_name: &str,
) -> (Pair, Server) {
    let addr = server.local_addr();

    // サーバーを別タスクで駆動し、1 接続を受け入れる
    let accept_task = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("accept が成功すること")
            .expect("接続が受け入れられること");
        (conn, server)
    });

    let mut client = timeout(
        PAIR_TIMEOUT,
        Client::connect_with_config(addr, ephemeral_addr(), server_name, &client_config),
    )
    .await
    .expect("ハンドシェイクがタイムアウトしないこと")
    .expect("クライアントが接続できること");

    let (mut server_conn, server) = timeout(PAIR_TIMEOUT, accept_task)
        .await
        .expect("accept がタイムアウトしないこと")
        .expect("サーバータスクが完了すること");

    // 両側の HandshakeCompleted を消費する
    // (recv_event はハンドシェイク完了後に 1 回だけこのイベントを返す)
    for (label, event) in [
        (
            "client",
            client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること"),
        ),
        (
            "server",
            server_conn
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること"),
        ),
    ] {
        assert!(
            matches!(event, ConnectionEvent::HandshakeCompleted),
            "{label} に HandshakeCompleted が届くこと: {event:?}"
        );
    }

    (
        Pair {
            server: server_conn,
            client,
        },
        server,
    )
}
