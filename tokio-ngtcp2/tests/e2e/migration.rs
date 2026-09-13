//! 接続マイグレーションの e2e テスト (RFC 9000 Section 9)
//!
//! 実 UDP ソケットでクライアントとサーバーを接続し、クライアントが
//! ローカルアドレスを変えても接続が維持されることを検証する。
//!
//! マイグレーション中は経路の検証 (PATH_CHALLENGE / PATH_RESPONSE) が
//! 双方向に進むため、**両側を同時に駆動する**必要がある。片側だけを
//! await すると検証がタイムアウトし、送信したいデータもパケットに載らない。

use std::time::Duration;

use shiguredo_ngtcp2_tokio::{ClientConfig, ConnectionEvent, ServerConfig, TransportParams};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;
#[path = "helpers/pair.rs"]
mod pair;
#[path = "helpers/pump.rs"]
mod pump;

use certs::TestCert;
use pair::{Pair, bind_server, connect_with_server, ephemeral_addr};
use pump::PUMP_INTERVAL;

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// データを送る側
#[derive(Clone, Copy)]
enum Sender {
    /// クライアントが送る
    Client,
    /// サーバーが送る
    Server,
}

/// クライアントとサーバーを接続する
async fn connect_pair(cert: &TestCert, server_config: Option<ServerConfig>) -> Pair {
    let server = bind_server(cert.cert_path(), cert.key_path(), server_config).await;
    let client_config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
    let (pair, _server) = connect_with_server(server, client_config, "localhost").await;
    pair
}

/// 両側を駆動しながら、クライアント側で条件を満たすイベントを待つ
async fn wait_client_event<F>(pair: &mut Pair, mut predicate: F) -> ConnectionEvent
where
    F: FnMut(&ConnectionEvent) -> bool,
{
    let Pair { server, client } = pair;
    loop {
        tokio::select! {
            event = client.recv_event() => {
                let event = event.expect("クライアントがイベントを受信できること");
                if predicate(&event) {
                    return event;
                }
            }
            // 相手側も駆動しないと経路の検証が進まない
            _ = timeout(PUMP_INTERVAL, server.recv_event()) => {}
        }
    }
}

/// 両側を駆動しながら、サーバー側で条件を満たすイベントを待つ
async fn wait_server_event<F>(pair: &mut Pair, mut predicate: F) -> ConnectionEvent
where
    F: FnMut(&ConnectionEvent) -> bool,
{
    let Pair { server, client } = pair;
    loop {
        tokio::select! {
            event = server.recv_event() => {
                let event = event.expect("サーバーがイベントを受信できること");
                if predicate(&event) {
                    return event;
                }
            }
            _ = timeout(PUMP_INTERVAL, client.recv_event()) => {}
        }
    }
}

/// ハンドシェイクの確認 (HANDSHAKE_DONE) を待つ
///
/// クライアントは確認後でなければマイグレーションを開始できない
/// (RFC 9000 Section 9)。HANDSHAKE_DONE はサーバーが送るため、
/// 待つ間は両側を駆動する必要がある。
async fn wait_handshake_confirmed(pair: &mut Pair) {
    let event = wait_client_event(pair, |event| {
        matches!(event, ConnectionEvent::HandshakeConfirmed)
    })
    .await;
    assert!(
        matches!(event, ConnectionEvent::HandshakeConfirmed),
        "ハンドシェイクが確認されること: {event:?}"
    );
}

/// 経路の検証が成功するまで両側を駆動する
async fn wait_path_validated(pair: &mut Pair) {
    let event = wait_client_event(pair, |event| {
        matches!(event, ConnectionEvent::PathValidated { .. })
    })
    .await;
    assert!(
        matches!(event, ConnectionEvent::PathValidated { success: true, .. }),
        "経路の検証に成功すること: {event:?}"
    );
}

/// ストリームを開いてデータを送り、相手側に届くまで両側を駆動する
///
/// マイグレーション直後は制御フレームが優先されてデータがパケットに
/// 載らないことがあるため、届くまで駆動を繰り返す。
async fn send_and_receive(pair: &mut Pair, sender: Sender, payload: &[u8]) -> Vec<u8> {
    let stream_id = match sender {
        Sender::Client => pair.client.open_bidi_stream(),
        Sender::Server => pair.server.open_bidi_stream(),
    }
    .expect("ストリームを開けること");

    match sender {
        Sender::Client => pair.client.write_stream(stream_id, payload, true),
        Sender::Server => pair.server.write_stream(stream_id, payload, true),
    }
    .expect("送信待ちに積めること");

    let mut received = Vec::new();
    let mut fin = false;
    while !fin {
        let event = match sender {
            Sender::Client => {
                wait_server_event(pair, |event| {
                    matches!(event, ConnectionEvent::StreamData { .. })
                })
                .await
            }
            Sender::Server => {
                wait_client_event(pair, |event| {
                    matches!(event, ConnectionEvent::StreamData { .. })
                })
                .await
            }
        };
        if let ConnectionEvent::StreamData { data, fin: f, .. } = event {
            received.extend_from_slice(&data);
            fin = f;
        }
    }
    received
}

/// マイグレーション後も双方向でデータが流れることを確かめる
async fn assert_connection_works(pair: &mut Pair) {
    let received = send_and_receive(pair, Sender::Client, b"after migration").await;
    assert_eq!(
        received, b"after migration",
        "マイグレーション後もクライアントからデータが届くこと"
    );

    let reply = send_and_receive(pair, Sender::Server, b"reply").await;
    assert_eq!(
        reply, b"reply",
        "マイグレーション後もサーバーからデータが届くこと"
    );
}

/// クライアントがローカルアドレスを変えても接続が維持され、データが流れること
///
/// クライアントは新しいローカルアドレスへ即座にマイグレーションし、
/// サーバーは新しい送信元アドレスからのパケットを経路検証して受け入れる。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_client_migration_keeps_connection() {
    let cert = TestCert::generate("migration");
    let mut pair = connect_pair(&cert, None).await;

    let result = timeout(TEST_TIMEOUT, async {
        wait_handshake_confirmed(&mut pair).await;

        let before = pair.client.local_addr();
        pair.client
            .migrate(ephemeral_addr())
            .await
            .expect("マイグレーションを開始できること");

        assert_ne!(
            pair.client.local_addr(),
            before,
            "クライアントのローカルアドレスが変わること"
        );

        wait_path_validated(&mut pair).await;

        // マイグレーション後もデータが流れること
        assert_connection_works(&mut pair).await;

        // サーバーは新しい送信元アドレスを接続の経路として認識すること
        assert_eq!(
            pair.server.remote_addr(),
            pair.client.local_addr(),
            "サーバーが新しい送信元アドレスを認識すること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// ピアがマイグレーションを無効にしている場合はマイグレーションできないこと
/// (RFC 9000 Section 18.2)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_migration_is_rejected_when_disabled_by_peer() {
    let cert = TestCert::generate("migration_disabled");
    // サーバーが disable_active_migration を通知する
    let config = ServerConfig::new(&[b"hq-interop"])
        .with_transport_params(TransportParams::new().with_disable_active_migration(true));
    let mut pair = connect_pair(&cert, Some(config)).await;

    let result = timeout(TEST_TIMEOUT, async {
        wait_handshake_confirmed(&mut pair).await;

        let before = pair.client.local_addr();
        assert!(
            pair.client.migrate(ephemeral_addr()).await.is_err(),
            "ピアが無効にしている場合はマイグレーションできないこと"
        );

        // 失敗しても元の経路で接続が使えること
        assert!(
            !pair.client.is_closed(),
            "マイグレーションの失敗で接続が閉じないこと"
        );

        let received = send_and_receive(&mut pair, Sender::Client, b"still alive").await;
        assert_eq!(received, b"still alive", "元の経路でデータが届くこと");
        assert_eq!(
            pair.server.remote_addr(),
            before,
            "経路が変わっていないこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// マイグレーション後も接続を駆動し続けても生きていること
///
/// 経路の検証が完了するまでの間、両側が送受信を続けられることを確認する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_migration_connection_survives_pumping() {
    let cert = TestCert::generate("migration_pump");
    let mut pair = connect_pair(&cert, None).await;

    let result = timeout(TEST_TIMEOUT, async {
        wait_handshake_confirmed(&mut pair).await;

        pair.client
            .migrate(ephemeral_addr())
            .await
            .expect("マイグレーションを開始できること");

        // 両側を交互に駆動して経路の検証と再送を進める
        for _ in 0..8 {
            let _ = timeout(PUMP_INTERVAL, pair.server.recv_event()).await;
            let _ = timeout(PUMP_INTERVAL, pair.client.recv_event()).await;
        }

        assert!(
            !pair.client.is_closed() && !pair.server.is_closed(),
            "マイグレーション後も接続が生きていること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}
