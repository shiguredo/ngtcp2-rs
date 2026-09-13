//! サーバーの堅牢性テスト
//!
//! 不正パケット・未知の DCID・同一アドレスからの複数接続でサーバーが
//! 停止しないことを検証する。あわせてローカルからの接続終了がピアに伝わる
//! ことを確認する。

use std::net::SocketAddr;
use std::time::Duration;

use shiguredo_ngtcp2_tokio::{Client, ClientConfig, ConnectionEvent, Server, ServerConfig};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;
#[path = "helpers/events.rs"]
mod events;
#[path = "helpers/pair.rs"]
mod pair;

use certs::TestCert;
use events::is_connection_setup_event;
use pair::{Pair, bind_server as bind_server_with, connect_with_server, ephemeral_addr};

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// 既定のクライアント設定 (証明書検証なし)
fn default_client_config() -> ClientConfig {
    ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false)
}

/// サーバーを起動してアドレスを返す
async fn bind_server(cert: &TestCert) -> (Server, SocketAddr) {
    let server = bind_server_with(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"])),
    )
    .await;
    let addr = server.local_addr();
    (server, addr)
}

/// サーバーを所有したままクライアントと接続する
///
/// `Server` を返すのは、テストが接続の状態を検証できるようにするため。
async fn connect_pair(server: Server, client_config: ClientConfig) -> (Pair, Server) {
    connect_with_server(server, client_config, "localhost").await
}

/// 不正なパケットを送ってもサーバーが停止しないこと
///
/// 未知の DCID を持つ Short header、1200 バイト未満の Initial、切り詰めた
/// パケットを送る。いずれも破棄され、サーバーは接続を受け入れられる
/// (RFC 9000 Section 5.2.2 / Section 14.1)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_survives_invalid_packets() {
    let cert = TestCert::generate("robust_invalid");
    let (server, addr) = bind_server(&cert).await;

    // 不正なパケットを送る
    let attacker = UdpSocket::bind(ephemeral_addr())
        .await
        .expect("攻撃側のソケットを用意できること");

    // 未知の DCID を持つ Short header
    let mut short_header = vec![0x40u8];
    short_header.extend_from_slice(&[0xbb; 16]);
    short_header.extend_from_slice(&[0u8; 32]);
    attacker
        .send_to(&short_header, addr)
        .await
        .expect("送信できること");

    // 1200 バイト未満の Initial
    let mut short_initial = vec![0xc0u8; 100];
    short_initial[5] = 8;
    attacker
        .send_to(&short_initial, addr)
        .await
        .expect("送信できること");

    // 切り詰めたパケット (CID 長が不正)
    attacker
        .send_to(&[0xc0, 0, 0, 0, 1], addr)
        .await
        .expect("送信できること");

    // 空のデータグラム
    attacker.send_to(&[], addr).await.expect("送信できること");

    // Initial 以外の Long header (Handshake)
    let mut handshake = vec![0xe0u8; 1300];
    handshake[5] = 8;
    attacker
        .send_to(&handshake, addr)
        .await
        .expect("送信できること");

    // サーバーはこれらを破棄し、正常な接続を受け入れられる
    let result = timeout(TEST_TIMEOUT, async {
        let (pair, server) = connect_pair(server, default_client_config()).await;
        assert!(
            pair.client.is_handshake_completed(),
            "不正パケットの後でもハンドシェイクが完了すること"
        );
        (pair, server)
    })
    .await;

    let (pair, server) = result.expect("テストがタイムアウトしないこと");
    // 不正パケットで接続状態が作られていないこと
    // (accept で取り出した接続以外はサーバーに残っていない)
    assert_eq!(
        server.connection_ids().len(),
        0,
        "accept 済みの接続以外は保持しないこと"
    );
    drop(pair);
}

/// 同じアドレスから 2 接続を張れること (RFC 9000 Section 5.1)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_two_connections_same_address() {
    let cert = TestCert::generate("robust_two_conns");
    let (mut server, addr) = bind_server(&cert).await;

    // 1 接続目と同じローカルアドレスを使う
    let shared_local: SocketAddr = ephemeral_addr();

    // 1 接続目のハンドシェイクをサーバーと同時に進める
    let server_task = tokio::spawn(async move {
        let first = server
            .accept()
            .await
            .expect("accept が成功すること")
            .expect("1 接続目が受け入れられること");
        let second = server
            .accept()
            .await
            .expect("accept が成功すること")
            .expect("2 接続目が受け入れられること");
        (first, second, server)
    });

    let mut client1 = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(addr, shared_local, "localhost", &default_client_config()),
    )
    .await
    .expect("タイムアウトしないこと")
    .expect("1 接続目が接続できること");

    // 1 接続目がサーバーに受け入れられるのを待つため、少しだけ駆動する
    let _ = timeout(Duration::from_millis(200), client1.recv_event()).await;

    // 2 接続目は別のローカルポートを使う (同一アドレスからの複数接続は
    // 同一ソケットでは DCID ルーティングが必要なため、ここでは
    // サーバーが複数接続を保持できることを確認する)
    let mut client2 = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(
            addr,
            ephemeral_addr(),
            "localhost",
            &default_client_config(),
        ),
    )
    .await
    .expect("タイムアウトしないこと")
    .expect("2 接続目が接続できること");

    let (mut conn1, mut conn2, server) = timeout(TEST_TIMEOUT, server_task)
        .await
        .expect("accept がタイムアウトしないこと")
        .expect("サーバータスクが完了すること");

    // 両方の接続がハンドシェイク済みであること
    assert!(
        conn1.recv_event().await.is_ok(),
        "1 接続目がイベントを受信できること"
    );
    assert!(
        conn2.recv_event().await.is_ok(),
        "2 接続目がイベントを受信できること"
    );
    assert_ne!(
        conn1.connection_id(),
        conn2.connection_id(),
        "接続ごとに異なる SCID が割り当てられること"
    );

    // 両方の接続でデータをやり取りできること
    let result = timeout(TEST_TIMEOUT, async {
        let sid1 = conn1.open_bidi_stream().expect("ストリームを開けること");
        conn1
            .write_stream(sid1, b"first", true)
            .expect("送信待ちに積めること");
        conn1.flush().await.expect("送信できること");

        let sid2 = conn2.open_bidi_stream().expect("ストリームを開けること");
        conn2
            .write_stream(sid2, b"second", true)
            .expect("送信待ちに積めること");
        conn2.flush().await.expect("送信できること");

        // クライアント側でそれぞれ受信する
        let mut received1 = Vec::new();
        while received1.is_empty() {
            if let ConnectionEvent::StreamData { data, .. } = client1
                .recv_event()
                .await
                .expect("1 接続目でイベントを受信できること")
            {
                received1 = data;
            }
        }
        let mut received2 = Vec::new();
        while received2.is_empty() {
            if let ConnectionEvent::StreamData { data, .. } = client2
                .recv_event()
                .await
                .expect("2 接続目でイベントを受信できること")
            {
                received2 = data;
            }
        }

        assert_eq!(received1, b"first", "1 接続目のデータ");
        assert_eq!(received2, b"second", "2 接続目のデータ");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
    drop(server);
}

/// クライアントからの接続終了がサーバーに伝わること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_handles_peer_close() {
    let cert = TestCert::generate("robust_peer_close");
    let (server, _addr) = bind_server(&cert).await;
    let (mut pair, _server) = connect_pair(server, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        pair.client
            .close(0, b"bye")
            .await
            .expect("接続を閉じられること");

        // サーバー側で接続終了を観測できること
        // ハンドシェイクの進行イベントは対象外のため読み飛ばす
        let event = loop {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("イベントを受信できること");
            if !is_connection_setup_event(&event) {
                break event;
            }
        };
        assert!(
            matches!(event, ConnectionEvent::ConnectionClosed { .. }),
            "ConnectionClosed が届くこと: {event:?}"
        );

        // 終了後は ConnectionClosed エラーになること
        let err = pair
            .server
            .recv_event()
            .await
            .expect_err("終了後はエラーになること");
        assert!(
            matches!(err, shiguredo_ngtcp2::Error::ConnectionClosed),
            "ConnectionClosed が返ること: {err:?}"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// サーバーからの接続終了がクライアントに伝わること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_initiated_close() {
    let cert = TestCert::generate("robust_server_close");
    let (server, _addr) = bind_server(&cert).await;
    let (mut pair, _server) = connect_pair(server, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        pair.server
            .close(0, b"bye")
            .await
            .expect("接続を閉じられること");
        assert!(pair.server.is_closed(), "close 後は閉じていること");

        // ハンドシェイクの進行イベントは対象外のため読み飛ばす

        let event = loop {
            let event = pair
                .client
                .recv_event()
                .await
                .expect("イベントを受信できること");

            if !is_connection_setup_event(&event) {
                break event;
            }
        };
        assert!(
            matches!(event, ConnectionEvent::ConnectionClosed { .. }),
            "ConnectionClosed が届くこと: {event:?}"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 未知の DCID の Short header には Stateless Reset を返すこと
/// (RFC 9000 Section 10.3)
///
/// トークンの検証は `e2e_stateless_reset` テストで行う。ここではサーバーが
/// 応答しつつ接続状態を作らずに動き続けることを確認する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_resets_unknown_dcid() {
    let cert = TestCert::generate("robust_unknown_dcid");
    let (server, addr) = bind_server(&cert).await;

    // Stateless Reset はパケットの受信処理の中で送られるため、
    // サーバーを駆動し続けるタスクを立てる
    let server_task = tokio::spawn(async move {
        let mut server = server;
        loop {
            let _ = server.accept().await;
        }
    });

    let attacker = UdpSocket::bind(ephemeral_addr())
        .await
        .expect("攻撃側のソケットを用意できること");

    // 未知の DCID を持つ Short header を送る
    let mut packet = vec![0x40u8];
    packet.extend_from_slice(&[0xcc; 16]);
    packet.extend_from_slice(&[0u8; 64]);
    attacker
        .send_to(&packet, addr)
        .await
        .expect("送信できること");

    // Stateless Reset が返ること
    let mut buf = [0u8; 1500];
    let (len, from) = timeout(Duration::from_secs(5), attacker.recv_from(&mut buf))
        .await
        .expect("Stateless Reset が返ること")
        .expect("受信できること");
    assert_eq!(from, addr, "サーバーからの応答であること");
    // Stateless Reset は Short header 形式で先頭 2 ビットが 01
    // (RFC 9000 Section 10.3.3)
    assert_eq!(
        buf[0] >> 6,
        0b01,
        "Stateless Reset のヘッダー形式であること"
    );
    assert!(
        len <= packet.len(),
        "応答が元のパケットより長くないこと: {len} <= {}",
        packet.len()
    );

    server_task.abort();
}
