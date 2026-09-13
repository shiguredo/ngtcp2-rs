//! DATAGRAM の e2e テスト (RFC 9221)
//!
//! 実 UDP ソケットでクライアントとサーバーを接続し、DATAGRAM の送受信と
//! サイズ上限の検証を行う。

use std::time::Duration;

use shiguredo_ngtcp2::TransportParams;
use shiguredo_ngtcp2_tokio::{
    Client, ClientConfig, ConnectionEvent, DatagramConfig, Server, ServerConfig,
};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;
#[path = "helpers/events.rs"]
mod events;
#[path = "helpers/pair.rs"]
mod pair;

use certs::TestCert;
use events::is_connection_setup_event;
use pair::{Pair, bind_server, connect_with_server, ephemeral_addr};

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// DATAGRAM を有効にした設定でサーバーとクライアントを接続する
///
/// DATAGRAM は相互に `max_datagram_frame_size` を通知しないと送受信できない
/// (RFC 9221 Section 3) ため、両側のトランスポートパラメータで有効にする。
async fn connect_pair(cert: &TestCert, config: DatagramConfig) -> Pair {
    let transport_params = TransportParams::new().with_datagram(config.max_datagram_frame_size);
    let server_config = ServerConfig::new(&[b"hq-interop"])
        .with_transport_params(transport_params.clone())
        .with_datagram(config);
    let client_config = ClientConfig::new(&[b"hq-interop"])
        .with_verify_peer(false)
        .with_transport_params(transport_params)
        .with_datagram(config);

    let server = bind_server(cert.cert_path(), cert.key_path(), Some(server_config)).await;
    let (pair, _server) = connect_with_server(server, client_config, "localhost").await;
    pair
}

/// クライアントからサーバーへ DATAGRAM を送れること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_datagram_client_to_server() {
    let cert = TestCert::generate("datagram_c2s");
    let mut pair = connect_pair(&cert, DatagramConfig::default()).await;

    let result = timeout(TEST_TIMEOUT, async {
        assert!(
            pair.client.can_send_datagram(),
            "DATAGRAM を送信できる状態であること"
        );
        assert!(
            pair.server.can_send_datagram(),
            "サーバーも DATAGRAM を送信できる状態であること"
        );

        // 双方が自分の max_datagram_frame_size をピアに通知していること
        let expected = DatagramConfig::default().max_datagram_frame_size;
        assert_eq!(
            pair.client.local_max_datagram_frame_size(),
            expected,
            "クライアントの通知値が設定と一致すること"
        );
        assert_eq!(
            pair.server.local_max_datagram_frame_size(),
            expected,
            "サーバーの通知値が設定と一致すること"
        );
        assert_eq!(
            pair.client.remote_max_datagram_frame_size(),
            expected,
            "ピアの通知値が設定と一致すること"
        );

        pair.client
            .send_datagram(b"hello datagram")
            .await
            .expect("DATAGRAM を送信できること");

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
        match event {
            ConnectionEvent::Datagram { data } => {
                assert_eq!(data, b"hello datagram", "受信データが一致すること");
            }
            other => panic!("Datagram が届くこと: {other:?}"),
        }
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// サーバーからクライアントへ DATAGRAM を送れること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_datagram_server_to_client() {
    let cert = TestCert::generate("datagram_s2c");
    let mut pair = connect_pair(&cert, DatagramConfig::default()).await;

    let result = timeout(TEST_TIMEOUT, async {
        pair.server
            .send_datagram(b"from server")
            .await
            .expect("DATAGRAM を送信できること");

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
        match event {
            ConnectionEvent::Datagram { data } => {
                assert_eq!(data, b"from server", "受信データが一致すること");
            }
            other => panic!("Datagram が届くこと: {other:?}"),
        }
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 送信上限を超える DATAGRAM はエラーになること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_datagram_rejects_oversized() {
    let cert = TestCert::generate("datagram_oversize");
    let config = DatagramConfig {
        max_datagram_frame_size: 65535,
        max_tx_datagram_size: 100,
    };
    let mut pair = connect_pair(&cert, config).await;

    let result = timeout(TEST_TIMEOUT, async {
        // 上限内は成功する
        pair.client
            .send_datagram(&[0u8; 100])
            .await
            .expect("上限内の DATAGRAM は送信できること");

        // 上限を超えるとエラーになる
        let err = pair
            .client
            .send_datagram(&[0u8; 101])
            .await
            .expect_err("上限を超える DATAGRAM はエラーになること");
        assert!(
            matches!(err, shiguredo_ngtcp2::Error::InvalidArgument(_)),
            "InvalidArgument が返ること: {err:?}"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// DATAGRAM を無効にすると送信できないこと
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_datagram_disabled() {
    let cert = TestCert::generate("datagram_disabled");
    let mut pair = connect_pair(&cert, DatagramConfig::disabled()).await;

    let result = timeout(TEST_TIMEOUT, async {
        assert!(
            !pair.client.can_send_datagram(),
            "無効時は can_send_datagram が false であること"
        );
        assert!(!pair.server.can_send_datagram(), "サーバーも無効であること");
        assert_eq!(
            pair.client.local_max_datagram_frame_size(),
            0,
            "無効時は通知値が 0 であること"
        );

        // 送信を試みるとローカルの上限 0 で弾かれる
        let err = pair
            .client
            .send_datagram(b"x")
            .await
            .expect_err("無効時は送信できないこと");
        assert!(
            matches!(err, shiguredo_ngtcp2::Error::InvalidArgument(_)),
            "無効時は InvalidArgument が返ること: {err:?}"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// ピアが DATAGRAM を無効にしていると送信できないこと
///
/// RFC 9221 Section 3 により、DATAGRAM はピアが `max_datagram_frame_size` を
/// 通知しない限り送信できない。ここではサーバーだけ DATAGRAM を無効にして、
/// クライアントが ngtcp2 の INVALID_STATE を受け取ることを確認する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_datagram_rejected_when_peer_disabled() {
    let cert = TestCert::generate("datagram_peer_disabled");
    // サーバーは DATAGRAM を通知しない
    let mut server = Server::bind(
        ephemeral_addr(),
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"]).with_datagram(DatagramConfig::disabled())),
    )
    .await
    .expect("サーバーを起動できること");
    let addr = server.local_addr();

    let accept_task = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("accept が成功すること")
            .expect("接続が受け入れられること");
        (conn, server)
    });

    // クライアントは DATAGRAM を有効にする
    let client_config = ClientConfig::new(&[b"hq-interop"])
        .with_verify_peer(false)
        .with_datagram(DatagramConfig::default());

    let mut client = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(addr, ephemeral_addr(), "localhost", &client_config),
    )
    .await
    .expect("ハンドシェイクがタイムアウトしないこと")
    .expect("クライアントが接続できること");

    let (_server_conn, server) = timeout(TEST_TIMEOUT, accept_task)
        .await
        .expect("accept がタイムアウトしないこと")
        .expect("サーバータスクが完了すること");
    drop(server);

    // ハンドシェイク完了を消費する
    let _ = client.recv_event().await.expect("イベントを受信できること");

    let result = timeout(TEST_TIMEOUT, async {
        assert!(
            !client.can_send_datagram(),
            "ピアが無効なら can_send_datagram が false であること"
        );
        assert_eq!(
            client.remote_max_datagram_frame_size(),
            0,
            "ピアの max_datagram_frame_size は 0 であること"
        );

        let err = client
            .send_datagram(b"x")
            .await
            .expect_err("ピアが無効なら送信できないこと");
        assert!(
            matches!(err, shiguredo_ngtcp2::Error::Ngtcp2(_, _)),
            "ngtcp2 の INVALID_STATE が返ること: {err:?}"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 複数の DATAGRAM が順に届くこと
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multiple_datagrams() {
    let cert = TestCert::generate("datagram_multiple");
    let mut pair = connect_pair(&cert, DatagramConfig::default()).await;

    let result = timeout(TEST_TIMEOUT, async {
        for i in 0u8..3 {
            pair.client
                .send_datagram(&[i])
                .await
                .expect("DATAGRAM を送信できること");
        }

        let mut received = Vec::new();
        while received.len() < 3 {
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
            match event {
                ConnectionEvent::Datagram { data } => received.push(data[0]),
                other => panic!("Datagram が届くこと: {other:?}"),
            }
        }

        assert_eq!(received, vec![0, 1, 2], "送信順に届くこと");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// ピアのトランスポートパラメータを取得できること (RFC 9000 Section 18)
///
/// サーバー側で特徴的な値を設定し、クライアントがハンドシェイク後に
/// それをそのまま読めることを確認する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_remote_transport_params() {
    let cert = TestCert::generate("datagram_remote_params");

    // DATAGRAM の上限は DatagramConfig がトランスポートパラメータに反映される
    let datagram = DatagramConfig {
        max_datagram_frame_size: 4321,
        max_tx_datagram_size: 1200,
    };
    let server_params = TransportParams::new()
        .with_max_streams_bidi(21)
        .with_max_streams_uni(22)
        .with_initial_max_data(4 * 1024 * 1024)
        .with_initial_max_stream_data_uni(44_444)
        .with_max_idle_timeout(Duration::from_secs(45))
        .with_disable_active_migration(true);

    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(
            ServerConfig::new(&[b"hq-interop"])
                .with_transport_params(server_params)
                .with_datagram(datagram),
        ),
    )
    .await;
    let client_config = ClientConfig::new(&[b"hq-interop"])
        .with_verify_peer(false)
        .with_datagram(datagram);
    let (pair, _server) = connect_with_server(server, client_config, "localhost").await;

    let result = timeout(TEST_TIMEOUT, async {
        let remote = pair
            .client
            .remote_transport_params()
            .expect("クライアントがピアのパラメータを取得できること");
        assert_eq!(remote.initial_max_streams_bidi, 21, "max_streams_bidi");
        assert_eq!(remote.initial_max_streams_uni, 22, "max_streams_uni");
        assert_eq!(remote.initial_max_data, 4 * 1024 * 1024, "initial_max_data");
        assert_eq!(
            remote.initial_max_stream_data_uni, 44_444,
            "initial_max_stream_data_uni"
        );
        assert_eq!(
            remote.max_idle_timeout,
            Duration::from_secs(45),
            "max_idle_timeout"
        );
        assert!(
            remote.disable_active_migration,
            "disable_active_migration が伝わること"
        );
        assert_eq!(
            remote.max_datagram_frame_size, 4321,
            "DatagramConfig の値がトランスポートパラメータに反映されること"
        );
        assert_eq!(
            pair.client.remote_max_datagram_frame_size(),
            4321,
            "DATAGRAM の上限も同じ値を返すこと"
        );

        // サーバー側から見たクライアントのパラメータは既定値であること
        let client_remote = pair
            .server
            .remote_transport_params()
            .expect("サーバーがピアのパラメータを取得できること");
        assert_eq!(
            client_remote.initial_max_streams_bidi, 100,
            "クライアントの既定の max_streams_bidi"
        );
        assert_eq!(
            client_remote.max_datagram_frame_size, 4321,
            "クライアントも同じ DATAGRAM の上限を通知すること"
        );
        assert!(
            !client_remote.disable_active_migration,
            "クライアントはマイグレーションを無効にしていないこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}
