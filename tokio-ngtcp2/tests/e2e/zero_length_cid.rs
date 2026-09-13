//! 長さ 0 のコネクション ID (RFC 9000 Section 5.1) の e2e テスト
//!
//! サーバーが長さ 0 のコネクション ID を使う場合、パケットにはコネクション ID が
//! 載らないため、サーバーはピアのアドレスでパケットを接続へ振り分ける。
//! クライアントはサーバーの SCID が長さ 0 でもそのまま接続できる。

use std::time::Duration;

use shiguredo_ngtcp2::{RetrySecret, TransportParams};
use shiguredo_ngtcp2_tokio::{ClientConfig, ConnectionEvent, DatagramConfig, ServerConfig};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;
#[path = "helpers/pair.rs"]
mod pair;

use certs::TestCert;
use pair::{bind_server, connect_with_server};

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// 既定のクライアント設定 (証明書検証なし)
fn default_client_config() -> ClientConfig {
    ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false)
}

/// 長さ 0 のコネクション ID を使うサーバーとデータをやり取りできること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_with_zero_length_cid() {
    let cert = TestCert::generate("zero_length_cid");
    let server_config = ServerConfig::new(&[b"hq-interop"]).with_scid_len(0);
    let mut pair = {
        let server = bind_server(cert.cert_path(), cert.key_path(), Some(server_config)).await;
        let (pair, _server) =
            connect_with_server(server, default_client_config(), "localhost").await;
        pair
    };

    let result = timeout(TEST_TIMEOUT, async {
        // クライアントからサーバーへ
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"zero-length", false)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("送信できること");

        loop {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            if let ConnectionEvent::StreamData { data, .. } = event {
                assert_eq!(data, b"zero-length", "サーバーが受け取ったデータ");
                break;
            }
        }

        // サーバーからクライアントへ
        //
        // クライアントの SCID はサーバーの DCID になるため、サーバーが
        // コネクション ID を使わない場合でもこの向きはコネクション ID で届く
        pair.server
            .write_stream(stream_id, b"server-data", true)
            .expect("送信待ちに積めること");
        pair.server.flush().await.expect("送信できること");

        loop {
            let event = pair
                .client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること");
            if let ConnectionEvent::StreamData { data, .. } = event {
                assert_eq!(data, b"server-data", "クライアントが受け取ったデータ");
                break;
            }
        }
    })
    .await;
    result.expect("テストがタイムアウトしないこと");
}

/// 長さ 0 のコネクション ID でも Retry でアドレスを検証できること
///
/// Retry の SCID も長さ 0 になるため、クライアントの 2 通目の Initial は
/// コネクション ID を載せない。サーバーはアドレスで振り分ける
/// (RFC 9000 Section 8.1.2)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_with_zero_length_cid_and_retry() {
    let cert = TestCert::generate("zero_length_cid_retry");
    let server_config = ServerConfig::new(&[b"hq-interop"])
        .with_scid_len(0)
        .with_retry(RetrySecret::from_bytes([0x51; 32]));
    let mut pair = {
        let server = bind_server(cert.cert_path(), cert.key_path(), Some(server_config)).await;
        let (pair, _server) =
            connect_with_server(server, default_client_config(), "localhost").await;
        pair
    };

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"retried", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("送信できること");

        loop {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            if let ConnectionEvent::StreamData { data, .. } = event {
                assert_eq!(data, b"retried", "サーバーが受け取ったデータ");
                break;
            }
        }

        // サーバーはコネクション ID を発行しない (NEW_CONNECTION_ID を送らない)
        assert!(
            pair.server
                .remote_transport_params()
                .is_some_and(|params| params.initial_max_data > 0),
            "ハンドシェイクが完了していること"
        );
    })
    .await;
    result.expect("テストがタイムアウトしないこと");
}

/// 長さ 0 のコネクション ID を使うサーバーが DATAGRAM を送れること
///
/// 制御フレームもコネクション ID なしで届くことを確認する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_with_zero_length_cid_datagram() {
    let cert = TestCert::generate("zero_length_cid_datagram");
    let datagram = DatagramConfig::default();
    let transport_params = TransportParams::new().with_datagram(datagram.max_datagram_frame_size);
    let server_config = ServerConfig::new(&[b"hq-interop"])
        .with_scid_len(0)
        .with_transport_params(transport_params.clone())
        .with_datagram(datagram);
    let mut pair = {
        let server = bind_server(cert.cert_path(), cert.key_path(), Some(server_config)).await;
        let client_config = default_client_config()
            .with_transport_params(transport_params)
            .with_datagram(datagram);
        let (pair, _server) = connect_with_server(server, client_config, "localhost").await;
        pair
    };

    let result = timeout(TEST_TIMEOUT, async {
        pair.client
            .send_datagram(b"datagram")
            .await
            .expect("DATAGRAM を送信できること");

        loop {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            if let ConnectionEvent::Datagram { data } = event {
                assert_eq!(data, b"datagram", "サーバーが受け取った DATAGRAM");
                break;
            }
        }
    })
    .await;
    result.expect("テストがタイムアウトしないこと");
}
