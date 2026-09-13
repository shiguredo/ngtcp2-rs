//! ストリーム転送の e2e テスト
//!
//! 実 UDP ソケットでクライアントとサーバーを接続し、双方向 / 単方向
//! ストリームのデータ転送、FIN の伝播、フロー制御を検証する。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use shiguredo_ngtcp2::TransportParams;
use shiguredo_ngtcp2_tokio::{
    AcceptedConnection, Client, ClientConfig, CongestionAlgorithm, ConnectionEvent, ServerConfig,
    Settings,
};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;
#[path = "helpers/events.rs"]
mod events;
#[path = "helpers/pair.rs"]
mod pair;
#[path = "helpers/pump.rs"]
mod pump;

use certs::TestCert;
use events::is_connection_setup_event;
use pair::{Pair, bind_server, connect_with_server, ephemeral_addr};
use pump::PUMP_INTERVAL;

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// 既定のクライアント設定 (証明書検証なし)
fn default_client_config() -> ClientConfig {
    ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false)
}

/// サーバーとクライアントを接続する
///
/// サーバー本体は接続ハンドルがソケットを共有しているため破棄する。
async fn connect_pair(
    cert: &TestCert,
    server_config: Option<ServerConfig>,
    client_config: ClientConfig,
) -> Pair {
    let server = bind_server(cert.cert_path(), cert.key_path(), server_config).await;
    let (pair, _server) = connect_with_server(server, client_config, "localhost").await;
    pair
}

/// サーバー側でストリームデータを終端まで読み、フロー制御クレジットを戻す
///
/// ピア開始のストリームではデータの前に `StreamOpened` が届き、ハンドシェイクの
/// 進行イベントは任意のタイミングで届くため、いずれも読み飛ばす。
async fn read_stream_to_end(conn: &mut AcceptedConnection, stream_id: i64) -> Vec<u8> {
    let mut received = Vec::new();
    loop {
        match conn
            .recv_event()
            .await
            .expect("サーバーがイベントを受信できること")
        {
            ConnectionEvent::StreamData {
                stream_id: sid,
                data,
                fin,
            } => {
                assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                conn.extend_max_stream_offset(sid, data.len() as u64)
                    .expect("フロー制御クレジットを戻せること");
                received.extend_from_slice(&data);
                if fin {
                    return received;
                }
            }
            // ストリームの開設通知とハンドシェイクの進行は対象外
            ConnectionEvent::StreamOpened { .. } => {}
            other if is_connection_setup_event(&other) => {}
            other => panic!("想定外のイベント: {other:?}"),
        }
    }
}

/// クライアントからサーバーへストリームでデータを送り、全量が届くことを検証する
///
/// QUIC は双方向なので、送信側も受信して ACK と MAX_STREAM_DATA を処理しないと
/// 輻輳ウィンドウとフロー制御ウィンドウが伸びない。そのため両側で送受信を
/// 交互に行う。
///
/// 戻り値はサーバーが受信したデータ。
async fn transfer_client_to_server(pair: &mut Pair, payload: &[u8]) -> Vec<u8> {
    let stream_id = pair
        .client
        .open_bidi_stream()
        .expect("ストリームを開けること");
    // 送信待ちに積む。実際の送信は下のループで行う
    pair.client
        .write_stream(stream_id, payload, true)
        .expect("送信待ちに積めること");

    let mut received = Vec::new();
    while pair.client.has_pending_data() || received.len() < payload.len() {
        // 送信する
        pair.client.flush().await.expect("送信できること");

        // サーバー側で受信し、クレジットを戻す
        if let Ok(Ok(event)) = timeout(Duration::from_millis(1), pair.server.recv_event()).await {
            match event {
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    fin,
                } => {
                    // この接続には他のストリームのデータも流れるため、
                    // 対象のストリームだけを集計する
                    if sid != stream_id {
                        continue;
                    }
                    pair.server
                        .extend_max_stream_offset(sid, data.len() as u64)
                        .expect("フロー制御クレジットを戻せること");
                    received.extend_from_slice(&data);
                    if fin {
                        break;
                    }
                }
                ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }

        // クライアント側で受信する (ACK と MAX_STREAM_DATA を処理する)
        if let Ok(Ok(event)) = timeout(Duration::from_millis(1), pair.client.recv_event()).await {
            match event {
                // クライアント側はデータを送るだけなので、届くのは
                // フロー制御の拡張通知とストリームの状態変化のみ
                ConnectionEvent::StreamData { .. }
                | ConnectionEvent::StreamMaxData { .. }
                | ConnectionEvent::StreamClosed { .. }
                | ConnectionEvent::Datagram { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
    }

    received
}

/// クライアントからサーバーへ双方向ストリームでデータを送れること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_bidi_stream_client_to_server() {
    let cert = TestCert::generate("stream_c2s");
    let mut pair = connect_pair(&cert, None, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"hello from client", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        let received = read_stream_to_end(&mut pair.server, stream_id).await;
        assert_eq!(received, b"hello from client", "受信データが一致すること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// サーバーからクライアントへ双方向ストリームでデータを送れること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_bidi_stream_server_to_client() {
    let cert = TestCert::generate("stream_s2c");
    let mut pair = connect_pair(&cert, None, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .server
            .open_bidi_stream()
            .expect("サーバーがストリームを開けること");
        pair.server
            .write_stream(stream_id, b"hello from server", true)
            .expect("送信待ちに積めること");
        pair.server.flush().await.expect("データを送信できること");

        let mut received = Vec::new();
        loop {
            match pair
                .client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること")
            {
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    fin,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    pair.client
                        .extend_max_stream_offset(sid, data.len() as u64)
                        .expect("フロー制御クレジットを戻せること");
                    received.extend_from_slice(&data);
                    if fin {
                        break;
                    }
                }
                // サーバー開始のストリームではデータの前に StreamOpened が届く
                ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }

        assert_eq!(received, b"hello from server", "受信データが一致すること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 単方向ストリームでデータを送れること (RFC 9000 Section 2.1)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_uni_stream() {
    let cert = TestCert::generate("stream_uni");
    let mut pair = connect_pair(&cert, None, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_uni_stream()
            .expect("ストリームを開けること");
        // クライアント開始の単方向ストリームは bit 1 が 1、bit 0 が 0
        // (RFC 9000 Section 2.1)
        assert_eq!(stream_id & 0x2, 0x2, "単方向ストリームであること");
        assert_eq!(stream_id & 0x1, 0x0, "クライアント開始であること");

        pair.client
            .write_stream(stream_id, b"uni", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        let received = read_stream_to_end(&mut pair.server, stream_id).await;
        assert_eq!(received, b"uni", "受信データ");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 0 長データ + FIN が伝わること
///
/// ngtcp2 は「0 長 STREAM フレームはデータも FIN も未送信の場合のみ受理される」
/// という特別扱いをするため、FIN だけを送る経路を検証する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_zero_length_data_with_fin() {
    let cert = TestCert::generate("stream_zero_fin");
    let mut pair = connect_pair(&cert, None, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("FIN だけを送信できること");

        let received = read_stream_to_end(&mut pair.server, stream_id).await;
        assert!(received.is_empty(), "データが空であること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 大きなデータがフロー制御で分割されて全量届くこと
///
/// QUIC は双方向なので、送信側も受信して ACK と MAX_STREAM_DATA を
/// 処理しなければ輻輳ウィンドウとフロー制御ウィンドウが伸びない。
/// そのため両側で送受信を交互に行う。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_large_transfer_with_flow_control() {
    // ストリームあたりのウィンドウを小さくして分割を強制する
    let params = TransportParams::new()
        .with_initial_max_stream_data_bidi_local(64 * 1024)
        .with_initial_max_stream_data_bidi_remote(64 * 1024)
        .with_initial_max_data(1024 * 1024);
    let cert = TestCert::generate("stream_large");
    let mut pair = connect_pair(
        &cert,
        Some(ServerConfig::new(&[b"hq-interop"]).with_transport_params(params)),
        default_client_config(),
    )
    .await;

    let payload = vec![0x5au8; 200 * 1024];

    let result = timeout(TEST_TIMEOUT, async {
        let received = transfer_client_to_server(&mut pair, &payload).await;
        assert_eq!(received.len(), payload.len(), "全量が届くこと");
        // 内容の不一致時に巨大な配列をダンプしないよう bool で比較する
        assert!(received == payload, "内容が一致すること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 統計情報とフロー制御の残量が転送を反映すること
///
/// `stats` は RTT や送受信量のスナップショット、`max_stream_data_left` は
/// ストリーム単位で送信できる残りのバイト数 (RFC 9000 Section 4.1)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stats_and_stream_data_left() {
    let cert = TestCert::generate("stream_stats");
    let params = TransportParams::new()
        .with_initial_max_stream_data_bidi_remote(64 * 1024)
        .with_initial_max_data(1024 * 1024);
    let mut pair = connect_pair(
        &cert,
        Some(ServerConfig::new(&[b"hq-interop"]).with_transport_params(params.clone())),
        default_client_config().with_transport_params(params),
    )
    .await;

    let result = timeout(TEST_TIMEOUT, async {
        // ハンドシェイクだけで送受信が記録されていること
        let before = pair.client.stats();
        assert!(before.bytes_sent > 0, "ハンドシェイクで送信していること");
        assert!(
            before.bytes_received > 0,
            "ハンドシェイクで受信していること"
        );
        assert_eq!(before.packets_lost, 0, "ループバックでは喪失しないこと");
        assert!(
            before.min_rtt.is_some(),
            "ハンドシェイクで RTT を観測していること"
        );
        assert!(
            pair.client.cwnd_left() > 0,
            "輻輳ウィンドウの残りがあること"
        );

        // まとまった量を転送すると統計が増えること。
        // transfer_client_to_server はストリーム ID で絞り込まないため、
        // 別のストリームへの書き込みは転送が終わってから行う。
        let payload = vec![0x55u8; 16 * 1024];
        let received = transfer_client_to_server(&mut pair, &payload).await;
        assert_eq!(received.len(), payload.len(), "全量が届くこと");
        // 内容の不一致時に巨大な配列をダンプしないよう bool で比較する
        assert!(received == payload, "内容が一致すること");

        // ストリームのフロー制御の残りはサーバーが通知した値から始まること
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        assert_eq!(
            pair.client.max_stream_data_left(stream_id),
            64 * 1024,
            "ストリームの残りはサーバーの通知値であること"
        );

        // 書き込んだ分だけ残りが減ること
        pair.client
            .write_stream(stream_id, &[0x77u8; 1024], false)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");
        assert_eq!(
            pair.client.max_stream_data_left(stream_id),
            64 * 1024 - 1024,
            "書き込んだ分だけ残りが減ること"
        );

        let after = pair.client.stats();
        assert!(
            after.bytes_sent > before.bytes_sent,
            "転送するとクライアントの送信量が増えること"
        );
        assert!(
            after.packets_sent > before.packets_sent,
            "転送するとクライアントの送信パケット数が増えること"
        );
        assert!(
            pair.server.stats().bytes_received > 0,
            "サーバー側の受信量が記録されること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 接続設定を変えても大きなデータが転送できること
///
/// 輻輳制御アルゴリズム (BBRv2)、UDP ペイロードの上限、初期 RTT、PMTUD の
/// 無効化を同時に指定し、設定が両側の接続に反映されても転送が成立することを
/// 確認する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_large_transfer_with_custom_settings() {
    let mut settings = Settings::new(0);
    settings.congestion_algorithm = CongestionAlgorithm::Bbr2;
    settings.max_tx_udp_payload_size = 1200;
    settings.initial_rtt = Duration::from_millis(5);
    settings.no_pmtud = true;

    // ストリームあたりのウィンドウを小さくして分割を強制する
    let params = TransportParams::new()
        .with_initial_max_stream_data_bidi_local(64 * 1024)
        .with_initial_max_stream_data_bidi_remote(64 * 1024)
        .with_initial_max_data(1024 * 1024);

    let cert = TestCert::generate("stream_settings");
    let mut pair = connect_pair(
        &cert,
        Some(
            ServerConfig::new(&[b"hq-interop"])
                .with_transport_params(params.clone())
                .with_settings(settings.clone()),
        ),
        default_client_config()
            .with_transport_params(params)
            .with_settings(settings),
    )
    .await;

    let payload = vec![0x33u8; 100 * 1024];

    let result = timeout(TEST_TIMEOUT, async {
        let received = transfer_client_to_server(&mut pair, &payload).await;
        assert_eq!(received.len(), payload.len(), "全量が届くこと");
        // 内容の不一致時に巨大な配列をダンプしないよう bool で比較する
        assert!(received == payload, "内容が一致すること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// ストリームをエラーコード付きで閉じるとピアに RESET_STREAM が伝わること
///
/// `close_stream` は RESET_STREAM と STOP_SENDING の両方を送る
/// (RFC 9000 Section 19.4 / 19.5)。受信側は RESET_STREAM を
/// `StreamReset` として、STOP_SENDING を `StreamStopSending` として観測し、
/// 最終的に `StreamClosed` で両方向のエラーコードを受け取る。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_close_stream() {
    let cert = TestCert::generate("stream_close");
    let mut pair = connect_pair(&cert, None, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        // データを送ってからエラーコード 42 で閉じる
        pair.client
            .write_stream(stream_id, b"partial", false)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");
        pair.client
            .close_stream(stream_id, 42)
            .expect("ストリームを閉じられること");
        // RESET_STREAM と STOP_SENDING は次の flush で送出される
        pair.client.flush().await.expect("フレームを送信できること");

        // 両側を交互に駆動し、それぞれの StreamClosed を待つ
        let mut events = Vec::new();
        let mut server_closed = None;
        let mut client_closed = None;
        while server_closed.is_none() || client_closed.is_none() {
            if let Ok(Ok(event)) = timeout(PUMP_INTERVAL, pair.server.recv_event()).await {
                if let ConnectionEvent::StreamClosed { stream_id: sid, .. } = &event
                    && *sid == stream_id
                {
                    server_closed = Some(event);
                } else if !is_connection_setup_event(&event) {
                    events.push(event);
                }
            }
            if let Ok(Ok(event)) = timeout(PUMP_INTERVAL, pair.client.recv_event()).await
                && let ConnectionEvent::StreamClosed { stream_id: sid, .. } = &event
                && *sid == stream_id
            {
                client_closed = Some(event);
            }
        }

        // 両側でストリームが閉じること
        let closed = server_closed.expect("サーバーが StreamClosed を受け取ること");
        assert!(
            client_closed.is_some(),
            "クライアントも StreamClosed を受け取ること"
        );

        // RESET_STREAM がエラーコード付きで届くこと (RFC 9000 Section 19.4)
        assert!(
            events.iter().any(|event| matches!(
                event,
                ConnectionEvent::StreamReset {
                    stream_id: sid,
                    app_error_code: 42,
                    ..
                } if *sid == stream_id
            )),
            "StreamReset(42) が届くこと: {events:?}"
        );

        // STOP_SENDING がエラーコード付きで届くこと (RFC 9000 Section 19.5)
        assert!(
            events.iter().any(|event| matches!(
                event,
                ConnectionEvent::StreamStopSending {
                    stream_id: sid,
                    app_error_code: 42,
                } if *sid == stream_id
            )),
            "StreamStopSending(42) が届くこと: {events:?}"
        );

        // 閉じたときに両方向のエラーコードが伝わること
        assert_eq!(
            closed,
            ConnectionEvent::StreamClosed {
                stream_id,
                rx_app_error_code: Some(42),
                tx_app_error_code: Some(42),
            },
            "StreamClosed に両方向のエラーコードが含まれること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// アプリケーションエラーで接続を閉じるとピアに伝わること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_close_connection_propagates_to_peer() {
    let cert = TestCert::generate("stream_close_conn");
    let mut pair = connect_pair(&cert, None, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        pair.client
            .close(7, b"goodbye")
            .await
            .expect("接続を閉じられること");
        assert!(pair.client.is_closed(), "close 後は閉じていること");

        // サーバー側で接続終了を観測する
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

        // 終了後の recv_event は ConnectionClosed を返すこと
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

/// 応答のないアドレスへの接続はハンドシェイクのタイムアウトで失敗すること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_handshake_timeout() {
    // 応答しないアドレスに接続する (誰もバインドしていないポート)
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().expect("テスト用アドレスは有効");
    let config = ClientConfig::new(&[b"hq-interop"])
        .with_verify_peer(false)
        .with_handshake_timeout(Duration::from_millis(500));

    let start = std::time::Instant::now();
    let result = timeout(
        TEST_TIMEOUT,
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
}

/// 一方がデータを読み終えるまで受信し、内容を返す
///
/// ハンドシェイクの進行イベントとストリームの開設通知は読み飛ばす。
async fn read_stream(pair: &mut Pair, from_server: bool, stream_id: i64) -> Vec<u8> {
    let mut received = Vec::new();
    let mut fin = false;
    while !fin {
        let event = if from_server {
            pair.client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること")
        } else {
            pair.server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること")
        };
        if let ConnectionEvent::StreamData {
            stream_id: sid,
            data,
            fin: f,
        } = event
            && sid == stream_id
        {
            received.extend_from_slice(&data);
            fin = f;
        }
    }
    received
}

/// ngtcp2 が鍵の更新を受け付けるまで再試行する
///
/// ハンドシェイクの確認前と、前の更新の確定から 1 PTO が経過するまでは
/// `NGTCP2_ERR_INVALID_STATE` で拒否される (ngtcp2 の
/// `conn_initiate_key_update` 参照)。いずれも一時的な状態なので再試行する。
async fn initiate_key_update(client_side: bool, pair: &mut Pair) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let result = if client_side {
            pair.client.initiate_key_update()
        } else {
            pair.server.initiate_key_update()
        };
        if result.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "鍵の更新を開始できること (NGTCP2_ERR_INVALID_STATE が解消しない)"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// クライアントが鍵を更新したあとも双方向にデータが転送できること
/// (RFC 9001 Section 4.6.3)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_client_key_update() {
    let cert = TestCert::generate("stream_key_update_client");
    let mut pair = connect_pair(&cert, None, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        // ハンドシェイクが確認されるまで待つ。ngtcp2 は確認前の
        // 鍵の更新を拒否する (RFC 9001 Section 4.1.2)
        let mut confirmed = false;
        while !confirmed {
            match timeout(PUMP_INTERVAL, pair.client.recv_event()).await {
                Ok(Ok(ConnectionEvent::HandshakeConfirmed)) => confirmed = true,
                Ok(Ok(_)) => {}
                other => panic!("ハンドシェイクが確認されること: {other:?}"),
            }
        }

        initiate_key_update(true, &mut pair).await;
        pair.client.flush().await.expect("更新を送信できること");

        // 更新後もクライアントからサーバーへ送れること
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"client after update", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");
        let received = read_stream(&mut pair, false, stream_id).await;
        assert_eq!(received, b"client after update", "サーバーへ届くこと");

        // ピア (サーバー) も鍵を更新したあとで送れること
        let sid = pair
            .server
            .open_bidi_stream()
            .expect("サーバーがストリームを開けること");
        pair.server
            .write_stream(sid, b"server after update", true)
            .expect("送信待ちに積めること");
        pair.server.flush().await.expect("データを送信できること");
        let received = read_stream(&mut pair, true, sid).await;
        assert_eq!(received, b"server after update", "クライアントへ届くこと");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// サーバーが鍵を更新したあとも双方向にデータが転送できること
/// (RFC 9001 Section 4.6.3)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_key_update() {
    let cert = TestCert::generate("stream_key_update_server");
    let mut pair = connect_pair(&cert, None, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        initiate_key_update(false, &mut pair).await;
        pair.server.flush().await.expect("更新を送信できること");

        // サーバーからクライアントへ送れること
        let stream_id = pair
            .server
            .open_bidi_stream()
            .expect("サーバーがストリームを開けること");
        pair.server
            .write_stream(stream_id, b"server after update", true)
            .expect("送信待ちに積めること");
        pair.server.flush().await.expect("データを送信できること");
        let received = read_stream(&mut pair, true, stream_id).await;
        assert_eq!(received, b"server after update", "クライアントへ届くこと");

        // クライアントも鍵の世代に追従して送れること
        let sid = pair
            .client
            .open_bidi_stream()
            .expect("クライアントがストリームを開けること");
        pair.client
            .write_stream(sid, b"client after update", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");
        let received = read_stream(&mut pair, false, sid).await;
        assert_eq!(received, b"client after update", "サーバーへ届くこと");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}
