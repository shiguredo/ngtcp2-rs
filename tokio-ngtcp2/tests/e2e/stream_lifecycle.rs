//! ストリームのライフサイクルイベントの e2e テスト
//!
//! 実 UDP ソケットでクライアントとサーバーを接続し、ストリームの開設・終了・
//! リセット・受信停止と、フロー制御 / ストリーム数の拡張通知がイベントとして
//! 届くことを検証する。

use std::time::Duration;

use shiguredo_ngtcp2::TransportParams;
use shiguredo_ngtcp2_tokio::{ClientConfig, ConnectionEvent, ServerConfig};
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
use pair::{Pair, bind_server, connect_with_server};
use pump::PUMP_INTERVAL;

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// 既定のクライアント設定 (証明書検証なし)
fn default_client_config() -> ClientConfig {
    ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false)
}

/// サーバーとクライアントを接続する
async fn connect_pair(cert: &TestCert, server_config: Option<ServerConfig>) -> Pair {
    connect_pair_with_client_config(cert, default_client_config(), server_config).await
}

/// クライアント設定を指定してサーバーとクライアントを接続する
async fn connect_pair_with_client_config(
    cert: &TestCert,
    client_config: ClientConfig,
    server_config: Option<ServerConfig>,
) -> Pair {
    let server = bind_server(cert.cert_path(), cert.key_path(), server_config).await;
    let (pair, _server) = connect_with_server(server, client_config, "localhost").await;
    pair
}

/// ピアが開いた双方向ストリームで `StreamOpened` が届くこと
///
/// `StreamOpened` はピア開始のストリームに初めてフレームが届いたときに発生し、
/// `StreamData` より先に届く (RFC 9000 Section 2.1)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stream_opened_for_peer_initiated_stream() {
    let cert = TestCert::generate("lifecycle_opened");
    let mut pair = connect_pair(&cert, None).await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"open", false)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        let mut opened = false;
        let mut got_data = false;
        while !opened || !got_data {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            match event {
                ConnectionEvent::StreamOpened { stream_id: sid } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    assert!(!opened, "StreamOpened は 1 回だけ届くこと");
                    assert!(
                        !got_data,
                        "StreamOpened は StreamData より先に届くこと: {event:?}"
                    );
                    opened = true;
                }
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    ..
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    assert_eq!(data, b"open", "受信データが一致すること");
                    pair.server
                        .extend_max_stream_offset(sid, data.len() as u64)
                        .expect("フロー制御クレジットを戻せること");
                    got_data = true;
                }
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// サーバーが開いたストリームでもクライアントに `StreamOpened` が届くこと
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stream_opened_for_server_initiated_stream() {
    let cert = TestCert::generate("lifecycle_opened_s2c");
    let mut pair = connect_pair(&cert, None).await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .server
            .open_bidi_stream()
            .expect("サーバーがストリームを開けること");
        // サーバー開始の双方向ストリームは bit 0 が 1 (RFC 9000 Section 2.1)
        assert_eq!(stream_id & 0x1, 0x1, "サーバー開始であること");

        pair.server
            .write_stream(stream_id, b"from server", false)
            .expect("送信待ちに積めること");
        pair.server.flush().await.expect("データを送信できること");

        let mut opened = false;
        while !opened {
            let event = pair
                .client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること");
            match event {
                ConnectionEvent::StreamOpened { stream_id: sid } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    opened = true;
                }
                ConnectionEvent::StreamData { .. } => {
                    assert!(opened, "StreamOpened は StreamData より先に届くこと");
                }
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 両方向を FIN で終端すると `StreamClosed` のエラーコードが `None` になること
///
/// ストリームは両方向が終端し、送信データがすべて ACK されて初めて閉じる
/// (RFC 9000 Section 3.3)。そのため両側を同時に駆動する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stream_closed_after_fin() {
    let cert = TestCert::generate("lifecycle_closed");
    let pair = connect_pair(&cert, None).await;

    let result = timeout(TEST_TIMEOUT, async {
        let Pair {
            mut server,
            mut client,
        } = pair;

        let stream_id = client.open_bidi_stream().expect("ストリームを開けること");
        client
            .write_stream(stream_id, b"request", true)
            .expect("送信待ちに積めること");
        client.flush().await.expect("データを送信できること");

        // サーバーは終端まで読んでから FIN を返す
        let mut got_fin = false;
        while !got_fin {
            let event = server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            match event {
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    fin,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    server
                        .extend_max_stream_offset(sid, data.len() as u64)
                        .expect("フロー制御クレジットを戻せること");
                    got_fin = fin;
                }
                ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
        server
            .write_stream(stream_id, b"response", true)
            .expect("送信待ちに積めること");
        server.flush().await.expect("データを送信できること");

        // 両側を交互に駆動して、それぞれの StreamClosed を待つ。
        // 片側だけを await すると ACK が流れず、もう一方が閉じない。
        let mut server_closed = None;
        let mut client_closed = None;
        while server_closed.is_none() || client_closed.is_none() {
            if let Ok(Ok(event)) = timeout(PUMP_INTERVAL, server.recv_event()).await
                && let ConnectionEvent::StreamClosed {
                    stream_id: sid,
                    rx_app_error_code,
                    tx_app_error_code,
                } = event
                && sid == stream_id
            {
                server_closed = Some((rx_app_error_code, tx_app_error_code));
            }
            if let Ok(Ok(event)) = timeout(PUMP_INTERVAL, client.recv_event()).await
                && let ConnectionEvent::StreamClosed {
                    stream_id: sid,
                    rx_app_error_code,
                    tx_app_error_code,
                } = event
                && sid == stream_id
            {
                client_closed = Some((rx_app_error_code, tx_app_error_code));
            }
        }

        let (client_rx, client_tx) = client_closed.expect("クライアント側が閉じること");
        let (server_rx, server_tx) = server_closed.expect("サーバー側が閉じること");

        // 正常終了ではどちらの方向にもエラーコードが付かないこと
        assert_eq!(
            (client_rx, client_tx),
            (None, None),
            "クライアント側の StreamClosed にエラーコードが無いこと"
        );
        assert_eq!(
            (server_rx, server_tx),
            (None, None),
            "サーバー側の StreamClosed にエラーコードが無いこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// `reset_stream` がピアに `StreamReset` として伝わること (RFC 9000 Section 19.4)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reset_stream_notifies_peer() {
    let cert = TestCert::generate("lifecycle_reset");
    let mut pair = connect_pair(&cert, None).await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"partial", false)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        // 送信側をエラーコード 42 で中断する
        pair.client
            .reset_stream(stream_id, 42)
            .expect("送信側を中断できること");
        pair.client
            .flush()
            .await
            .expect("RESET_STREAM を送信できること");

        let mut reset = None;
        while reset.is_none() {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            match event {
                ConnectionEvent::StreamReset {
                    stream_id: sid,
                    final_size,
                    app_error_code,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    assert_eq!(app_error_code, 42, "エラーコードが伝わること");
                    // 中断前に送った 7 バイトが最終サイズになる
                    assert_eq!(final_size, 7, "final_size が送信済みバイト数であること");
                    reset = Some(app_error_code);
                }
                ConnectionEvent::StreamData { .. } | ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
        assert_eq!(reset, Some(42), "StreamReset(42) が届くこと");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// `stop_sending` がピアに `StreamStopSending` として伝わること
/// (RFC 9000 Section 19.5)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stop_sending_notifies_peer() {
    let cert = TestCert::generate("lifecycle_stop_sending");
    let mut pair = connect_pair(&cert, None).await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"some data", false)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        // サーバーはデータを受け取ったうえで受信を中断する
        let mut got_data = false;
        while !got_data {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            match event {
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    ..
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    pair.server
                        .extend_max_stream_offset(sid, data.len() as u64)
                        .expect("フロー制御クレジットを戻せること");
                    got_data = true;
                }
                ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }

        pair.server
            .stop_sending(stream_id, 7)
            .expect("受信側を中断できること");
        pair.server
            .flush()
            .await
            .expect("STOP_SENDING を送信できること");

        // クライアントは STOP_SENDING を観測する
        let mut stopped = None;
        while stopped.is_none() {
            let event = pair
                .client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること");
            match event {
                ConnectionEvent::StreamStopSending {
                    stream_id: sid,
                    app_error_code,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    assert_eq!(app_error_code, 7, "エラーコードが伝わること");
                    stopped = Some(app_error_code);
                }
                ConnectionEvent::StreamClosed { .. } | ConnectionEvent::StreamMaxData { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
        assert_eq!(stopped, Some(7), "StreamStopSending(7) が届くこと");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// フロー制御クレジットを返すと送信側に `StreamMaxData` が届くこと
/// (RFC 9000 Section 19.10)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stream_max_data_notifies_sender() {
    let cert = TestCert::generate("lifecycle_max_data");
    // ストリームあたりの受信上限を 1024 バイトにして、拡張を強制する。
    // bidi_remote は「ピア (クライアント) 開始の双方向ストリーム」に対する
    // サーバー側の受信上限 (RFC 9000 Section 18.2)。
    let params = TransportParams::new().with_initial_max_stream_data_bidi_remote(1024);
    let mut pair = connect_pair(
        &cert,
        Some(ServerConfig::new(&[b"hq-interop"]).with_transport_params(params)),
    )
    .await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        // ストリームウィンドウをちょうど埋める
        pair.client
            .write_stream(stream_id, &[0x41u8; 1024], false)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        // サーバーは受信した分だけクレジットを返す
        let mut received = 0usize;
        while received < 1024 {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            match event {
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    ..
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    pair.server
                        .extend_max_stream_offset(sid, data.len() as u64)
                        .expect("フロー制御クレジットを戻せること");
                    received += data.len();
                }
                ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
        pair.server
            .flush()
            .await
            .expect("MAX_STREAM_DATA を送信できること");

        // クライアントは上限の拡張を観測する
        let mut extended = None;
        while extended.is_none() {
            let event = pair
                .client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること");
            match event {
                ConnectionEvent::StreamMaxData {
                    stream_id: sid,
                    max_data,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    extended = Some(max_data);
                }
                ConnectionEvent::StreamClosed { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
        // 初期値 1024 から受信した 1024 バイト分だけ伸びること
        assert_eq!(extended, Some(2048), "max_data が拡張されること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// `extend_max_streams_bidi` がピアに `MaxStreamsBidi` として伝わること
/// (RFC 9000 Section 19.11)
///
/// ngtcp2 はストリーム数の上限を自動では増やさないため、アプリケーションが
/// 明示的に拡張しない限りピアは上限に達した後にストリームを開けない。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_extend_max_streams_bidi() {
    let cert = TestCert::generate("lifecycle_max_streams_bidi");
    // クライアントが開ける双方向ストリームを 1 本に制限する
    let params = TransportParams::new().with_max_streams_bidi(1);
    let mut pair = connect_pair(
        &cert,
        Some(ServerConfig::new(&[b"hq-interop"]).with_transport_params(params)),
    )
    .await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair.client.open_bidi_stream().expect("1 本目は開けること");
        assert_eq!(
            pair.client.streams_bidi_left(),
            0,
            "上限に達したら残りが 0 になること"
        );
        // 上限に達しているため 2 本目は開けないこと
        assert!(
            pair.client.open_bidi_stream().is_err(),
            "上限を超えてストリームを開けないこと"
        );

        // 1 本目を完結させてサーバーが拡張できるようにする
        pair.client
            .write_stream(stream_id, b"one", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        let mut got_fin = false;
        while !got_fin {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            match event {
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    fin,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    pair.server
                        .extend_max_stream_offset(sid, data.len() as u64)
                        .expect("フロー制御クレジットを戻せること");
                    got_fin = fin;
                }
                ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }

        // サーバーが双方向ストリームの上限を 1 増やす
        pair.server.extend_max_streams_bidi(1);
        pair.server
            .flush()
            .await
            .expect("MAX_STREAMS を送信できること");

        // クライアントは拡張を観測する。ハンドシェイク完了時の初期通知は 1 で、
        // 拡張後は 2 になるため値で区別できる。
        let mut max_streams = None;
        while max_streams != Some(2) {
            let event = pair
                .client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること");
            match event {
                ConnectionEvent::MaxStreamsBidi { max_streams: n } => {
                    assert!(n <= 2, "上限は 2 を超えないこと: {n}");
                    max_streams = Some(n);
                }
                ConnectionEvent::StreamClosed { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }

        // 拡張後は 2 本目を開けること
        assert_eq!(
            pair.client.streams_bidi_left(),
            1,
            "拡張後に残りが 1 になること"
        );
        pair.client
            .open_bidi_stream()
            .expect("拡張後は 2 本目を開けること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// `extend_max_streams_uni` がピアに `MaxStreamsUni` として伝わること
/// (RFC 9000 Section 19.11)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_extend_max_streams_uni() {
    let cert = TestCert::generate("lifecycle_max_streams_uni");
    // クライアントが開ける単方向ストリームを 1 本に制限する
    let params = TransportParams::new().with_max_streams_uni(1);
    let mut pair = connect_pair(
        &cert,
        Some(ServerConfig::new(&[b"hq-interop"]).with_transport_params(params)),
    )
    .await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair.client.open_uni_stream().expect("1 本目は開けること");
        assert!(
            pair.client.open_uni_stream().is_err(),
            "上限を超えてストリームを開けないこと"
        );

        pair.client
            .write_stream(stream_id, b"one", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        let mut got_fin = false;
        while !got_fin {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            match event {
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    fin,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    pair.server
                        .extend_max_stream_offset(sid, data.len() as u64)
                        .expect("フロー制御クレジットを戻せること");
                    got_fin = fin;
                }
                ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }

        pair.server.extend_max_streams_uni(1);
        pair.server
            .flush()
            .await
            .expect("MAX_STREAMS を送信できること");

        let mut max_streams = None;
        while max_streams != Some(2) {
            let event = pair
                .client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること");
            match event {
                ConnectionEvent::MaxStreamsUni { max_streams: n } => {
                    assert!(n <= 2, "上限は 2 を超えないこと: {n}");
                    max_streams = Some(n);
                }
                ConnectionEvent::StreamClosed { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }

        pair.client
            .open_uni_stream()
            .expect("拡張後は 2 本目を開けること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// クライアントに `HandshakeConfirmed` が届くこと (RFC 9001 Section 4.1.2)
///
/// ngtcp2 は HANDSHAKE_DONE を受信したクライアントだけで
/// `handshake_confirmed` コールバックを呼ぶ。サーバーは
/// `ngtcp2_conn_tls_handshake_completed` が確認済みフラグを立てるだけで
/// コールバックを呼ばないため、サーバー側にこのイベントは届かない。
///
/// サーバーの確認済みフラグは HANDSHAKE_DONE を送る前に立つので、
/// クライアントが確認を観測した時点でサーバー側は出尽くしている。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_handshake_confirmed_on_client() {
    let cert = TestCert::generate("lifecycle_confirmed");
    let pair = connect_pair(&cert, None).await;

    let result = timeout(TEST_TIMEOUT, async {
        let Pair {
            mut server,
            mut client,
        } = pair;

        // 両側を交互に駆動する。HANDSHAKE_DONE はサーバーが送信するため、
        // サーバー側も回さないとクライアントに届かない。
        let mut client_confirmed = false;
        let mut server_confirmed = false;
        while !client_confirmed {
            if let Ok(Ok(event)) = timeout(PUMP_INTERVAL, server.recv_event()).await {
                server_confirmed |= matches!(event, ConnectionEvent::HandshakeConfirmed);
            }
            if let Ok(Ok(event)) = timeout(PUMP_INTERVAL, client.recv_event()).await {
                client_confirmed = matches!(event, ConnectionEvent::HandshakeConfirmed);
            }
        }

        assert!(
            client_confirmed,
            "クライアントに HandshakeConfirmed が届くこと"
        );
        assert!(
            !server_confirmed,
            "サーバーに HandshakeConfirmed は届かないこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// `reset_stream_reliable` が送信済みのデータを届けてからリセットすること
/// (draft-ietf-quic-reliable-stream-reset)
///
/// 送信したデータを破棄しないため、ピアは `StreamData` でデータを受け取ってから
/// `StreamReset` を受け取る。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reset_stream_reliable_delivers_data() {
    let cert = TestCert::generate("lifecycle_reliable_reset");
    // 双方が reset_stream_at を通知する
    let client_config = default_client_config()
        .with_transport_params(TransportParams::new().with_reset_stream_at(true));
    let server_config = ServerConfig::new(&[b"hq-interop"])
        .with_transport_params(TransportParams::new().with_reset_stream_at(true));
    let mut pair = connect_pair_with_client_config(&cert, client_config, Some(server_config)).await;

    let result = timeout(TEST_TIMEOUT, async {
        assert!(
            pair.client.supports_reset_stream_at(),
            "ピアが通知した reset_stream_at が読めること"
        );
        assert!(
            pair.server.supports_reset_stream_at(),
            "サーバー側からも読めること"
        );

        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"partial", false)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        // データを送った直後にリセットする。ACK が届いていなくてもデータは届く
        pair.client
            .reset_stream_reliable(stream_id, 42)
            .expect("送信側を中断できること");
        pair.client
            .flush()
            .await
            .expect("RESET_STREAM_AT を送信できること");

        let mut received = Vec::new();
        let mut reset = None;
        while reset.is_none() {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            match event {
                ConnectionEvent::StreamData { data, .. } => received.extend_from_slice(&data),
                ConnectionEvent::StreamReset {
                    stream_id: sid,
                    final_size,
                    app_error_code,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    assert_eq!(app_error_code, 42, "エラーコードが伝わること");
                    assert_eq!(
                        final_size, 7,
                        "リセットの時点までのデータが配信対象になること"
                    );
                    reset = Some(app_error_code);
                }
                ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
        assert_eq!(reset, Some(42), "StreamReset(42) が届くこと");
        assert_eq!(
            received, b"partial",
            "リセットの前に送ったデータが欠落せず届くこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// ピアが `reset_stream_at` を通知していない場合は RESET_STREAM に落ちること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reset_stream_reliable_falls_back_without_support() {
    let cert = TestCert::generate("lifecycle_reliable_reset_fallback");
    // サーバーは通知しないため、クライアントからは保証なしのリセットになる
    let mut pair = connect_pair(&cert, None).await;

    let result = timeout(TEST_TIMEOUT, async {
        assert!(
            !pair.client.supports_reset_stream_at(),
            "通知していないピアは false になること"
        );

        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .reset_stream_reliable(stream_id, 9)
            .expect("保証が得られなくてもリセットできること");
        pair.client
            .flush()
            .await
            .expect("RESET_STREAM を送信できること");

        let mut reset = None;
        while reset.is_none() {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            match event {
                ConnectionEvent::StreamReset {
                    stream_id: sid,
                    final_size,
                    app_error_code,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    assert_eq!(app_error_code, 9, "エラーコードが伝わること");
                    assert_eq!(final_size, 0, "データを送っていないこと");
                    reset = Some(app_error_code);
                }
                ConnectionEvent::StreamOpened { .. } => {}
                other if is_connection_setup_event(&other) => {}
                other => panic!("想定外のイベント: {other:?}"),
            }
        }
        assert_eq!(reset, Some(9), "StreamReset(9) が届くこと");
        assert!(!pair.server.is_closed(), "接続は終了しないこと");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}
