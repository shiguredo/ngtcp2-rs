//! accept が accept 済み接続宛てのデータグラムを接続へ引き渡すことを検証する
//!
//! [`Server::accept`] はリスナーソケットを読み、accept 済み接続宛ての
//! データグラムも読むことがある。これを引き渡さずに捨てると、そのデータは
//! ピアが再送するまで届かない。
//!
//! このテストは「クライアントが送信 → サーバーは接続を駆動せず accept だけを
//! 回す → そのあと接続を駆動する」という順序を作る。クライアントは送信後に
//! 駆動しないため、ngtcp2 (sans-IO) は再送しない。accept がデータグラムを
//! 引き渡していれば接続を駆動した時点で届き、捨てていれば永久に届かない。

use std::time::Duration;

use shiguredo_ngtcp2_tokio::{Client, ClientConfig, ConnectionEvent, Server, ServerConfig};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;

use certs::TestCert;

/// 送信するデータサイズ (バイト)
const DATA_SIZE: usize = 4 * 1024;

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// accept を回す時間
///
/// クライアントのデータグラムがサーバーのソケットに届いたあと、接続を駆動する
/// 前に accept へソケットを読ませるための時間。
const ACCEPT_POLL_WINDOW: Duration = Duration::from_millis(10);

/// accept 1 回あたりの待ち時間
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// サーバー接続の駆動間隔
const PUMP_INTERVAL: Duration = Duration::from_millis(1);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_accept_hands_datagrams_to_accepted_connection() {
    let cert = TestCert::generate("accept_handoff");
    let mut server = Server::bind(
        "127.0.0.1:0".parse().expect("リテラルアドレスは有効"),
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"])),
    )
    .await
    .expect("サーバーを起動できること");
    let addr = server.local_addr();

    // ハンドシェイクは accept が処理するため、接続の受け入れとクライアントの
    // 接続を並行して進める
    let accept_task = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("accept が成功すること")
            .expect("接続が受け入れられること");
        (conn, server)
    });
    let mut client = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(
            addr,
            "127.0.0.1:0".parse().expect("リテラルアドレスは有効"),
            "localhost",
            &ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false),
        ),
    )
    .await
    .expect("ハンドシェイクがタイムアウトしないこと")
    .expect("クライアントが接続できること");
    let (mut accepted, mut server) = timeout(TEST_TIMEOUT, accept_task)
        .await
        .expect("accept がタイムアウトしないこと")
        .expect("accept タスクが完了すること");

    // クライアントがデータを送る。flush がパケットを送信するため、この時点で
    // サーバーのソケットにデータグラムが届いている。以降クライアントは駆動しない
    // (ngtcp2 は sans-IO のため、駆動しない限り再送も起きない)。
    let payload = vec![0x5au8; DATA_SIZE];
    let stream_id = client.open_bidi_stream().expect("ストリームを開けること");
    client
        .write_stream(stream_id, &payload, true)
        .expect("ストリームへ書き込めること");
    client.flush().await.expect("送信できること");

    // サーバーは接続を駆動する前に accept を回す。accept がソケットを読むため、
    // accept 済み接続宛てのデータグラムもここで読まれる。
    let accept_deadline = tokio::time::Instant::now() + ACCEPT_POLL_WINDOW;
    while tokio::time::Instant::now() < accept_deadline {
        let _ = timeout(ACCEPT_POLL_INTERVAL, server.accept()).await;
    }

    // 接続を駆動してデータを受信する。accept がデータグラムを引き渡していれば
    // 再送を待たずに届く。
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    let mut received = Vec::new();
    while received.len() < DATA_SIZE {
        assert!(
            tokio::time::Instant::now() < deadline,
            "accept が読んだデータグラムが接続へ引き渡されなかった (受信 {} バイト)",
            received.len()
        );
        match timeout(PUMP_INTERVAL, accepted.recv_event()).await {
            Ok(Ok(ConnectionEvent::StreamData { data, .. })) => received.extend_from_slice(&data),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("サーバーでエラーが発生した: {e}"),
            Err(_) => {}
        }
    }

    assert_eq!(received, payload, "受信データが一致すること");
}
