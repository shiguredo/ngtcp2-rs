//! qlog の e2e テスト
//!
//! サーバーとクライアントの両方で qlog を有効にし、接続ごとのファイルが
//! 作られて中身が空でないことを検証する。

use std::time::Duration;

use shiguredo_ngtcp2_tokio::{ClientConfig, ServerConfig};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;
#[path = "helpers/pair.rs"]
mod pair;

use certs::TestCert;
use pair::{bind_server, connect_with_server};

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// qlog を有効にすると接続ごとのファイルが作られること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_qlog_files_are_written() {
    let cert = TestCert::generate("qlog");
    // テストごとに専用のディレクトリを作る
    let dir = std::env::temp_dir().join(format!("ngtcp2_qlog_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"]).with_qlog_dir(dir.clone())),
    )
    .await;
    let client_config = ClientConfig::new(&[b"hq-interop"])
        .with_qlog_dir(dir.clone())
        .with_verify_peer(false);

    let result = timeout(TEST_TIMEOUT, async {
        let (mut pair, _server) = connect_with_server(server, client_config, "localhost").await;

        // ハンドシェイクとデータのやり取りで qlog が出力される
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"qlog", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("送信できること");

        // サーバー側でもデータを受け取る (両側で qlog が出力される)
        loop {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            if matches!(
                event,
                shiguredo_ngtcp2_tokio::ConnectionEvent::StreamData { .. }
            ) {
                break;
            }
        }
    })
    .await;
    result.expect("テストがタイムアウトしないこと");

    // クライアントとサーバーの両方のファイルが作られていること
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("qlog のディレクトリを読めること")
        .map(|entry| entry.expect("エントリを読めること").path())
        .collect();
    files.sort();
    assert_eq!(
        files.len(),
        2,
        "接続ごとに 1 ファイル作られること: {files:?}"
    );

    for path in &files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert!(
            name.ends_with(".sqlog"),
            "拡張子が sqlog であること: {name}"
        );
        let body = std::fs::read_to_string(path).expect("qlog を読めること");
        assert!(!body.is_empty(), "qlog が空でないこと: {name}");
        assert!(
            body.contains("\"qlog_version\""),
            "qlog のヘッダーが含まれること: {name}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
