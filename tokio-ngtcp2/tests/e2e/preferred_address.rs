//! 優先アドレス (RFC 9000 Section 9.6) の e2e テスト
//!
//! サーバーは優先アドレス用に 2 つ目のソケットを持ち、そのアドレスへ届いた
//! パケットも接続へ振り分けて、同じアドレスから応答する。クライアントは
//! ハンドシェイクの確認後に、通知された優先アドレスへ自分から移る。
//!
//! このファイルは `helpers/pair.rs` を取り込まない。あのヘルパーは
//! 「取り込むバイナリが全ての項目を使う」前提で、優先アドレス専用の接続手順
//! (接続先を指定する) は他のテストでは使わないため、ここに置く。

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use shiguredo_ngtcp2::QuicVersion;
use shiguredo_ngtcp2_tokio::{
    AcceptedConnection, Client, ClientConfig, ClientConnection, ConnectionEvent, Server,
    ServerConfig,
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;

use certs::TestCert;

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// 応答を待つタイムアウト
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// 接続済みのクライアントとサーバー
struct Pair {
    /// サーバー側の接続ハンドル
    server: AcceptedConnection,
    /// クライアント側の接続
    client: ClientConnection,
}

/// `127.0.0.1` のエフェメラルポートのアドレス
fn ephemeral_addr() -> SocketAddr {
    "127.0.0.1:0".parse().expect("リテラルアドレスは有効")
}

/// 優先アドレス付きでサーバーを起動する
///
/// 優先アドレスはポート 0 で bind し、実際に割り当てられたアドレスを使う。
async fn bind_server_with_preferred_addr(
    cert_path: &Path,
    key_path: &Path,
    config: ServerConfig,
) -> Server {
    let config = config.with_preferred_address(ephemeral_addr());
    Server::bind(ephemeral_addr(), cert_path, key_path, Some(config))
        .await
        .expect("サーバーを起動できること")
}

/// 指定したアドレスへクライアントを接続する
///
/// サーバーは別タスクで駆動し、1 接続を受け入れる。
async fn connect_with_server_addr(
    mut server: Server,
    client_config: ClientConfig,
    server_name: &str,
    addr: SocketAddr,
) -> Pair {
    let accept_task = tokio::spawn(async move {
        server
            .accept()
            .await
            .expect("accept が成功すること")
            .expect("接続が受け入れられること")
    });

    let client = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(addr, ephemeral_addr(), server_name, &client_config),
    )
    .await
    .expect("ハンドシェイクがタイムアウトしないこと")
    .expect("クライアントが接続できること");

    let server = timeout(TEST_TIMEOUT, accept_task)
        .await
        .expect("accept がタイムアウトしないこと")
        .expect("サーバータスクが完了すること");

    Pair { server, client }
}

/// 優先アドレスへ接続してもハンドシェイクとデータのやり取りができること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_client_connects_to_preferred_address() {
    let cert = TestCert::generate("preferred_address");
    let server = bind_server_with_preferred_addr(
        cert.cert_path(),
        cert.key_path(),
        ServerConfig::new(&[b"hq-interop"]),
    )
    .await;
    let preferred_addr = server
        .preferred_addr()
        .expect("優先アドレスが設定されていること");
    assert_ne!(
        preferred_addr,
        server.local_addr(),
        "優先アドレスは主アドレスと異なること"
    );

    let client_config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
    // 主アドレスではなく優先アドレスへ接続する
    let mut pair =
        connect_with_server_addr(server, client_config, "localhost", preferred_addr).await;

    let result = timeout(TEST_TIMEOUT, async {
        // 優先アドレスへ接続しているため、クライアントの経路は優先アドレス
        assert_eq!(
            pair.client.remote_addr(),
            preferred_addr,
            "クライアントは優先アドレスへ接続していること"
        );

        // 優先アドレスのソケットで受け取ったデータが接続へ振り分けられる
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"preferred", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("送信できること");

        loop {
            let event = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること");
            if let ConnectionEvent::StreamData { data, .. } = event {
                assert_eq!(data, b"preferred", "優先アドレスで受け取ったデータ");
                break;
            }
        }
    })
    .await;
    result.expect("テストがタイムアウトしないこと");
}

/// クライアントが通知された優先アドレスへ移ること (RFC 9000 Section 9.6)
///
/// 主アドレスへ接続したクライアントは、ハンドシェイクの確認後に優先アドレスを
/// 選び、経路の検証を経てそこへ移る。移行後もデータをやり取りできることまで
/// 確認する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_client_migrates_to_preferred_address() {
    let cert = TestCert::generate("preferred_address_migration");
    let server = bind_server_with_preferred_addr(
        cert.cert_path(),
        cert.key_path(),
        ServerConfig::new(&[b"hq-interop"]),
    )
    .await;
    let primary_addr = server.local_addr();
    let preferred_addr = server
        .preferred_addr()
        .expect("優先アドレスが設定されていること");

    // サーバーは接続を維持したまま駆動し続ける必要がある。経路の検証は双方が
    // 同時にパケットを処理して初めて進むため、サーバーは別タスクで回し続け、
    // 受け取ったストリームデータをチャネルで返す
    let (tx, mut rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut server = server;
        let mut conn = server
            .accept()
            .await
            .expect("accept が成功すること")
            .expect("接続が受け入れられること");

        let mut tx = Some(tx);
        loop {
            match conn.recv_event().await {
                Ok(ConnectionEvent::StreamData { data, .. }) => {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(data);
                    }
                }
                Ok(_) => {}
                // 接続が終わったらテスト側の判定に任せる
                Err(_) => break,
            }
        }
    });

    let result = timeout(TEST_TIMEOUT, async {
        let client_config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
        // 主アドレスへ接続する
        let mut client = Client::connect_with_config(
            primary_addr,
            ephemeral_addr(),
            "localhost",
            &client_config,
        )
        .await
        .expect("クライアントが接続できること");
        assert_eq!(
            client.remote_addr(),
            primary_addr,
            "接続直後は主アドレスを使っていること"
        );

        // 優先アドレスへの移行は経路の検証を経て通知される
        let path = loop {
            let event = client
                .recv_event()
                .await
                .expect("クライアントがイベントを受信できること");
            if let ConnectionEvent::PathValidated { path, success } = event {
                assert!(success, "優先アドレスの経路検証に成功すること");
                break path;
            }
        };
        assert_eq!(
            path.remote, preferred_addr,
            "検証された経路は優先アドレスであること"
        );
        assert_eq!(
            client.remote_addr(),
            preferred_addr,
            "クライアントは優先アドレスへ移っていること"
        );

        // 移行後もデータをやり取りできる
        let stream_id = client.open_bidi_stream().expect("ストリームを開けること");
        client
            .write_stream(stream_id, b"migrated", true)
            .expect("送信待ちに積めること");
        client.flush().await.expect("送信できること");

        // サーバーがデータを受け取るまでクライアントを駆動し続ける。サーバーも
        // 優先アドレスの経路を検証しており、その PATH_CHALLENGE に応答しないと
        // 経路が確立しない
        let mut received = None;
        while received.is_none() {
            tokio::select! {
                data = &mut rx => {
                    received = Some(data.expect("サーバーがデータを送ってくること"));
                }
                event = client.recv_event() => {
                    event.expect("クライアントがイベントを受信できること");
                }
            }
        }
        assert_eq!(
            received.expect("データを受信すること"),
            b"migrated",
            "移行後に受け取ったデータ"
        );
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// 応答が優先アドレスから送られること
///
/// 優先アドレスのソケットで受信したパケットへの応答は、同じアドレスから
/// 送らなければクライアントは受理しない (RFC 9000 Section 9.6.1)。
/// Retry はアドレス検証のためにトークン無しの Initial へ返るため、
/// 復号できない Initial でも応答を確認できる (RFC 9000 Section 8.1.2)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_response_is_sent_from_preferred_address() {
    let cert = TestCert::generate("preferred_address_send");
    let server = bind_server_with_preferred_addr(
        cert.cert_path(),
        cert.key_path(),
        ServerConfig::new(&[b"hq-interop"])
            .with_retry(shiguredo_ngtcp2::RetrySecret::from_bytes([0x6f; 32])),
    )
    .await;
    let preferred_addr = server
        .preferred_addr()
        .expect("優先アドレスが設定されていること");
    let server_task = tokio::spawn(async move {
        let mut server = server;
        loop {
            let _ = server.accept().await;
        }
    });

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用のソケットを用意できること");

        // 優先アドレスへ Initial を送る (中身は復号できないが応答は返る)
        let packet = make_initial(QuicVersion::V1.as_u32(), &[0x11; 16], &[0x22; 16]);
        probe
            .send_to(&packet, preferred_addr)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 1500];
        let (len, from) = timeout(PROBE_TIMEOUT, probe.recv_from(&mut buf))
            .await
            .expect("応答が返ること")
            .expect("受信できること");
        assert!(len > 0, "応答が空でないこと");
        assert_eq!(from, preferred_addr, "応答は優先アドレスから送られること");
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// 指定バージョンの Initial パケットを組み立てる
///
/// Version Negotiation と同様、応答の判定は復号より前に行われるため
/// 中身は暗号化しなくてよい。
fn make_initial(version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; shiguredo_ngtcp2::MIN_INITIAL_DATAGRAM_SIZE];
    data[0] = 0x80 | 0x40;
    data[1..5].copy_from_slice(&version.to_be_bytes());
    data[5] = dcid.len() as u8;
    data[6..6 + dcid.len()].copy_from_slice(dcid);
    let scid_offset = 6 + dcid.len();
    data[scid_offset] = scid.len() as u8;
    data[scid_offset + 1..scid_offset + 1 + scid.len()].copy_from_slice(scid);
    data
}
