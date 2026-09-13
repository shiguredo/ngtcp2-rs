//! Stateless Reset の e2e テスト (RFC 9000 Section 10.3)
//!
//! 実 UDP ソケットでサーバーを動かし、未知の DCID を持つ Short header パケットに
//! 対して Stateless Reset が返ること、そのトークンが秘密から正しく導出されること、
//! 短いパケットと引き渡し済みの接続には応答しないことを検証する。

use std::time::Duration;

use shiguredo_ngtcp2::{
    ConnectionId, MIN_STATELESS_RESET_SIZE, STATELESS_RESET_SECRET_LEN, STATELESS_RESET_TOKEN_LEN,
    write_stateless_reset,
};
use shiguredo_ngtcp2_tokio::{
    ClientConfig, ConnectionEvent, Server, ServerConfig, StatelessResetSecret, TransportParams,
};
use tokio::net::UdpSocket;
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

/// Stateless Reset の応答を待つタイムアウト
const RESET_TIMEOUT: Duration = Duration::from_secs(5);

/// 応答が無いことを確認するときの待ち時間
const NO_REPLY_TIMEOUT: Duration = Duration::from_millis(500);

/// 既知の秘密。導出されるトークンをテスト側でも計算できるようにする
const TEST_SECRET: [u8; STATELESS_RESET_SECRET_LEN] = [0x5a; 32];

/// テスト用の秘密を返す
fn test_secret() -> StatelessResetSecret {
    StatelessResetSecret::from_bytes(TEST_SECRET)
}

/// 秘密を設定したサーバーの構成を返す
fn server_config_with_secret() -> ServerConfig {
    ServerConfig::new(&[b"hq-interop"]).with_stateless_reset_secret(test_secret())
}

/// Short header パケットを組み立てる
///
/// 暗号化はしない。Stateless Reset の判定は復号より前に行われるため、
/// 中身は任意でよい。
fn make_short_header(dcid: &[u8], total_len: usize) -> Vec<u8> {
    let mut data = vec![0u8; total_len];
    // Short header: Header Form ビットが 1 (RFC 9000 Section 17.3)
    data[0] = 0x40;
    data[1..1 + dcid.len()].copy_from_slice(dcid);
    data
}

/// サーバーを駆動し続けるタスクを立てる
///
/// Stateless Reset はパケットの受信処理の中で送られるため、`accept` を
/// 回し続けなければならない。接続は成立させない。
fn spawn_server(mut server: Server) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let _ = server.accept().await;
        }
    })
}

/// 未知の DCID に対して Stateless Reset が返り、トークンが秘密から
/// 導出された値と一致すること (RFC 9000 Section 10.3.1 / 10.3.3)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stateless_reset_carries_derived_token() {
    let cert = TestCert::generate("reset_token");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(server_config_with_secret()),
    )
    .await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用のソケットを用意できること");

        // サーバーが発行していない DCID を使う
        let dcid = [0xccu8; 16];
        let packet = make_short_header(&dcid, 64);
        probe
            .send_to(&packet, server_addr)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 1500];
        let (len, from) = timeout(RESET_TIMEOUT, probe.recv_from(&mut buf))
            .await
            .expect("Stateless Reset が返ること")
            .expect("受信できること");
        assert_eq!(from, server_addr, "サーバーからの応答であること");

        // Short header 形式で先頭 2 ビットが 01 (RFC 9000 Section 10.3.3)
        assert_eq!(
            buf[0] >> 6,
            0b01,
            "Stateless Reset のヘッダー形式であること"
        );

        // 末尾 16 バイトが、同じ秘密から導出したトークンと一致すること
        let expected = test_secret()
            .token(&ConnectionId::new(&dcid).expect("DCID を作れること"))
            .expect("トークンを導出できること");
        assert!(
            len >= STATELESS_RESET_TOKEN_LEN,
            "トークンを収められる長さであること: {len}"
        );
        assert_eq!(
            &buf[len - STATELESS_RESET_TOKEN_LEN..len],
            expected.as_bytes(),
            "トークンが秘密から導出された値であること"
        );

        // 増幅攻撃に使われないよう、応答は元のパケットより長くないこと
        // (RFC 9000 Section 10.3.3)
        assert!(
            len <= packet.len(),
            "応答 ({len}) が元のパケット ({}) より長くないこと",
            packet.len()
        );
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// 短すぎるパケットには Stateless Reset を返さないこと
///
/// 応答は引き金になったパケットより短くしなければならず
/// (RFC 9000 Section 10.3.3)、最小長に満たないパケットには応答できない。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_no_stateless_reset_for_short_packet() {
    let cert = TestCert::generate("reset_short");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(server_config_with_secret()),
    )
    .await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用のソケットを用意できること");

        // Stateless Reset の最小長より 1 バイト短いパケットを送る
        let packet = make_short_header(&[0xddu8; 16], MIN_STATELESS_RESET_SIZE - 1);
        probe
            .send_to(&packet, server_addr)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 1500];
        let received = timeout(NO_REPLY_TIMEOUT, probe.recv_from(&mut buf)).await;
        assert!(
            received.is_err(),
            "短すぎるパケットには応答しないこと: {received:?}"
        );
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// accept で引き渡した接続の CID には Stateless Reset を返さないこと
///
/// ルーティングテーブルからは消えるが接続は同じプロセス内で生きているため、
/// リセットを返すと正常な接続を止めてしまう。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_no_stateless_reset_for_accepted_connection() {
    let cert = TestCert::generate("reset_taken");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(server_config_with_secret()),
    )
    .await;
    let server_addr = server.local_addr();

    let client_config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
    let (
        Pair {
            server: conn,
            client: _client,
        },
        server,
    ) = connect_with_server(server, client_config, "localhost").await;

    // サーバーが引き渡した接続の SCID (= クライアントの DCID)
    let scid = conn.connection_id();
    drop(conn);
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用のソケットを用意できること");
        let packet = make_short_header(scid.as_bytes(), 64);
        probe
            .send_to(&packet, server_addr)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 1500];
        let received = timeout(NO_REPLY_TIMEOUT, probe.recv_from(&mut buf)).await;
        assert!(
            received.is_err(),
            "引き渡した接続の CID には Stateless Reset を返さないこと: {received:?}"
        );
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// 導出したトークンで Stateless Reset パケットを書き出せること
///
/// サーバーは最初の SCID に対応するトークンをトランスポートパラメータで
/// 配布する (RFC 9000 Section 18.2) ため、ピアはその DCID に対する
/// Stateless Reset を検証できる。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_write_stateless_reset_with_server_scid_token() {
    let cert = TestCert::generate("reset_params");
    let secret = test_secret();
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(
            ServerConfig::new(&[b"hq-interop"])
                .with_transport_params(TransportParams::new())
                .with_stateless_reset_secret(secret.clone()),
        ),
    )
    .await;
    let client_config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
    let (
        Pair {
            server: conn,
            client,
        },
        _server,
    ) = connect_with_server(server, client_config, "localhost").await;

    let result = timeout(TEST_TIMEOUT, async {
        // サーバーの SCID からトークンを導出できること
        let scid = conn.connection_id();
        let token = secret
            .token(&scid)
            .expect("サーバーの SCID からトークンを導出できること");

        let mut buf = [0u8; 1200];
        let written = write_stateless_reset(&mut buf, &token, 1200)
            .expect("Stateless Reset を書き出せること");
        assert!(written > 0, "パケットが生成されること");
        assert_eq!(
            &buf[written - STATELESS_RESET_TOKEN_LEN..written],
            token.as_bytes(),
            "末尾にトークンが入ること"
        );

        // トークンを配布しても接続は正常に使えること
        assert!(
            !client.is_closed() && !conn.is_closed(),
            "トークンを配布しても接続は生きていること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 秘密を明示しなくても Stateless Reset が返ること
///
/// `Server::bind` が乱数から秘密を生成するため、設定なしでも
/// プロセスの寿命の間は Stateless Reset を送れる。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_default_secret_enables_stateless_reset() {
    let cert = TestCert::generate("reset_default_secret");
    let server = bind_server(cert.cert_path(), cert.key_path(), None).await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用のソケットを用意できること");
        let packet = make_short_header(&[0xeeu8; 16], 64);
        probe
            .send_to(&packet, server_addr)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 1500];
        let (len, from) = timeout(RESET_TIMEOUT, probe.recv_from(&mut buf))
            .await
            .expect("秘密を明示しなくても Stateless Reset が返ること")
            .expect("受信できること");
        assert_eq!(from, server_addr, "サーバーからの応答であること");
        assert_eq!(
            buf[0] >> 6,
            0b01,
            "Stateless Reset のヘッダー形式であること"
        );
        assert!(len > 0, "パケットが届くこと");
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// 明示した秘密がサーバー設定に保持されること
#[test]
fn test_server_config_holds_secret() {
    let config = ServerConfig::new(&[b"hq-interop"]);
    assert_eq!(
        config.stateless_reset_secret, None,
        "既定では秘密を設定しないこと"
    );

    let config = config.with_stateless_reset_secret(test_secret());
    assert_eq!(
        config.stateless_reset_secret,
        Some(test_secret()),
        "設定した秘密が保持されること"
    );
}

/// サーバーが再起動した後に Stateless Reset を受け取ったクライアントが
/// 接続を閉じること (RFC 9000 Section 10.3)
///
/// 同じアドレス・同じ秘密でサーバーを起動し直すことで再起動を模す。
/// 再起動後のサーバーは接続状態も引き渡し済み CID の記録も持たないため、
/// クライアントのパケットを未知の DCID とみなして Stateless Reset を返す。
/// クライアントは最初に受け取ったトランスポートパラメータのトークンと
/// 一致するため、これを受理して接続を終了する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_client_closes_after_server_restart() {
    let cert = TestCert::generate("reset_restart");

    // 1 つ目のサーバーで接続を確立する
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(server_config_with_secret()),
    )
    .await;
    let addr = server.local_addr();
    let client_config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
    let (
        Pair {
            server: conn,
            mut client,
        },
        first_server,
    ) = connect_with_server(server, client_config, "localhost").await;
    // サーバー側のハンドルとサーバー本体を捨てて、プロセスが終わった状態を作る。
    // ソケットは Arc で共有されているため、両方を落とさないと
    // 同じアドレスで起動し直せない。
    drop(conn);
    drop(first_server);

    // 同じアドレス・同じ秘密で起動し直す (再起動)
    let restarted = Server::bind(
        addr,
        cert.cert_path(),
        cert.key_path(),
        Some(server_config_with_secret()),
    )
    .await
    .expect("同じアドレスでサーバーを起動し直せること");
    let server_task = spawn_server(restarted);

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = client.open_bidi_stream().expect("ストリームを開けること");

        let mut saw_reset = false;
        let mut saw_closed = false;
        while !saw_closed {
            // データを送り続ける。draining 状態では書き込みも送信も失敗するため、
            // 結果は無視してイベントの受信だけを続ける
            let _ = client.write_stream(stream_id, b"ping", false);
            let _ = client.flush().await;

            match timeout(PUMP_INTERVAL, client.recv_event()).await {
                Ok(Ok(ConnectionEvent::StatelessResetReceived)) => saw_reset = true,
                Ok(Ok(ConnectionEvent::ConnectionClosed { .. })) => saw_closed = true,
                Ok(Ok(_)) => {}
                // イベントを配信し終えたあとは ConnectionClosed エラーになる
                Ok(Err(_)) => saw_closed = true,
                Err(_) => {}
            }
        }

        assert!(
            saw_reset,
            "再起動したサーバーの Stateless Reset を受け取ること"
        );
        assert!(saw_closed, "Stateless Reset のあとに接続が閉じること");
        assert!(client.is_closed(), "接続が閉じた状態になること");
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}
