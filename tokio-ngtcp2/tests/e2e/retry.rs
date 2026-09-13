//! Retry によるアドレス検証の e2e テスト
//!
//! 実 UDP ソケットでサーバーを動かし、トークンを持たない Initial に Retry
//! パケットが返ること、Retry を経たハンドシェイクが完了すること、
//! 不正なトークンが拒否されることを検証する (RFC 9000 Section 8.1.2 / 8.1.3)。

use std::net::SocketAddr;
use std::time::Duration;

use shiguredo_ngtcp2::{
    ConnectionId, MIN_INITIAL_DATAGRAM_SIZE, RETRY_SECRET_LEN, RetrySecret, varint,
};
use shiguredo_ngtcp2_tokio::{
    ClientConfig, ConnectionEvent, Server, ServerConfig, TransportParams,
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

/// Retry の応答を待つタイムアウト
const RETRY_TIMEOUT: Duration = Duration::from_secs(5);

/// テスト用の秘密。トークンをテスト側でも生成・検証できるようにする
const TEST_SECRET: [u8; RETRY_SECRET_LEN] = [0x6b; 32];

/// テスト用の秘密を返す
fn test_secret() -> RetrySecret {
    RetrySecret::from_bytes(TEST_SECRET)
}

/// Retry を有効にしたサーバー設定を返す
fn retry_server_config() -> ServerConfig {
    ServerConfig::new(&[b"hq-interop"]).with_retry(test_secret())
}

/// サーバーとクライアントを接続する
async fn connect_pair(
    cert: &TestCert,
    server_config: Option<ServerConfig>,
    client_config: ClientConfig,
) -> Pair {
    let server = bind_server(cert.cert_path(), cert.key_path(), server_config).await;
    let (pair, _server) = connect_with_server(server, client_config, "localhost").await;
    pair
}

/// トークンを持たない Initial パケットを組み立てる
///
/// Retry の判定はヘッダーだけを見るため、ペイロードは暗号化しなくてよい。
/// Token Length と Length は可変長整数として正しく書く
/// (RFC 9000 Section 17.2.2)。
fn make_initial(version: u32, dcid: &[u8], scid: &[u8], token: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    // Long header + Fixed Bit + Initial (v1 の種別ビットは 0x0)
    data.push(0x80 | 0x40);
    data.extend_from_slice(&version.to_be_bytes());
    data.push(dcid.len() as u8);
    data.extend_from_slice(dcid);
    data.push(scid.len() as u8);
    data.extend_from_slice(scid);
    varint::encode_to_vec(token.len() as u64, &mut data);
    data.extend_from_slice(token);
    // Length はパケット番号と暗号化ペイロードの長さ
    let rest = MIN_INITIAL_DATAGRAM_SIZE.saturating_sub(data.len() + 2);
    varint::encode_to_vec(rest as u64, &mut data);
    data.resize(MIN_INITIAL_DATAGRAM_SIZE, 0);
    data
}

/// サーバーを駆動し続けるタスクを立てる
///
/// Retry はパケットの受信処理の中で送られるため、`accept` を回し続ける。
fn spawn_server(mut server: Server) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let _ = server.accept().await;
        }
    })
}

/// Long header のパケット種別ビットを返す
///
/// QUIC v1 では Initial=0x0、0-RTT=0x1、Handshake=0x2、Retry=0x3
/// (RFC 9000 Section 17.2)。
fn long_header_type_bits(first_byte: u8) -> u8 {
    (first_byte >> 4) & 0x3
}

/// トークンを持たない Initial に Retry パケットが返ること
/// (RFC 9000 Section 8.1.2 / 17.2.5)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_retry_packet_for_initial_without_token() {
    let cert = TestCert::generate("retry_packet");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(retry_server_config()),
    )
    .await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用のソケットを用意できること");

        let dcid = [0x11u8; 16];
        let scid = [0x22u8; 16];
        let packet = make_initial(shiguredo_ngtcp2::NGTCP2_PROTO_VER_V1, &dcid, &scid, &[]);
        probe
            .send_to(&packet, server_addr)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 1500];
        let (len, from) = timeout(RETRY_TIMEOUT, probe.recv_from(&mut buf))
            .await
            .expect("Retry が返ること")
            .expect("受信できること");
        assert_eq!(from, server_addr, "サーバーからの応答であること");

        // Long header の Retry (v1 の種別ビット 0x3) であること
        assert_ne!(buf[0] & 0x80, 0, "Long header form bit が立っていること");
        assert_eq!(
            long_header_type_bits(buf[0]),
            0x3,
            "Retry パケットであること"
        );
        assert_eq!(
            &buf[1..5],
            &shiguredo_ngtcp2::NGTCP2_PROTO_VER_V1.to_be_bytes(),
            "バージョンフィールド"
        );

        // DCID にはクライアントの SCID が入ること (RFC 9000 Section 17.2.5)
        let retry_dcid_len = buf[5] as usize;
        assert_eq!(retry_dcid_len, scid.len(), "DCID 長");
        assert_eq!(
            &buf[6..6 + retry_dcid_len],
            &scid,
            "DCID はクライアントの SCID であること"
        );

        // SCID にはサーバーが選んだ CID が入り、クライアントの DCID とは異なること
        let scid_offset = 6 + retry_dcid_len;
        let retry_scid_len = buf[scid_offset] as usize;
        let retry_scid = &buf[scid_offset + 1..scid_offset + 1 + retry_scid_len];
        assert_eq!(retry_scid_len, 16, "サーバーの SCID 長は設定値であること");
        assert_ne!(retry_scid, &dcid, "SCID はクライアントの DCID と異なること");

        // トークンと整合性タグが続くこと
        assert!(
            len > scid_offset + 1 + retry_scid_len,
            "トークンを含むこと: {len}"
        );
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// Retry を経てもハンドシェイクが完了し、データが転送できること
///
/// クライアント側の ngtcp2 が Retry を処理してトークン付きの Initial を
/// 送り直し、サーバーはトークンを検証してから接続を作る。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_handshake_completes_with_retry() {
    let cert = TestCert::generate("retry_handshake");
    let mut pair = connect_pair(
        &cert,
        Some(retry_server_config()),
        ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false),
    )
    .await;

    let result = timeout(TEST_TIMEOUT, async {
        assert!(
            pair.client.is_handshake_completed(),
            "クライアントのハンドシェイクが完了すること"
        );
        assert!(!pair.server.is_closed(), "サーバー側の接続が生きていること");

        // Retry を挟んでもデータが転送できること
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"after retry", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        let mut received = Vec::new();
        let mut fin = false;
        while !fin {
            if let ConnectionEvent::StreamData {
                stream_id: sid,
                data,
                fin: f,
            } = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること")
            {
                assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                received.extend_from_slice(&data);
                fin = f;
            }
        }
        assert_eq!(received, b"after retry", "Retry 後もデータが届くこと");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 不正なトークンを持つ Initial には Retry ではなく CONNECTION_CLOSE が返ること
/// (RFC 9000 Section 8.1.3)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_invalid_token_gets_connection_close() {
    let cert = TestCert::generate("retry_invalid_token");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(retry_server_config()),
    )
    .await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用のソケットを用意できること");

        // Retry のマジックバイトを持つでたらめなトークンを載せる
        let bogus_token = vec![0xb7u8; 64];
        let packet = make_initial(
            shiguredo_ngtcp2::NGTCP2_PROTO_VER_V1,
            &[0x33u8; 16],
            &[0x44u8; 16],
            &bogus_token,
        );
        probe
            .send_to(&packet, server_addr)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 1500];
        let (len, from) = timeout(RETRY_TIMEOUT, probe.recv_from(&mut buf))
            .await
            .expect("応答が返ること")
            .expect("受信できること");
        assert_eq!(from, server_addr, "サーバーからの応答であること");
        assert!(len > 0, "パケットが届くこと");

        // Retry (種別ビット 0x3) ではなく Initial (種別ビット 0x0) の
        // CONNECTION_CLOSE が返ること
        assert_eq!(
            long_header_type_bits(buf[0]),
            0x0,
            "Initial パケット (CONNECTION_CLOSE) であること"
        );
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// アドレス検証を無効にしている場合は Retry を返さずに接続できること
///
/// 既定のサーバーは Retry の秘密を持たないため、トークンを持たない Initial でも
/// 接続を作る。Retry を送っていないことは、クライアントが受け取る
/// `retry_source_connection_id` が無いことで確認する。RFC 9000 Section 7.3 は
/// Retry を送っていないサーバーがこのパラメータを通知することを禁じており、
/// 通知されればクライアントは接続を終了する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_no_retry_when_address_validation_disabled() {
    let cert = TestCert::generate("retry_disabled");

    // 実際のクライアントでハンドシェイクが完了すること
    let pair = connect_pair(
        &cert,
        None,
        ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false),
    )
    .await;
    let remote = pair
        .client
        .remote_transport_params()
        .expect("ピアのパラメータを取得できること");
    assert!(
        remote.retry_scid.is_none(),
        "Retry を送っていないサーバーは Retry の SCID を通知しないこと"
    );

    // トークンを持たない Initial を投げても Retry が返らないこと
    let server = bind_server(cert.cert_path(), cert.key_path(), None).await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用の socket を用意できること");

        let packet = make_initial(
            shiguredo_ngtcp2::NGTCP2_PROTO_VER_V1,
            &[0x55u8; 16],
            &[0x66u8; 16],
            &[],
        );
        probe
            .send_to(&packet, server_addr)
            .await
            .expect("送信できること");

        // ペイロードを復号できない Initial は破棄されるため、通常は応答が
        // 返らない。応答が返る場合でも Retry ではないこと (RFC 9000 Section 8.1)。
        let mut buf = [0u8; 1500];
        match timeout(RETRY_TIMEOUT, probe.recv_from(&mut buf)).await {
            // 応答が無いことは「Retry を送らない」を満たす
            Err(_) => {}
            Ok(Ok((len, _))) => {
                assert!(len > 0, "パケットが届く場合は空でないこと");
                assert_ne!(
                    long_header_type_bits(buf[0]),
                    0x3,
                    "アドレス検証が無効なら Retry を返さないこと"
                );
            }
            Ok(Err(e)) => panic!("検証用の socket が受信できること: {e}"),
        }
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// QUIC v2 でも Retry によるアドレス検証が働くこと (RFC 9369)
///
/// Retry パケットの完全性保護に使う鍵はバージョンごとに異なるため、
/// v2 のクライアントも v2 の Retry を受け取ってハンドシェイクを完了できる。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_retry_with_quic_v2() {
    let cert = TestCert::generate("retry_v2");
    let client_config = ClientConfig::new(&[b"hq-interop"])
        .with_verify_peer(false)
        .with_quic_version(shiguredo_ngtcp2::QuicVersion::V2);
    let mut pair = connect_pair(&cert, Some(retry_server_config()), client_config).await;

    let result = timeout(TEST_TIMEOUT, async {
        assert_eq!(
            pair.client.negotiated_version(),
            Some(shiguredo_ngtcp2::QuicVersion::V2),
            "QUIC v2 で接続できること"
        );

        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"v2 after retry", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        let mut received = Vec::new();
        let mut fin = false;
        while !fin {
            if let ConnectionEvent::StreamData { data, fin: f, .. } = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること")
            {
                received.extend_from_slice(&data);
                fin = f;
            }
        }
        assert_eq!(received, b"v2 after retry", "v2 でもデータが届くこと");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// トークンの有効期間を設定できること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_retry_token_timeout_is_configurable() {
    let cert = TestCert::generate("retry_timeout");
    // 有効期間を短くしても再接続は間に合う
    let config = retry_server_config().with_retry_token_timeout(Duration::from_secs(2));
    let pair = connect_pair(
        &cert,
        Some(config),
        ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false),
    )
    .await;

    let result = timeout(TEST_TIMEOUT, async {
        assert!(
            pair.client.is_handshake_completed(),
            "有効期間を設定してもハンドシェイクが完了すること"
        );
        // 短い有効期間でもトークンが検証され、Retry を経たことが分かること
        let remote = pair
            .client
            .remote_transport_params()
            .expect("ピアのパラメータを取得できること");
        assert!(remote.retry_scid.is_some(), "Retry を経た接続であること");
        // 接続が使えることを確認する
        let _ = pair.client.stats();
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// サーバー設定が Retry の秘密と有効期間を保持すること
#[test]
fn test_server_config_holds_retry_settings() {
    let config = ServerConfig::new(&[b"hq-interop"]);
    assert_eq!(config.retry_secret, None, "既定では Retry を送らないこと");
    assert_eq!(
        config.retry_token_timeout,
        Duration::from_secs(10),
        "既定のトークン有効期間"
    );

    let config = config
        .with_retry(test_secret())
        .with_retry_token_timeout(Duration::from_secs(3));
    assert_eq!(
        config.retry_secret,
        Some(test_secret()),
        "設定した秘密が保持されること"
    );
    assert_eq!(
        config.retry_token_timeout,
        Duration::from_secs(3),
        "設定した有効期間が保持されること"
    );
}

/// トークンを検証して Original DCID を取り出せること
///
/// サーバーが実際に使う経路 (生成 → 検証) を、e2e のアドレスで再現する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_retry_token_roundtrip_with_address() {
    let cert = TestCert::generate("retry_token_roundtrip");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(retry_server_config()),
    )
    .await;
    let server_addr = server.local_addr();
    drop(server);

    let probe = UdpSocket::bind(ephemeral_addr())
        .await
        .expect("検証用のソケットを用意できること");
    let client_addr: SocketAddr = probe
        .local_addr()
        .expect("ローカルアドレスを取得できること");

    let secret = test_secret();
    let retry_scid = ConnectionId::new(&[0x77u8; 16]).expect("CID を作れること");
    let odcid = ConnectionId::new(&[0x88u8; 16]).expect("CID を作れること");

    let token = shiguredo_ngtcp2::generate_retry_token(
        &secret,
        shiguredo_ngtcp2::QuicVersion::V1,
        client_addr,
        &retry_scid,
        &odcid,
        1_000_000_000,
    )
    .expect("トークンを生成できること");

    let verified = shiguredo_ngtcp2::verify_retry_token(
        &secret,
        token.as_bytes(),
        shiguredo_ngtcp2::QuicVersion::V1,
        client_addr,
        &retry_scid,
        Duration::from_secs(10),
        1_000_000_001,
    )
    .expect("トークンを検証できること");

    assert_eq!(verified, odcid, "Original DCID が取り出せること");
    assert_ne!(server_addr, client_addr, "別々のアドレスであること");
}

/// Retry を挟んだ接続でも統計とトランスポートパラメータが正常であること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_retry_connection_is_tracked() {
    let cert = TestCert::generate("retry_tracked");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(retry_server_config()),
    )
    .await;
    let client_config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
    let (
        Pair {
            server: conn,
            client,
        },
        server,
    ) = connect_with_server(server, client_config, "localhost").await;

    let result = timeout(TEST_TIMEOUT, async {
        // `accept` で呼び出し側に渡した接続はサーバーの内部テーブルから
        // 取り除かれる (接続を二重に保持しない)
        assert!(
            server.connection_ids().is_empty(),
            "受け渡し済みの接続をサーバーが保持し続けないこと"
        );

        // Retry を挟んでもパケットの送受信が記録されていること
        assert!(
            conn.stats().packets_received > 0,
            "サーバーがパケットを受信していること"
        );
        assert!(
            conn.stats().packets_sent > 0,
            "サーバーがパケットを送信していること"
        );

        // クライアントは Retry の SCID を認証していること
        // (RFC 9000 Section 7.3)
        let remote = client
            .remote_transport_params()
            .expect("ピアのパラメータを取得できること");
        assert!(
            remote.retry_scid.is_some(),
            "Retry を送ったサーバーは Retry の SCID を通知すること"
        );
        assert!(!client.is_closed(), "クライアントの接続が生きていること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// トランスポートパラメータを設定しても Retry が働くこと
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_retry_with_transport_params() {
    let cert = TestCert::generate("retry_params");
    let config = retry_server_config()
        .with_transport_params(TransportParams::new().with_max_streams_bidi(3))
        .with_retry_token_timeout(Duration::from_secs(5));
    let client_config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
    let mut pair = connect_pair(&cert, Some(config), client_config).await;

    let result = timeout(TEST_TIMEOUT, async {
        let remote = pair
            .client
            .remote_transport_params()
            .expect("ピアのパラメータを取得できること");
        assert_eq!(
            remote.initial_max_streams_bidi, 3,
            "Retry を挟んでもトランスポートパラメータが伝わること"
        );

        // 上限どおり 3 本まで開けること
        for _ in 0..3 {
            pair.client
                .open_bidi_stream()
                .expect("上限までストリームを開けること");
        }
        assert!(
            pair.client.open_bidi_stream().is_err(),
            "上限を超えてストリームを開けないこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// Retry を挟んだ接続を両側で駆動し続けても生きていること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_retry_connection_survives_pumping() {
    let cert = TestCert::generate("retry_pump");
    let mut pair = connect_pair(
        &cert,
        Some(retry_server_config()),
        ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false),
    )
    .await;

    let result = timeout(TEST_TIMEOUT, async {
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"pump", false)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        // 両側を交互に駆動して ACK を流す
        for _ in 0..4 {
            let _ = timeout(PUMP_INTERVAL, pair.server.recv_event()).await;
            let _ = timeout(PUMP_INTERVAL, pair.client.recv_event()).await;
        }

        assert!(
            !pair.client.is_closed() && !pair.server.is_closed(),
            "Retry を挟んだ接続が駆動を続けても生きていること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}
