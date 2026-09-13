//! QUIC バージョン交渉の e2e テスト
//!
//! 実 UDP ソケットで QUIC v1 / v2 のハンドシェイクを検証し、サポート外の
//! バージョンの Initial に対してサーバーが Version Negotiation パケットを
//! 返すことを確認する (RFC 9000 Section 6 / RFC 9369)。

use std::time::Duration;

use shiguredo_ngtcp2::QuicVersion;
use shiguredo_ngtcp2_tokio::{
    Client, ClientConfig, ConnectionEvent, Error, Server, ServerConfig, TransportParams,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;
#[path = "helpers/pair.rs"]
mod pair;

use certs::TestCert;
use pair::{Pair, bind_server, connect_with_server, ephemeral_addr};

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Version Negotiation の応答を待つタイムアウト
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// 既定のクライアント設定 (証明書検証なし)
fn default_client_config() -> ClientConfig {
    ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false)
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

/// Initial パケットの先頭バイトを返す
///
/// 種別ビットは QUIC バージョンごとに異なり、Initial は v1 が 0x0
/// (RFC 9000 Section 17.2)、v2 が 0x1 (RFC 9369 Section 3.2)。
fn initial_first_byte(version: u32) -> u8 {
    let type_bits = if version == QuicVersion::V2.as_u32() {
        0x1
    } else {
        0x0
    };
    0x80 | 0x40 | (type_bits << 4)
}

/// 指定バージョンの Initial パケットを組み立てる
///
/// 中身は暗号化されていないため復号には失敗するが、Version Negotiation の
/// 判定は復号より前に行われる (RFC 9000 Section 6)。
fn make_initial(version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; shiguredo_ngtcp2::MIN_INITIAL_DATAGRAM_SIZE];
    data[0] = initial_first_byte(version);
    data[1..5].copy_from_slice(&version.to_be_bytes());
    data[5] = dcid.len() as u8;
    data[6..6 + dcid.len()].copy_from_slice(dcid);
    let scid_offset = 6 + dcid.len();
    data[scid_offset] = scid.len() as u8;
    data[scid_offset + 1..scid_offset + 1 + scid.len()].copy_from_slice(scid);
    data
}

/// サーバーを起動して accept を回し続けるタスクを立てる
///
/// Version Negotiation の検証では接続は成立しないため、accept は返らない。
/// パケットの処理だけを回す。
fn spawn_server(mut server: Server) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // 不正なパケットでは接続が作られないため accept は終わらない。
            // 終わった場合 (エラー) もサーバーを止めないためにループを続ける。
            let _ = server.accept().await;
        }
    })
}

/// Version Negotiation パケットを検証する
///
/// RFC 9000 Section 17.2.1 の形式に従い、バージョンフィールドは 0、
/// DCID はクライアントの SCID、SCID はクライアントの DCID になる。
fn assert_version_negotiation(
    packet: &[u8],
    client_dcid: &[u8],
    client_scid: &[u8],
    expected: &[u32],
) {
    assert_ne!(packet[0] & 0x80, 0, "Long header form bit が立っていること");
    assert_eq!(&packet[1..5], &[0, 0, 0, 0], "バージョンが 0 であること");

    let dcid_len = packet[5] as usize;
    assert_eq!(dcid_len, client_scid.len(), "DCID 長");
    assert_eq!(
        &packet[6..6 + dcid_len],
        client_scid,
        "DCID はクライアントの SCID であること"
    );

    let scid_offset = 6 + dcid_len;
    let scid_len = packet[scid_offset] as usize;
    assert_eq!(scid_len, client_dcid.len(), "SCID 長");
    assert_eq!(
        &packet[scid_offset + 1..scid_offset + 1 + scid_len],
        client_dcid,
        "SCID はクライアントの DCID であること"
    );

    let mut versions = Vec::new();
    let mut pos = scid_offset + 1 + scid_len;
    while pos + 4 <= packet.len() {
        versions.push(u32::from_be_bytes([
            packet[pos],
            packet[pos + 1],
            packet[pos + 2],
            packet[pos + 3],
        ]));
        pos += 4;
    }
    assert_eq!(&versions, expected, "サポートするバージョンの一覧");
}

/// サポート外のバージョンの Initial に Version Negotiation が返ること
/// (RFC 9000 Section 6)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_sends_version_negotiation_for_unknown_version() {
    let cert = TestCert::generate("vn_unknown");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"])),
    )
    .await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用のソケットを用意できること");

        // 未知のバージョン 0xdeadbeef の Initial を送る
        let client_dcid = [0x11u8; 8];
        let client_scid = [0x22u8; 16];
        let packet = make_initial(0xdead_beef, &client_dcid, &client_scid);
        probe
            .send_to(&packet, server_addr)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 1500];
        let (len, from) = timeout(PROBE_TIMEOUT, probe.recv_from(&mut buf))
            .await
            .expect("Version Negotiation が返ること")
            .expect("受信できること");
        assert_eq!(from, server_addr, "サーバーからの応答であること");

        assert_version_negotiation(
            &buf[..len],
            &client_dcid,
            &client_scid,
            &[QuicVersion::V1.as_u32(), QuicVersion::V2.as_u32()],
        );
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// サポートしないバージョンの Initial にも Version Negotiation が返ること
///
/// QUIC v2 は ngtcp2 がサポートするバージョンだが、サーバーの設定で
/// v1 だけを許可した場合も Version Negotiation を返さなければならない
/// (RFC 9000 Section 6)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_sends_version_negotiation_for_disabled_version() {
    let cert = TestCert::generate("vn_disabled");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"]).with_quic_versions(&[QuicVersion::V1])),
    )
    .await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    let result = timeout(TEST_TIMEOUT, async {
        let probe = UdpSocket::bind(ephemeral_addr())
            .await
            .expect("検証用のソケットを用意できること");

        // QUIC v2 の Initial を送る
        let client_dcid = [0x33u8; 8];
        let client_scid = [0x44u8; 16];
        let packet = make_initial(QuicVersion::V2.as_u32(), &client_dcid, &client_scid);
        assert_eq!(packet[0], 0xd0, "QUIC v2 の Initial の先頭バイト");
        probe
            .send_to(&packet, server_addr)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 1500];
        let (len, from) = timeout(PROBE_TIMEOUT, probe.recv_from(&mut buf))
            .await
            .expect("Version Negotiation が返ること")
            .expect("受信できること");
        assert_eq!(from, server_addr, "サーバーからの応答であること");

        assert_version_negotiation(
            &buf[..len],
            &client_dcid,
            &client_scid,
            &[QuicVersion::V1.as_u32()],
        );
    })
    .await;

    server_task.abort();
    result.expect("テストがタイムアウトしないこと");
}

/// 既定の設定では QUIC v1 でハンドシェイクが完了すること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_v1_handshake_negotiates_v1() {
    let cert = TestCert::generate("vn_v1");
    let pair = connect_pair(&cert, None, default_client_config()).await;

    let result = timeout(TEST_TIMEOUT, async {
        assert_eq!(
            pair.client.negotiated_version(),
            Some(QuicVersion::V1),
            "クライアントの交渉バージョンが v1 であること"
        );
        assert_eq!(
            pair.server.negotiated_version(),
            Some(QuicVersion::V1),
            "サーバーの交渉バージョンが v1 であること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// QUIC v2 でハンドシェイクが完了し、データも流れること (RFC 9369)
///
/// QUIC v2 は Initial の鍵導出とヘッダー保護のラベルが v1 と異なるため、
/// 両側で同じバージョンを使って初めて成立する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_v2_handshake_negotiates_v2() {
    let cert = TestCert::generate("vn_v2");
    let client_config = default_client_config().with_quic_version(QuicVersion::V2);
    let mut pair = connect_pair(&cert, None, client_config).await;

    let result = timeout(TEST_TIMEOUT, async {
        assert_eq!(
            pair.client.negotiated_version(),
            Some(QuicVersion::V2),
            "クライアントの交渉バージョンが v2 であること"
        );
        assert_eq!(
            pair.server.negotiated_version(),
            Some(QuicVersion::V2),
            "サーバーの交渉バージョンが v2 であること"
        );

        // v2 でもストリームデータが流れること
        let stream_id = pair
            .client
            .open_bidi_stream()
            .expect("ストリームを開けること");
        pair.client
            .write_stream(stream_id, b"over quic v2", true)
            .expect("送信待ちに積めること");
        pair.client.flush().await.expect("データを送信できること");

        let mut received = Vec::new();
        while received.is_empty() {
            if let ConnectionEvent::StreamData {
                stream_id: sid,
                data,
                ..
            } = pair
                .server
                .recv_event()
                .await
                .expect("サーバーがイベントを受信できること")
            {
                assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                received = data;
            }
        }
        assert_eq!(received, b"over quic v2", "受信データが一致すること");
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// サーバーがサポートしないバージョンを使うクライアントは接続できないこと
///
/// 本実装のクライアントは Version Negotiation によるバージョンの切り替えを
/// 行わないため、ハンドシェイクのタイムアウトとして観測される。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_client_with_disabled_version_fails() {
    let cert = TestCert::generate("vn_client_mismatch");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"]).with_quic_versions(&[QuicVersion::V2])),
    )
    .await;
    let server_addr = server.local_addr();
    let server_task = spawn_server(server);

    // v1 を使うクライアントは v2 限定のサーバーと接続できない
    let client_config = default_client_config()
        .with_quic_version(QuicVersion::V1)
        .with_handshake_timeout(Duration::from_secs(2));

    let result = timeout(
        TEST_TIMEOUT,
        Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &client_config),
    )
    .await
    .expect("テストがタイムアウトしないこと");

    server_task.abort();

    assert!(
        result.is_err(),
        "バージョンが合わない場合は接続に失敗すること"
    );
}

/// サポートするバージョンが空の設定はバインド時に拒否されること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_bind_rejects_empty_quic_versions() {
    let cert = TestCert::generate("vn_empty_versions");
    let config = ServerConfig::new(&[b"hq-interop"]).with_quic_versions(&[]);

    let result = Server::bind(
        ephemeral_addr(),
        cert.cert_path(),
        cert.key_path(),
        Some(config),
    )
    .await;

    match result {
        Err(Error::InvalidArgument(_)) => {}
        Err(other) => panic!("InvalidArgument が返ること: {other:?}"),
        Ok(_) => panic!("サポートするバージョンが空の設定は拒否されること"),
    }
}

/// トランスポートパラメータを設定してもバージョン交渉に影響しないこと
///
/// `ServerConfig::with_quic_versions` と `with_transport_params` を併用できる
/// ことを確認する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_versions_with_transport_params() {
    let cert = TestCert::generate("vn_with_params");
    let params = TransportParams::new().with_max_idle_timeout(Duration::from_secs(10));
    let server_config = ServerConfig::new(&[b"hq-interop"])
        .with_transport_params(params)
        .with_quic_versions(&[QuicVersion::V2, QuicVersion::V1]);
    let client_config = default_client_config().with_quic_version(QuicVersion::V2);

    let pair = connect_pair(&cert, Some(server_config), client_config).await;

    let result = timeout(TEST_TIMEOUT, async {
        assert_eq!(
            pair.server.negotiated_version(),
            Some(QuicVersion::V2),
            "v2 を先頭に設定しても v2 で接続できること"
        );
        assert_eq!(
            pair.client.negotiated_version(),
            Some(QuicVersion::V2),
            "クライアントも v2 であること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 互換バージョン交渉で v2 が選ばれること (RFC 9368)
///
/// クライアントは v1 で接続を開始し、提示するバージョンとして v1 と v2 を
/// 通知する。サーバーは v2 を優先するため、Version Negotiation パケットを
/// 返さずに v2 で接続を確立する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_compatible_version_negotiation_selects_v2() {
    let cert = TestCert::generate("compatible_version_negotiation");
    let server_config = ServerConfig::new(&[b"hq-interop"])
        .with_quic_versions(&[QuicVersion::V1, QuicVersion::V2])
        .with_preferred_versions(&[QuicVersion::V2]);
    let server = bind_server(cert.cert_path(), cert.key_path(), Some(server_config)).await;
    let server_addr = server.local_addr();

    // サーバーは接続を受け入れ、交渉されたバージョンを通知する
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut server = server;
        if let Ok(Some(conn)) = server.accept().await {
            let _ = tx.send(conn.negotiated_version());
        }
    });

    let client_config = default_client_config()
        .with_quic_version(QuicVersion::V1)
        .with_preferred_versions(&[QuicVersion::V1, QuicVersion::V2]);

    let result = timeout(TEST_TIMEOUT, async {
        let conn =
            Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &client_config)
                .await
                .expect("互換バージョン交渉で接続できること");
        let server_version = rx.await.expect("サーバーが接続を受け入れること");
        assert_eq!(
            conn.negotiated_version(),
            Some(QuicVersion::V2),
            "サーバーが優先する v2 が選ばれること"
        );

        assert_eq!(
            server_version,
            Some(QuicVersion::V2),
            "サーバー側でも v2 が選ばれること"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}
