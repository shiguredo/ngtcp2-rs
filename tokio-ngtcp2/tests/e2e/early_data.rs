//! 0-RTT (early data) の e2e テスト (RFC 9001 Section 4.6)
//!
//! 実 UDP ソケットと実際の TLS で、1 回目の接続で保存したセッション情報を
//! 使って 2 回目の接続のハンドシェイク完了前にデータを送れることを検証する。
//! 0-RTT が使われたかどうかは `is_in_early_data` で観測する。ハンドシェイク
//! 完了前に送ったデータが届いただけでは、1-RTT に格上げされた場合と区別が
//! つかないため。

use std::time::Duration;

use shiguredo_ngtcp2::{Error, RETRY_SECRET_LEN, RetrySecret};
use shiguredo_ngtcp2_tokio::{
    AcceptedConnection, Client, ClientConfig, ClientConnection, ConnectionEvent, Server,
    ServerConfig, SessionTicket,
};
use tokio::time::timeout;

#[path = "helpers/certs.rs"]
mod certs;
#[path = "helpers/pair.rs"]
mod pair;

use certs::TestCert;
use pair::{bind_server, connect_with_server, ephemeral_addr};

/// テスト全体のタイムアウト
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Retry を有効にしたテストで使う秘密
const RETRY_SECRET_BYTES: [u8; RETRY_SECRET_LEN] = [0x6c; 32];

/// サーバーが受信したデータをそのまま送り返すまで駆動する
///
/// クライアントがデータの到達を確認するための応答として使う。
/// 接続が閉じた場合はそこまでに受信したデータを返す。
async fn echo_until_closed(conn: &mut AcceptedConnection) -> Vec<u8> {
    let mut received = Vec::new();
    loop {
        match conn.recv_event().await {
            Ok(ConnectionEvent::StreamData {
                stream_id,
                data,
                fin,
            }) => {
                conn.extend_max_stream_offset(stream_id, data.len() as u64)
                    .expect("フロー制御クレジットを戻せること");
                received.extend_from_slice(&data);
                // 受け取ったデータをそのまま送り返す。クライアントはこれで
                // データがサーバーに届いたことを確認できる
                conn.write_stream(stream_id, &data, fin)
                    .expect("受信したデータを送り返せること");
            }
            Ok(ConnectionEvent::ConnectionClosed { .. }) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    received
}

/// サーバーが受け入れた接続の観測結果
struct Accepted {
    /// 受け取ったデータ
    data: Vec<u8>,
    /// 0-RTT (early data) で届いたデータを受信したかどうか
    ///
    /// 0-RTT かどうかはデータを受け取った時点でしか判定できないため、
    /// サーバーは接続に記録した結果 ([`AcceptedConnection::received_early_data`])
    /// を使う。
    received_early_data: bool,
}

/// 接続を 1 つ受け入れて、閉じられるまで駆動する
async fn accept_and_echo(server: &mut Server) -> Accepted {
    let mut conn = server
        .accept()
        .await
        .expect("accept が成功すること")
        .expect("接続が受け入れられること");
    let data = echo_until_closed(&mut conn).await;
    // データを受け取った時点の判定結果を接続から取り出す
    let received_early_data = conn.received_early_data();
    Accepted {
        data,
        received_early_data,
    }
}

/// 証明書検証を無効にしたクライアント設定を返す
fn insecure_client_config() -> ClientConfig {
    ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false)
}

/// 1 回目の接続でセッションチケットを取得する
///
/// セッションチケットはハンドシェイクの完了後にサーバーから届くため
/// (RFC 8446 Section 4.6.1)、届くまでパケットを処理し続ける。
async fn fetch_session_ticket(client: &mut ClientConnection) -> SessionTicket {
    loop {
        if let Some(ticket) = client
            .take_session_ticket()
            .expect("セッション情報を取得できること")
        {
            return ticket;
        }
        // チケットはサーバーが自発的に送るため、イベントが無くても
        // パケットの処理は進む。ここではイベントを待つだけでよい
        client.recv_event().await.expect("イベントを受信できること");
    }
}

/// ハンドシェイクが完了するまで駆動し、0-RTT が拒否されたかどうかを返す
async fn drive_until_handshake_completed(client: &mut ClientConnection) -> bool {
    let mut rejected = false;
    while !client.is_handshake_completed() {
        match client.recv_event().await.expect("イベントを受信できること") {
            ConnectionEvent::EarlyDataRejected => rejected = true,
            ConnectionEvent::ConnectionClosed { reason, .. } => {
                panic!("接続が閉じられた: {reason}")
            }
            _ => {}
        }
    }
    rejected
}

/// サーバーが送り返したデータを待つ
async fn recv_echo(client: &mut ClientConnection) -> Vec<u8> {
    loop {
        match client.recv_event().await.expect("イベントを受信できること") {
            ConnectionEvent::StreamData {
                stream_id, data, ..
            } => {
                client
                    .extend_max_stream_offset(stream_id, data.len() as u64)
                    .expect("フロー制御クレジットを戻せること");
                return data;
            }
            ConnectionEvent::ConnectionClosed { reason, .. } => {
                panic!("接続が閉じられた: {reason}")
            }
            _ => {}
        }
    }
}

/// ハンドシェイク完了前に送った 0-RTT のデータがサーバーに届くこと
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_early_data_stream_before_handshake() {
    let cert = TestCert::generate("early_data_accept");
    let mut server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"]).with_early_data(true)),
    )
    .await;
    let server_addr = server.local_addr();

    // サーバーは 2 つの接続を順に受け入れる。セッションチケットの暗号鍵は
    // SSL_CTX ごとに作られるため、同じ Server で受け入れる必要がある
    let server_task = tokio::spawn(async move {
        let first = accept_and_echo(&mut server).await;
        let second = accept_and_echo(&mut server).await;
        (first, second)
    });

    let result = timeout(TEST_TIMEOUT, async {
        let config = insecure_client_config();

        // 1 回目の接続でセッション情報を保存する
        let mut client =
            Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &config)
                .await
                .expect("1 回目の接続ができること");
        let ticket = fetch_session_ticket(&mut client).await;
        assert!(
            !ticket.session().is_empty(),
            "セッションチケットが保存されること"
        );
        assert!(
            !ticket.transport_params().is_empty(),
            "0-RTT 用のトランスポートパラメータが保存されること"
        );
        client
            .close(0, b"done")
            .await
            .expect("1 回目の接続を閉じられること");

        // 2 回目の接続を 0-RTT で行う
        let mut client = Client::connect_with_early_data(
            server_addr,
            ephemeral_addr(),
            "localhost",
            &config,
            &ticket,
        )
        .await
        .expect("2 回目の接続ができること");

        // ハンドシェイクが完了する前に 0-RTT のデータを送る
        assert!(
            client.is_in_early_data(),
            "0-RTT を送れる状態であること (サーバーが early data を受理する設定)"
        );
        assert!(
            !client.is_handshake_completed(),
            "0-RTT のデータを送る時点でハンドシェイクが完了していないこと"
        );

        let stream_id = client.open_bidi_stream().expect("ストリームを開けること");
        client
            .write_stream(stream_id, b"early data", true)
            .expect("0-RTT のデータを送信待ちに積めること");
        client
            .flush()
            .await
            .expect("0-RTT のデータを送信できること");

        // ハンドシェイクの完了まで駆動し、0-RTT が受理されたことを確認する
        let rejected = drive_until_handshake_completed(&mut client).await;
        assert!(!rejected, "0-RTT が拒否されないこと");
        assert!(
            client.is_early_data_accepted(),
            "サーバーが 0-RTT を受理したこと"
        );
        assert!(
            !client.is_early_data_rejected(),
            "0-RTT が拒否されていないこと"
        );

        // サーバーが 0-RTT のデータを受信したことを確認する
        assert_eq!(
            recv_echo(&mut client).await,
            b"early data",
            "0-RTT で送ったデータがサーバーに届くこと"
        );

        client
            .close(0, b"done")
            .await
            .expect("2 回目の接続を閉じられること");
    })
    .await;
    result.expect("テストがタイムアウトしないこと");

    let (first, second) = timeout(TEST_TIMEOUT, server_task)
        .await
        .expect("サーバータスクがタイムアウトしないこと")
        .expect("サーバータスクが完了すること");
    assert!(
        first.data.is_empty(),
        "1 回目の接続ではデータを送らないこと"
    );
    assert!(
        !first.received_early_data,
        "1 回目の接続では 0-RTT のデータを受信しないこと"
    );
    assert_eq!(
        second.data, b"early data",
        "2 回目の接続で 0-RTT のデータを受信すること"
    );
    assert!(
        second.received_early_data,
        "2 回目の接続ではデータを 0-RTT として受信したこと"
    );
}

/// サーバーが 0-RTT を受け入れない場合に拒否が通知されること
///
/// チケットを発行したサーバーとは別のサーバー (別の SSL_CTX) に接続する。
/// チケットを復号できないためセッションは再開されず、0-RTT のデータは
/// 破棄される。ハンドシェイク自体は通常どおり完了する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_early_data_rejected_by_another_server() {
    let cert = TestCert::generate("early_data_reject");

    // 1 台目: 0-RTT を受け入れ、チケットを発行する
    let mut first_server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"]).with_early_data(true)),
    )
    .await;
    let first_addr = first_server.local_addr();

    // 2 台目: 同じ証明書と設定だが別の SSL_CTX を持つため、
    // 1 台目が発行したチケットは復号できない
    let mut second_server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"]).with_early_data(true)),
    )
    .await;
    let second_addr = second_server.local_addr();

    let first_task = tokio::spawn(async move { accept_and_echo(&mut first_server).await });
    let second_task = tokio::spawn(async move { accept_and_echo(&mut second_server).await });

    let result = timeout(TEST_TIMEOUT, async {
        let config = insecure_client_config();

        let mut client =
            Client::connect_with_config(first_addr, ephemeral_addr(), "localhost", &config)
                .await
                .expect("1 回目の接続ができること");
        let ticket = fetch_session_ticket(&mut client).await;
        client
            .close(0, b"done")
            .await
            .expect("1 回目の接続を閉じられること");

        // チケットを発行していないサーバーへ 0-RTT で接続する
        let mut client = Client::connect_with_early_data(
            second_addr,
            ephemeral_addr(),
            "localhost",
            &config,
            &ticket,
        )
        .await
        .expect("2 回目の接続ができること");
        assert!(
            client.is_in_early_data(),
            "0-RTT を送れる状態であること (クライアントはチケットを提示する)"
        );

        let stream_id = client.open_bidi_stream().expect("ストリームを開けること");
        client
            .write_stream(stream_id, b"discarded", true)
            .expect("0-RTT のデータを送信待ちに積めること");
        client
            .flush()
            .await
            .expect("0-RTT のデータを送信できること");

        // ハンドシェイクが完了するまで駆動し、拒否が通知されることを確認する
        let rejected = drive_until_handshake_completed(&mut client).await;
        assert!(
            rejected,
            "サーバーが 0-RTT を受理しなかったため EarlyDataRejected が届くこと"
        );
        assert!(
            client.is_early_data_rejected(),
            "0-RTT が拒否されたことを API でも観測できること"
        );
        assert!(
            !client.is_early_data_accepted(),
            "0-RTT は受理されていないこと"
        );

        // 拒否されたデータはアプリケーションが送り直す (ngtcp2 は再送しない)
        let stream_id = client
            .open_bidi_stream()
            .expect("拒否後にストリームを開き直せること");
        client
            .write_stream(stream_id, b"resent", true)
            .expect("データを送り直せること");
        client.flush().await.expect("データを送信できること");

        assert_eq!(
            recv_echo(&mut client).await,
            b"resent",
            "送り直したデータがサーバーに届くこと"
        );

        client
            .close(0, b"done")
            .await
            .expect("2 回目の接続を閉じられること");
    })
    .await;
    result.expect("テストがタイムアウトしないこと");

    let first = timeout(TEST_TIMEOUT, first_task)
        .await
        .expect("1 台目のサーバータスクがタイムアウトしないこと")
        .expect("1 台目のサーバータスクが完了すること");
    let second = timeout(TEST_TIMEOUT, second_task)
        .await
        .expect("2 台目のサーバータスクがタイムアウトしないこと")
        .expect("2 台目のサーバータスクが完了すること");
    assert!(first.data.is_empty(), "1 台目はデータを受信しないこと");
    assert!(
        !first.received_early_data,
        "1 台目は 0-RTT のデータを受信しないこと"
    );
    assert_eq!(
        second.data, b"resent",
        "拒否された 0-RTT のデータは届かず、送り直したデータだけが届くこと"
    );
    assert!(
        !second.received_early_data,
        "2 台目は 0-RTT を受理していないため 0-RTT としては受信しないこと"
    );
}

/// セッション情報を保存して復元しても 0-RTT を送れること
///
/// アプリケーションはセッション情報をファイルなどに保存して次回の起動で
/// 使うため、バイト列から作り直せる必要がある。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_session_ticket_roundtrip() {
    let cert = TestCert::generate("early_data_roundtrip");
    let mut server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"]).with_early_data(true)),
    )
    .await;
    let server_addr = server.local_addr();

    let server_task = tokio::spawn(async move {
        let first = accept_and_echo(&mut server).await;
        let second = accept_and_echo(&mut server).await;
        (first, second)
    });

    let result = timeout(TEST_TIMEOUT, async {
        let config = insecure_client_config();

        let mut client =
            Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &config)
                .await
                .expect("1 回目の接続ができること");
        let ticket = fetch_session_ticket(&mut client).await;
        client
            .close(0, b"done")
            .await
            .expect("1 回目の接続を閉じられること");

        // 保存と復元を模す
        let restored = SessionTicket::new(
            ticket.session().to_vec(),
            ticket.transport_params().to_vec(),
        );
        assert_eq!(restored, ticket, "復元したセッション情報が一致すること");
        assert_eq!(
            restored.session(),
            ticket.session(),
            "セッションのバイト列が一致すること"
        );
        assert_eq!(
            restored.transport_params(),
            ticket.transport_params(),
            "トランスポートパラメータのバイト列が一致すること"
        );

        let mut client = Client::connect_with_early_data(
            server_addr,
            ephemeral_addr(),
            "localhost",
            &config,
            &restored,
        )
        .await
        .expect("復元したセッション情報で接続できること");
        assert!(
            client.is_in_early_data(),
            "復元したセッション情報でも 0-RTT を送れること"
        );

        let stream_id = client.open_bidi_stream().expect("ストリームを開けること");
        client
            .write_stream(stream_id, b"restored", true)
            .expect("0-RTT のデータを送信待ちに積めること");
        client
            .flush()
            .await
            .expect("0-RTT のデータを送信できること");

        let rejected = drive_until_handshake_completed(&mut client).await;
        assert!(!rejected, "0-RTT が拒否されないこと");
        assert!(
            client.is_early_data_accepted(),
            "復元したセッション情報でも 0-RTT が受理されること"
        );
        assert_eq!(
            recv_echo(&mut client).await,
            b"restored",
            "0-RTT のデータがサーバーに届くこと"
        );

        client
            .close(0, b"done")
            .await
            .expect("2 回目の接続を閉じられること");
    })
    .await;
    result.expect("テストがタイムアウトしないこと");

    let (first, second) = timeout(TEST_TIMEOUT, server_task)
        .await
        .expect("サーバータスクがタイムアウトしないこと")
        .expect("サーバータスクが完了すること");
    assert!(
        first.data.is_empty(),
        "1 回目の接続ではデータを送らないこと"
    );
    assert!(
        !first.received_early_data,
        "1 回目の接続では 0-RTT のデータを受信しないこと"
    );
    assert_eq!(second.data, b"restored", "0-RTT のデータを受信すること");
    assert!(
        second.received_early_data,
        "復元したセッション情報でも 0-RTT として受信すること"
    );
}

/// セッション情報が無ければ 0-RTT を送らないこと
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_early_data_not_used_without_session() {
    let cert = TestCert::generate("early_data_none");
    let server = bind_server(
        cert.cert_path(),
        cert.key_path(),
        Some(ServerConfig::new(&[b"hq-interop"]).with_early_data(true)),
    )
    .await;
    let (pair, _server) = connect_with_server(server, insecure_client_config(), "localhost").await;

    let result = timeout(TEST_TIMEOUT, async {
        assert!(
            pair.client.is_handshake_completed(),
            "ハンドシェイクが完了していること"
        );
        assert_eq!(
            pair.server.selected_alpn_protocol().as_deref(),
            Some(b"hq-interop".as_slice()),
            "サーバー側もハンドシェイクを完了していること"
        );
        assert!(
            !pair.client.is_in_early_data(),
            "セッション情報が無ければ 0-RTT を送らないこと"
        );
        assert!(
            !pair.client.is_early_data_accepted(),
            "0-RTT は受理されていないこと"
        );
        assert!(
            !pair.client.is_early_data_rejected(),
            "0-RTT を試みていないため拒否もされていないこと"
        );
    })
    .await;
    result.expect("テストがタイムアウトしないこと");
}

/// 不正なセッション情報では 0-RTT 接続を作れないこと
///
/// 保存したセッション情報が壊れている場合、接続の作成時点でエラーになる。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_connect_with_early_data_rejects_invalid_ticket() {
    // 接続の作成で失敗するためサーバーは不要
    let addr: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("テスト用アドレスは有効");
    let config = insecure_client_config();

    // セッションとして解釈できないバイト列を渡す
    let ticket = SessionTicket::new(vec![0xff; 32], vec![0x00, 0x01]);
    let result =
        Client::connect_with_early_data(addr, ephemeral_addr(), "localhost", &config, &ticket)
            .await;
    assert!(
        matches!(result, Err(Error::InvalidArgument(_))),
        "不正なセッション情報は InvalidArgument であること"
    );
}

/// Retry を挟んでも 0-RTT のデータが届くこと (RFC 9000 Section 8.1.2)
///
/// クライアントは Retry を受け取るとトークンを載せた Initial を送り直し、
/// 0-RTT のデータも送り直す。Retry によるアドレス検証と 0-RTT が同時に
/// 働くことを検証する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_early_data_with_retry() {
    let cert = TestCert::generate("early_data_retry");
    let config = ServerConfig::new(&[b"hq-interop"])
        .with_retry(RetrySecret::from_bytes(RETRY_SECRET_BYTES))
        .with_early_data(true);
    let mut server = bind_server(cert.cert_path(), cert.key_path(), Some(config)).await;
    let server_addr = server.local_addr();

    // サーバーは 2 つの接続を順に受け入れる。どちらの接続でも Retry を返す
    let server_task = tokio::spawn(async move {
        let first = accept_and_echo(&mut server).await;
        let second = accept_and_echo(&mut server).await;
        (first, second)
    });

    let result = timeout(TEST_TIMEOUT, async {
        let config = insecure_client_config();

        // 1 回目の接続でセッション情報を保存する
        let mut client =
            Client::connect_with_config(server_addr, ephemeral_addr(), "localhost", &config)
                .await
                .expect("1 回目の接続ができること");
        let ticket = fetch_session_ticket(&mut client).await;
        client
            .close(0, b"done")
            .await
            .expect("1 回目の接続を閉じられること");

        // 2 回目の接続は Retry を挟んで 0-RTT のデータを送る
        let mut client = Client::connect_with_early_data(
            server_addr,
            ephemeral_addr(),
            "localhost",
            &config,
            &ticket,
        )
        .await
        .expect("2 回目の接続ができること");
        assert!(client.is_in_early_data(), "0-RTT を送れる状態であること");

        let stream_id = client.open_bidi_stream().expect("ストリームを開けること");
        client
            .write_stream(stream_id, b"early data with retry", true)
            .expect("0-RTT のデータを送信待ちに積めること");
        client
            .flush()
            .await
            .expect("0-RTT のデータを送信できること");

        // Retry を処理してハンドシェイクが完了するまで駆動する
        let rejected = drive_until_handshake_completed(&mut client).await;
        assert!(!rejected, "Retry を挟んでも 0-RTT が拒否されないこと");
        assert!(
            client.is_early_data_accepted(),
            "Retry を挟んでもサーバーが 0-RTT を受理すること"
        );

        assert_eq!(
            recv_echo(&mut client).await,
            b"early data with retry",
            "Retry を挟んでも 0-RTT のデータがサーバーに届くこと"
        );

        client
            .close(0, b"done")
            .await
            .expect("2 回目の接続を閉じられること");
    })
    .await;
    result.expect("テストがタイムアウトしないこと");

    let (first, second) = timeout(TEST_TIMEOUT, server_task)
        .await
        .expect("サーバータスクがタイムアウトしないこと")
        .expect("サーバータスクが完了すること");
    assert!(
        !first.received_early_data,
        "1 回目の接続では 0-RTT のデータを受信しないこと"
    );
    assert_eq!(
        second.data, b"early data with retry",
        "Retry を挟んでも 0-RTT のデータを受信すること"
    );
    assert!(
        second.received_early_data,
        "2 回目の接続ではデータを 0-RTT として受信したこと"
    );
}
