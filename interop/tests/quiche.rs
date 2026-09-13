//! quiche (Cloudflare) との相互運用テスト
//!
//! quiche は Cloudflare が開発する独立した QUIC 実装で、TLS に BoringSSL を使う。
//! ngtcp2 系 (aws-lc) とは TLS スタックも QUIC の実装も異なるため、
//! ハンドシェイクとストリームのやり取りがワイヤー上で仕様どおりであることを
//! 検証できる。
//!
//! quiche 側は `quiche-driver` パッケージのバイナリを **別プロセス** として
//! 起動する。quiche が静的リンクする BoringSSL と ngtcp2 系が使う aws-lc は
//! `SSL_CTX_new` などの unprefixed なシンボルを共有するため、同一プロセスに
//! リンクするとリンカがどちらか一方の実装を選び、構造体のレイアウトの食い違いで
//! abort する。
//!
//! 検証する組み合わせ:
//!
//! - 我々のサーバー ← quiche のクライアント
//! - 我々のサーバー (Retry 有効) ← quiche のクライアント
//! - 我々のサーバー (0-RTT 有効) ← quiche のクライアント (0-RTT)
//! - 我々のサーバー (長さ 0 のコネクション ID) ← quiche のクライアント
//! - 我々のサーバー ← quiche のクライアント (マイグレーション)
//! - quiche のサーバー ← 我々のクライアント
//! - quiche のサーバー (0-RTT 有効) ← 我々のクライアント (0-RTT)
//! - quiche のサーバー (マイグレーション有効) ← 我々のクライアント (マイグレーション)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;

use shiguredo_ngtcp2::RetrySecret;
use shiguredo_ngtcp2_interop::{
    ALPN, TEST_TIMEOUT, TestCert, accept_and_echo, accept_and_echo_n, accept_and_echo_until_closed,
    bind_server, client_roundtrip, client_roundtrip_early_data, client_roundtrip_with_migration,
};
use shiguredo_ngtcp2_tokio::ServerConfig;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tokio::io::Lines;
use tokio::process::Child;
use tokio::process::ChildStdout;
use tokio::process::Command;
use tokio::time::timeout;

/// テスト用の Retry 秘密
const RETRY_SECRET_BYTES: [u8; shiguredo_ngtcp2::RETRY_SECRET_LEN] = [0x6c; 32];

/// 相互運用テスト用の quiche ドライバのパスを返す
///
/// ドライバは別パッケージ (`quiche-driver`) のバイナリのため `CARGO_BIN_EXE_*` を
/// 使えない。テスト実行ファイルの場所 (`target/<profile>/deps/<test>-<hash>`) から
/// 辿る。`cargo test` の前に `cargo build --bins` でビルドしておくこと
/// (`make interop-test` が行う)。
fn driver_bin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("テスト実行ファイルのパスを取得できること");
    let dir = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target ディレクトリを特定できること");
    let path = dir.join(name);
    assert!(
        path.exists(),
        "quiche のドライバがビルドされていること: {} (先に cargo build --bins を実行する)",
        path.display()
    );
    path
}

/// quiche のクライアントを子プロセスとして起動し、エコーを受け取る
///
/// CA 証明書のパスとペイロードを引数で渡し、標準出力に書き出されたエコーを読む。
/// `options` はドライバのフラグ (`--early-data` など) を渡す。
async fn run_quiche_client(
    server_addr: SocketAddr,
    ca_cert_path: &str,
    payload: &str,
    options: &[&str],
) -> Vec<u8> {
    let output = Command::new(driver_bin("quiche_driver"))
        .arg("client")
        .arg(server_addr.to_string())
        .arg(ca_cert_path)
        .arg(payload)
        .args(options)
        .output()
        .await
        .expect("quiche のクライアントを起動できること");

    assert!(
        output.status.success(),
        "quiche のクライアントが成功すること: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// quiche のサーバーを子プロセスとして起動する
///
/// 子プロセスが標準出力に書き出す待ち受けアドレスを読んで返す。戻り値の
/// `Lines` からは接続ごとの結果 (`<バイト数> bytes (early data: <真偽>)`) を
/// 読める。サーバーは接続の終了を待たずに動き続けるため、テストが
/// [`stop_quiche_server`] で終了させる。
///
/// `options` はドライバのフラグ (`--early-data` など) を渡す。
async fn spawn_quiche_server(
    cert_path: &str,
    key_path: &str,
    options: &[&str],
) -> (Child, SocketAddr, Lines<BufReader<ChildStdout>>) {
    let mut child = Command::new(driver_bin("quiche_driver"))
        .arg("server")
        .arg(cert_path)
        .arg(key_path)
        .args(options)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("quiche のサーバーを起動できること");

    let stdout = child
        .stdout
        .take()
        .expect("quiche のサーバーの標準出力を取得できること");

    // 待ち受けアドレスの 1 行を読む。子プロセスは起動直後に書き出す
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let read = timeout(TEST_TIMEOUT, reader.read_line(&mut line))
        .await
        .expect("quiche のサーバーが待ち受けアドレスを書き出すこと")
        .expect("標準出力を読めること");
    assert!(
        read > 0,
        "quiche のサーバーが待ち受けアドレスを書き出すこと"
    );

    let addr = line
        .trim()
        .parse()
        .expect("待ち受けアドレスを解釈できること");
    (child, addr, reader.lines())
}

/// quiche のサーバーが書き出した結果の 1 行を読む
///
/// サーバーはエコーするたびに `<バイト数> bytes (early data: <真偽>)` を
/// 標準出力に書き出す。
async fn read_server_report(lines: &mut Lines<BufReader<ChildStdout>>) -> String {
    let line = timeout(TEST_TIMEOUT, lines.next_line())
        .await
        .expect("quiche のサーバーが結果を書き出すこと")
        .expect("標準出力を読めること");
    line.expect("quiche のサーバーが接続を処理していること")
}

/// quiche のサーバーがピアの接続終了を観測したことを確認する
///
/// 我々のクライアントはハンドシェイクが確認される前に接続を閉じることがある。
/// その場合 ngtcp2 は Handshake と 1-RTT の CONNECTION_CLOSE を連結して返すため、
/// パケットごとに分けて送らないとピアがデータグラム全体を破棄し、接続の終了を
/// 観測できない (RFC 9000 Section 12.2)。
async fn assert_peer_closed(lines: &mut Lines<BufReader<ChildStdout>>) {
    let report = read_server_report(lines).await;
    assert_eq!(
        report, "peer closed",
        "quiche のサーバーがピアの接続終了を観測すること"
    );
}

/// quiche のサーバーを終了させる
///
/// サーバーは接続が終わっても終了しないため、テストが終了させる。
async fn stop_quiche_server(mut child: Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

/// パスを UTF-8 の文字列で返す
///
/// quiche はファイルパスを `&str` で受け取る。
fn path_str(path: &std::path::Path) -> String {
    path.to_str()
        .expect("テスト用のパスが UTF-8 であること")
        .to_string()
}

/// quiche のクライアントが我々のサーバーとハンドシェイクし、ストリームを往復できること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_server_with_quiche_client() {
    let cert = TestCert::generate("quiche_client");
    let server = bind_server(&cert, None).await;
    let server_addr = server.local_addr();
    let server_task = tokio::spawn(accept_and_echo(server));
    let ca_cert_path = path_str(cert.ca_cert_path());

    let payload = "quiche client to ngtcp2 server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed = run_quiche_client(server_addr, &ca_cert_path, payload, &[]).await;
        let received = server_task.await.expect("サーバータスクが完了すること");

        assert_eq!(
            received.data,
            payload.as_bytes(),
            "quiche のクライアントが送ったデータがサーバーに届くこと"
        );
        assert_eq!(
            echoed,
            payload.as_bytes(),
            "サーバーが返したエコーが quiche のクライアントに届くこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// quiche のクライアントが Retry を処理して我々のサーバーと接続できること
/// (RFC 9000 Section 8.1.2)
///
/// quiche は ngtcp2 が生成したトークンを検証できないため、ここでは我々の
/// サーバーが返す Retry を quiche が受理し、トークンを載せた Initial を
/// 送り直せることを検証する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_server_with_quiche_client_retry() {
    let cert = TestCert::generate("quiche_client_retry");
    let config = ServerConfig::new(&[ALPN]).with_retry(RetrySecret::from_bytes(RETRY_SECRET_BYTES));
    let server = bind_server(&cert, Some(config)).await;
    let server_addr = server.local_addr();
    let server_task = tokio::spawn(accept_and_echo(server));
    let ca_cert_path = path_str(cert.ca_cert_path());

    let payload = "retry from ngtcp2 server to quiche";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed = run_quiche_client(server_addr, &ca_cert_path, payload, &[]).await;
        let received = server_task.await.expect("サーバータスクが完了すること");

        assert_eq!(
            received.data,
            payload.as_bytes(),
            "Retry を挟んでもデータが届くこと"
        );
        assert_eq!(
            echoed,
            payload.as_bytes(),
            "Retry を挟んでもエコーが届くこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 我々のクライアントが quiche のサーバーとハンドシェイクし、ストリームを往復できること
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_client_with_quiche_server() {
    let cert = TestCert::generate("quiche_server");
    let cert_path = path_str(cert.cert_path());
    let key_path = path_str(cert.key_path());

    let (child, server_addr, mut lines) = spawn_quiche_server(&cert_path, &key_path, &[]).await;

    let payload = b"ngtcp2 client to quiche server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed = client_roundtrip(server_addr, cert.ca_cert_pem(), payload).await;
        assert_eq!(echoed, payload, "quiche のサーバーが返したエコーが届くこと");

        // quiche のサーバー側でもデータを受け取っていること
        let report = read_server_report(&mut lines).await;
        assert_eq!(
            report,
            format!("{} bytes (early data: false)", payload.len()),
            "quiche のサーバーがデータを受け取ったこと"
        );
        // 接続の終了も観測できること (連結された CONNECTION_CLOSE の検証)
        assert_peer_closed(&mut lines).await;
    })
    .await;

    stop_quiche_server(child).await;
    result.expect("テストがタイムアウトしないこと");
}

/// quiche のクライアントが 0-RTT で我々のサーバーへデータを送れること
/// (RFC 9001 Section 4.6)
///
/// 1 回目の接続で quiche がセッションチケットを保存し、2 回目の接続で
/// ハンドシェイクの完了前にデータを送る。我々のサーバーがそのデータを
/// 0-RTT として受理したことを接続から観測する。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_server_with_quiche_client_early_data() {
    let cert = TestCert::generate("quiche_client_early_data");
    let config = ServerConfig::new(&[ALPN]).with_early_data(true);
    let server = bind_server(&cert, Some(config)).await;
    let server_addr = server.local_addr();
    // 1 回目はセッションチケットの取得、2 回目が 0-RTT のデータ
    let server_task = tokio::spawn(accept_and_echo_n(server, 2));
    let ca_cert_path = path_str(cert.ca_cert_path());

    let payload = "quiche client early data to ngtcp2 server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed =
            run_quiche_client(server_addr, &ca_cert_path, payload, &["--early-data"]).await;
        let received = server_task.await.expect("サーバータスクが完了すること");

        assert_eq!(
            echoed,
            payload.as_bytes(),
            "0-RTT で送ったデータのエコーが quiche のクライアントに届くこと"
        );
        assert!(
            received[0].data.is_empty(),
            "1 回目の接続ではデータを送らないこと"
        );
        assert_eq!(
            received[1].data,
            payload.as_bytes(),
            "0-RTT のデータがサーバーに届くこと"
        );
        assert!(
            received[1].received_early_data,
            "サーバーがデータを 0-RTT として受理したこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// quiche のクライアントが Retry を挟んでデータを届けられること
/// (RFC 9000 Section 8.1.2 / RFC 9001 Section 4.6)
///
/// 我々のサーバーは Retry によるアドレス検証と 0-RTT の受理を同時に有効に
/// する。Retry を受け取ったクライアントがデータを届けられることを検証する。
///
/// Retry の後に 0-RTT でデータを送り直すかは実装による。ngtcp2 は 0-RTT で
/// 送り直す (`conn_retransmit_retry_early`) が、quiche はハンドシェイクの
/// 完了後に 1-RTT で送る。そのためここでは 0-RTT として受理されたかは
/// 検証しない (我々のクライアントが Retry の後も 0-RTT を送ることは
/// `e2e_early_data` の `test_early_data_with_retry` で検証している)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_server_with_quiche_client_retry_and_early_data() {
    let cert = TestCert::generate("quiche_client_retry_early_data");
    let config = ServerConfig::new(&[ALPN])
        .with_retry(RetrySecret::from_bytes(RETRY_SECRET_BYTES))
        .with_early_data(true);
    let server = bind_server(&cert, Some(config)).await;
    let server_addr = server.local_addr();
    // 1 回目はセッションチケットの取得、2 回目が 0-RTT のデータ
    let server_task = tokio::spawn(accept_and_echo_n(server, 2));
    let ca_cert_path = path_str(cert.ca_cert_path());

    let payload = "quiche client retry and early data to ngtcp2 server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed =
            run_quiche_client(server_addr, &ca_cert_path, payload, &["--early-data"]).await;
        let received = server_task.await.expect("サーバータスクが完了すること");

        assert_eq!(
            echoed,
            payload.as_bytes(),
            "Retry を挟んでもエコーが届くこと"
        );
        assert_eq!(
            received[1].data,
            payload.as_bytes(),
            "Retry を挟んでもデータが届くこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// 我々のクライアントが 0-RTT で quiche のサーバーへデータを送れること
/// (RFC 9001 Section 4.6)
///
/// quiche が発行したセッションチケットで再開し、ハンドシェイクの完了前に
/// データを送る。quiche のサーバーにも 0-RTT として受理されたことを確認させる。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_client_with_quiche_server_early_data() {
    let cert = TestCert::generate("quiche_server_early_data");
    let cert_path = path_str(cert.cert_path());
    let key_path = path_str(cert.key_path());

    // セッションチケットの発行と 0-RTT の受理を設定する
    let (child, server_addr, mut lines) =
        spawn_quiche_server(&cert_path, &key_path, &["--early-data"]).await;

    let payload = b"ngtcp2 client early data to quiche server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed = client_roundtrip_early_data(server_addr, cert.ca_cert_pem(), payload).await;

        assert!(
            echoed.accepted,
            "ngtcp2 のクライアントが 0-RTT の受理を観測すること"
        );
        assert_eq!(
            echoed.echoed, payload,
            "0-RTT で送ったデータのエコーが届くこと"
        );

        // quiche のサーバーがデータを受け取ったことを確認する。
        //
        // 受け取ったデータを 0-RTT として扱ったかどうかは検証しない。
        // tokio-quiche のワーカーはたまっているパケットをまとめて処理するため、
        // アプリケーションがデータを読む時点でハンドシェイクが完了していること
        // があり、`is_in_early_data` は 0-RTT でも false になりうる。
        // 0-RTT が受理されたことはクライアント側の観測
        // (`is_early_data_accepted`) とデータが届いたことの両方で確認している。
        let report = read_server_report(&mut lines).await;
        assert!(
            report.starts_with(&format!("{} bytes (early data: ", payload.len())),
            "quiche のサーバーがデータを受け取ったこと: {report}"
        );
        // 接続の終了も観測できること (連結された CONNECTION_CLOSE の検証)
        assert_peer_closed(&mut lines).await;
    })
    .await;

    stop_quiche_server(child).await;
    result.expect("テストがタイムアウトしないこと");
}

/// 我々のクライアントが接続を維持したまま quiche のサーバーへ移れること
/// (RFC 9000 Section 9)
///
/// 経路の検証が完了してからデータを送るため、エコーが届けば移った先の経路が
/// quiche に受理されたことになる。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_client_migrates_with_quiche_server() {
    let cert = TestCert::generate("quiche_server_migration");
    let cert_path = path_str(cert.cert_path());
    let key_path = path_str(cert.key_path());

    // ピアのマイグレーションを受理する設定で起動する
    let (child, server_addr, mut lines) =
        spawn_quiche_server(&cert_path, &key_path, &["--migration"]).await;

    let payload = b"ngtcp2 client migrated to quiche server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed =
            client_roundtrip_with_migration(server_addr, cert.ca_cert_pem(), payload).await;
        assert_eq!(
            echoed, payload,
            "移った先の経路で送ったデータのエコーが届くこと"
        );

        // quiche のサーバー側でも、移った先の経路でデータを受け取っていること
        let report = read_server_report(&mut lines).await;
        assert_eq!(
            report,
            format!("{} bytes (early data: false)", payload.len()),
            "quiche のサーバーが移った先の経路でデータを受け取ったこと"
        );
        // 接続の終了も観測できること (連結された CONNECTION_CLOSE の検証)
        assert_peer_closed(&mut lines).await;
    })
    .await;

    stop_quiche_server(child).await;
    result.expect("テストがタイムアウトしないこと");
}

/// 長さ 0 のコネクション ID を使うサーバーと quiche のクライアントが通信できること
///
/// サーバーがコネクション ID を発行しない場合、クライアントはコネクション ID を
/// 載せずにパケットを送る。サーバーはアドレスでパケットを接続へ振り分ける
/// (RFC 9000 Section 5.1)。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_our_server_with_zero_length_cid_and_quiche_client() {
    let cert = TestCert::generate("quiche_client_zero_length_cid");
    let config = ServerConfig::new(&[ALPN]).with_scid_len(0);
    let server = bind_server(&cert, Some(config)).await;
    let server_addr = server.local_addr();
    let server_task = tokio::spawn(accept_and_echo(server));
    let ca_cert_path = path_str(cert.ca_cert_path());

    let payload = "zero length cid";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed = run_quiche_client(server_addr, &ca_cert_path, payload, &[]).await;
        let received = server_task.await.expect("サーバータスクが完了すること");

        assert_eq!(
            received.data,
            payload.as_bytes(),
            "quiche のクライアントが送ったデータがサーバーに届くこと"
        );
        assert_eq!(
            echoed,
            payload.as_bytes(),
            "サーバーが返したエコーが quiche のクライアントに届くこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}

/// quiche のクライアントが我々のサーバーへマイグレーションできること
/// (RFC 9000 Section 9)
///
/// quiche は移った先の経路を検証してから移り、移った先でデータを送る。我々の
/// サーバーはピアが新しいアドレスから送ってきたことを検出して経路を検証し、
/// 移った先の経路でエコーを返す。エコーが届いてからクライアントが閉じるまで
/// サーバーを駆動し続ける。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quiche_client_migrates_with_our_server() {
    let cert = TestCert::generate("quiche_client_migration");
    let server = bind_server(&cert, None).await;
    let server_addr = server.local_addr();
    // 経路が切り替わるまでサーバーを止めない
    let server_task = tokio::spawn(accept_and_echo_until_closed(server));
    let ca_cert_path = path_str(cert.ca_cert_path());

    let payload = "quiche client migrated to ngtcp2 server";
    let result = timeout(TEST_TIMEOUT, async {
        let echoed = run_quiche_client(server_addr, &ca_cert_path, payload, &["--migrate"]).await;
        let received = server_task.await.expect("サーバータスクが完了すること");

        assert_eq!(
            received.data,
            payload.as_bytes(),
            "移った先の経路で送ったデータがサーバーに届くこと"
        );
        assert_eq!(
            echoed,
            payload.as_bytes(),
            "サーバーが返したエコーが quiche のクライアントに届くこと"
        );
        assert!(received.echo_sent, "サーバーがエコーを返したこと");
        assert!(
            received.path_validated,
            "サーバーが新しい経路の検証に成功したこと"
        );
    })
    .await;

    result.expect("テストがタイムアウトしないこと");
}
