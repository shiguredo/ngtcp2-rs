//! 相互運用テスト用の quiche ドライバ
//!
//! quiche を我々の実装とは別プロセスで動かすためのバイナリ。クライアントと
//! サーバーをサブコマンドで切り替える。
//!
//! quiche 側の駆動は 2 つのモジュールに分かれている。
//!
//! - [`tokio_quiche_driver`]: tokio-quiche (quiche の tokio 統合) で動かす。
//!   通常のクライアントと、サーバー (0-RTT とピアのマイグレーションの受理を含む)
//! - [`raw_quiche`]: 生の quiche を直接動かす。tokio-quiche では表現できない
//!   0-RTT の送信とマイグレーションだけを担当する
//!
//! 使い方:
//!
//! - `quiche_driver client <server_addr> <ca_cert_path> <payload> [--early-data] [--migrate]`
//!   - 受け取ったエコーを標準出力に書き出す
//!   - `--early-data` は 1 回目の接続でセッション情報を保存し、2 回目の接続で 0-RTT を送る
//!   - `--migrate` はハンドシェイクの完了後にローカルアドレスを変え、移った先の経路でデータを送る
//! - `quiche_driver server <cert_path> <key_path> [--early-data] [--migration]`
//!   - 待ち受けアドレスを標準出力に 1 行で書き出し、接続ごとにデータをエコーする
//!   - `--early-data` はセッションチケットを発行して 0-RTT を受理する
//!   - `--migration` はピア (クライアント) のマイグレーションを受理する
//!   - エコーするたびに `<バイト数> bytes (early data: <真偽>)` を標準出力に書き出す。
//!     プロセスは終了しないため、テストが結果を読んでから終了させる
//!
//! 成功なら終了コード 0、失敗なら理由を標準エラーに書き出して 1。

#[path = "../raw_quiche.rs"]
mod raw_quiche;
#[path = "../tokio_quiche_driver.rs"]
mod tokio_quiche_driver;

use std::net::SocketAddr;
use std::net::UdpSocket;
use std::process::ExitCode;

use tokio_quiche_driver::ServerOptions;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("client") => client(&args[1..]),
        Some("server") => server(&args[1..]),
        _ => {
            usage();
            ExitCode::FAILURE
        }
    }
}

/// 使い方を標準エラーに書き出す
fn usage() {
    eprintln!(
        "usage: quiche_driver client <server_addr> <ca_cert_path> <payload> [--early-data] [--migrate]"
    );
    eprintln!("       quiche_driver server <cert_path> <key_path> [--early-data] [--migration]");
}

/// コマンドライン引数から取り出したフラグ
#[derive(Default)]
struct Options {
    /// 0-RTT (early data) を使う
    early_data: bool,
    /// マイグレーションを行う / 受理する
    migration: bool,
}

/// 位置引数とフラグに分ける
fn parse_args(args: &[String]) -> Result<(Vec<String>, Options), String> {
    let mut positional = Vec::new();
    let mut options = Options::default();
    for arg in args {
        match arg.as_str() {
            "--early-data" => options.early_data = true,
            "--migration" | "--migrate" => options.migration = true,
            other if other.starts_with("--") => return Err(format!("unknown option: {other}")),
            other => positional.push(other.to_string()),
        }
    }
    Ok((positional, options))
}

/// クライアントとして接続し、ペイロードを送ってエコーを標準出力に書き出す
fn client(args: &[String]) -> ExitCode {
    let (positional, options) = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("{e}");
            usage();
            return ExitCode::FAILURE;
        }
    };
    if positional.len() != 3 {
        usage();
        return ExitCode::FAILURE;
    }
    if options.early_data && options.migration {
        eprintln!("--early-data and --migrate cannot be used together");
        return ExitCode::FAILURE;
    }

    let Ok(server_addr) = positional[0].parse::<SocketAddr>() else {
        eprintln!("invalid server address: {}", positional[0]);
        return ExitCode::FAILURE;
    };
    let ca_cert_path = &positional[1];
    let payload = positional[2].as_bytes();

    let result = if options.migration {
        // tokio-quiche ではローカルアドレスを変えられないため生 quiche を使う
        raw_quiche::client_migrate_roundtrip(server_addr, ca_cert_path, payload)
    } else if options.early_data {
        // tokio-quiche のクライアントは early data を送れないため生 quiche を使う
        raw_quiche::client_early_data_roundtrip(server_addr, ca_cert_path, payload)
    } else {
        run_async(tokio_quiche_driver::client_roundtrip(
            server_addr,
            ca_cert_path,
            payload,
        ))
    };

    match result {
        Ok(echoed) => {
            write_stdout(&echoed);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("quiche client failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// サーバーとして待ち受け、待ち受けアドレスを書き出してからエコーを返す
fn server(args: &[String]) -> ExitCode {
    let (positional, options) = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("{e}");
            usage();
            return ExitCode::FAILURE;
        }
    };
    if positional.len() != 2 {
        usage();
        return ExitCode::FAILURE;
    }

    let listener = match UdpSocket::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("failed to bind: {e}");
            return ExitCode::FAILURE;
        }
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("failed to get local address: {e}");
            return ExitCode::FAILURE;
        }
    };

    // 親プロセスに待ち受けアドレスを伝える
    write_stdout(format!("{addr}\n").as_bytes());

    let server_options = ServerOptions {
        early_data: options.early_data,
        migration: options.migration,
    };
    // 受け入れた接続ごとの結果は標準出力に書き出される。プロセスは
    // 終了しないため、テストが結果を読んでから終了させる
    match run_async(tokio_quiche_driver::server_echo(
        listener,
        &positional[0],
        &positional[1],
        server_options,
    )) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("quiche server failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// tokio のランタイムで非同期処理を実行する
///
/// quiche のワーカーは接続を閉じた後もソケットを持ち続けるため、ランタイムを
/// 普通に drop すると終了がアイドルタイムアウトまで待たされる。結果はここで
/// 得ているので、後始末は待たずにプロセスを終了する。
fn run_async<F, T>(future: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("failed to start the runtime: {e}"))?;
    let result = runtime.block_on(future);
    runtime.shutdown_background();
    result
}

/// 標準出力に書き出して flush する
///
/// 親プロセスがパイプで読むため、明示的に flush しないと届かない。
fn write_stdout(data: &[u8]) {
    use std::io::Write;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = handle.write_all(data);
    let _ = handle.flush();
}
