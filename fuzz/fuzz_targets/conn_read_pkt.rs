#![no_main]

//! 接続の受信処理の fuzz ターゲット
//!
//! サーバーまたはクライアントの接続を作り、任意のデータグラムを `read_pkt` に
//! 渡す。あわせて送信パケットの書き出しとイベントの取り出しまで駆動し、
//! ngtcp2 から呼ばれる Rust 側のコールバックも実行する。
//!
//! ngtcp2 本体は C で書かれており fuzz のカバレッジ計測の対象外のため、ここで
//! 検出できるのは主に Rust 側のパニック (CID の扱い・コールバック・エラー変換)
//! になる。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use shiguredo_ngtcp2::{
    Connection, ConnectionErrorKind, ConnectionId, Error, PacketInfo, PathInfo, QuicVersion,
    STATELESS_RESET_SECRET_LEN, Settings, StatelessResetSecret, TlsContext, TransportParams,
    infer_quic_transport_error_code,
};

/// 接続に使う ALPN
const ALPN: &[u8] = b"hq-interop";

/// 送信バッファのサイズ
///
/// Initial パケットは 1200 バイト以上で送る必要があるため (RFC 9000 Section 14.1)、
/// それより大きい 1500 にする。
const SEND_BUFFER_SIZE: usize = 1500;

/// 送信パケットを書き出す上限回数
///
/// 1 つのデータグラムの処理で書き出しが終わらないことは無いが、無限ループで
/// fuzz が止まらないように上限を設ける。
const MAX_WRITE_ITERATIONS: usize = 64;

/// fuzz 入力
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// true ならサーバー接続、false ならクライアント接続を作る
    is_server: bool,
    /// 受信するデータグラム
    datagram: Vec<u8>,
}

/// サーバー用の TLS コンテキスト
///
/// 証明書と鍵は一時ディレクトリに生成する。Connection が保持する SSL は
/// SSL_CTX を参照するため、コンテキストはプロセスが終わるまで保持する。
static SERVER_TLS_CTX: OnceLock<TlsContext> = OnceLock::new();

/// クライアント用の TLS コンテキスト
static CLIENT_TLS_CTX: OnceLock<TlsContext> = OnceLock::new();

/// サーバー用の TLS コンテキストを取得する
fn server_tls_ctx() -> &'static TlsContext {
    SERVER_TLS_CTX.get_or_init(|| {
        let temp_dir: PathBuf =
            std::env::temp_dir().join(format!("ngtcp2_fuzz_certs_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).expect("一時ディレクトリを作成できること");
        let cert_path = temp_dir.join("cert.pem");
        let key_path = temp_dir.join("key.pem");

        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("証明書パラメータを作成できること");
        let key_pair = rcgen::KeyPair::generate().expect("鍵ペアを生成できること");
        let cert = params
            .self_signed(&key_pair)
            .expect("自己署名証明書を生成できること");
        std::fs::write(&cert_path, cert.pem()).expect("証明書を書き込めること");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("秘密鍵を書き込めること");

        let tls_ctx = TlsContext::new_server(&cert_path, &key_path, &[ALPN])
            .expect("TLS コンテキストを作成できること");

        // SSL_CTX は証明書と鍵を読み込み済みのため、ファイルは不要になる
        let _ = std::fs::remove_dir_all(&temp_dir);
        tls_ctx
    })
}

/// クライアント用の TLS コンテキストを取得する
fn client_tls_ctx() -> &'static TlsContext {
    // 証明書の検証は fuzz の対象外にする (自己署名証明書でハンドシェイクを進めるため)
    CLIENT_TLS_CTX.get_or_init(|| {
        TlsContext::new_client_with_options(&[ALPN], false)
            .expect("TLS コンテキストを作成できること")
    })
}

/// 送信パケットを書き出せるだけ書き出す
fn drain_packets(conn: &mut Connection, ts: u64) {
    let mut buf = [0u8; SEND_BUFFER_SIZE];
    for _ in 0..MAX_WRITE_ITERATIONS {
        match conn.write_pkt(&mut buf, ts) {
            Ok((0, _, _)) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    let local: SocketAddr = "127.0.0.1:50000".parse().expect("valid address");
    let remote: SocketAddr = "127.0.0.1:4433".parse().expect("valid address");
    let path = PathInfo { local, remote };

    let dcid = ConnectionId::new(&[0x11; 16]).expect("valid connection id");
    let scid = ConnectionId::new(&[0x22; 16]).expect("valid connection id");
    // サーバーは original_dcid を必ず通知する (RFC 9000 Section 7.3)
    let original_dcid = ConnectionId::new(&[0x33; 16]).expect("valid connection id");

    // 任意のデータグラムで到達できる経路を増やすため、DATAGRAM と
    // reliable stream reset を有効にしたトランスポートパラメータを使う
    let base_params = TransportParams::new()
        .with_datagram(1200)
        .with_reset_stream_at(true);
    // original_dcid はサーバーだけが設定する。クライアントで設定すると
    // ngtcp2 が接続の作成を拒否する (RFC 9000 Section 7.3)
    let params = if input.is_server {
        base_params.with_original_dcid(&original_dcid)
    } else {
        base_params
    };

    let mut settings = Settings::new(0);
    // NEW_CONNECTION_ID のトークンを導出するコールバックを有効にする
    settings.stateless_reset_secret = Some(StatelessResetSecret::from_bytes(
        [0x5a; STATELESS_RESET_SECRET_LEN],
    ));
    // qlog の出力コールバックを有効にする
    settings.qlog = true;

    let conn = if input.is_server {
        let session = server_tls_ctx()
            .create_session()
            .expect("TLS セッションを作成できること");
        Connection::server_new(
            &dcid,
            &scid,
            local,
            remote,
            QuicVersion::V1,
            session,
            &params,
            &settings,
        )
    } else {
        let session = client_tls_ctx()
            .create_session()
            .expect("TLS セッションを作成できること");
        Connection::client_new(
            &dcid,
            &scid,
            local,
            remote,
            QuicVersion::V1,
            "localhost",
            session,
            &params,
            &settings,
        )
    };
    let Ok(mut conn) = conn else {
        return;
    };

    // クライアントは Initial を送ってからでないと受信したパケットを復号できない
    // ため、先に送信を駆動して初期鍵をインストールする
    if !input.is_server {
        drain_packets(&mut conn, 0);
    }

    // 受信したデータグラムを処理する。
    //
    // ngtcp2 の契約 (ngtcp2_conn_read_pkt のドキュメント) では、回復可能な
    // エラー以外が返ったときにパケットの送信を続けてはならない。順序を守らずに
    // write_pkt を呼ぶと ngtcp2 が assert でプロセスを abort するため、
    // エラーの種別ごとに I/O 層 (tokio-ngtcp2) と同じ処理をする
    match conn.read_pkt(&path, &PacketInfo::default(), &input.datagram, 0) {
        // 正常に処理できた場合は、積まれた送信データを書き出す
        Ok(()) => drain_packets(&mut conn, 0),
        Err(e) => match e.classify_connection_error() {
            // 無視してよいエラーでは接続が継続するため、送信を続ける
            ConnectionErrorKind::Ignore => drain_packets(&mut conn, 0),
            // トランスポートエラーではパケットではなく終端パケット
            // (CONNECTION_CLOSE) を書き出す (RFC 9000 Section 11.1)
            ConnectionErrorKind::TransportClose | ConnectionErrorKind::ApplicationClose => {
                let error_code = match &e {
                    Error::Ngtcp2(_, code) => infer_quic_transport_error_code(*code),
                    _ => 0,
                };
                let mut buf = [0u8; SEND_BUFFER_SIZE];
                let _ = conn.write_connection_close(&mut buf, error_code, b"", 0);
            }
            // それ以外はパケットを送信してはならない
            ConnectionErrorKind::SilentDrop
            | ConnectionErrorKind::Terminal
            | ConnectionErrorKind::Internal => {}
        },
    }

    // read_pkt / write_pkt で ngtcp2 から呼ばれたコールバックの結果を処理する
    while conn.poll_event().is_some() {}
    while conn.poll_qlog_data().is_some() {}
});
