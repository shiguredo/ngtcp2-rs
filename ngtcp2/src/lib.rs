//! ngtcp2 の sans-IO な QUIC 実装
//!
//! このクレートは [ngtcp2](https://github.com/ngtcp2/ngtcp2) を Rust から利用するための
//! sans-IO な QUIC プロトコル実装を提供する。
//!
//! # 設計
//!
//! ソケット I/O を一切持たず、パケットの読み書きとタイマー管理だけを提供する。
//! 呼び出し側が UDP ソケットを用意し、[`Connection::read_pkt`] と
//! [`Connection::write_pkt`] を駆動する。非同期ランタイムとの統合は
//! `shiguredo_ngtcp2_tokio` が担う。
//!
//! # 使い方
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use shiguredo_ngtcp2::{
//!     Connection, ConnectionEvent, ConnectionId, PacketInfo, PathInfo, QuicVersion, Settings,
//!     TlsContext, TransportParams,
//! };
//!
//! # fn main() -> shiguredo_ngtcp2::Result<()> {
//! let local: SocketAddr = "127.0.0.1:50000".parse().expect("valid address");
//! let remote: SocketAddr = "127.0.0.1:4433".parse().expect("valid address");
//!
//! let tls_ctx = TlsContext::new_client(&[b"hq-interop"])?;
//! let session = tls_ctx.create_session()?;
//! let dcid = ConnectionId::random(16).expect("valid connection id");
//! let scid = ConnectionId::random(16).expect("valid connection id");
//! let params = TransportParams::new();
//!
//! let mut conn = Connection::client_new(
//!     &dcid, &scid, local, remote, QuicVersion::V1, "localhost", session, &params,
//!     &Settings::new(0),
//! )?;
//!
//! // 受信パケットを処理する (data は UDP で受信したペイロード)
//! let data: &[u8] = &[];
//! let path = PathInfo { local, remote };
//! let _ = conn.read_pkt(&path, &PacketInfo::default(), data, 0);
//!
//! // 送信パケットを書き出す
//! let mut buf = [0u8; 1350];
//! loop {
//!     let (written, _info, _path) = conn.write_pkt(&mut buf, 0)?;
//!     if written == 0 {
//!         break;
//!     }
//!     // buf[..written] を UDP で送信する
//! }
//!
//! // 発生したイベントを取り出す
//! while let Some(event) = conn.poll_event() {
//!     match event {
//!         ConnectionEvent::StreamData { stream_id, data, .. } => {
//!             // 処理し終えたらフロー制御クレジットを戻す
//!             conn.extend_max_stream_offset(stream_id, data.len() as u64)?;
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

mod config;
mod conn;
mod crypto;
mod error;
mod event;
pub mod packet;
mod reset;
mod retry;
mod settings;
mod stats;
mod types;
pub mod varint;
mod version;

pub use config::{RemoteTransportParams, TransportParams};
pub use conn::{Connection, ConnectionError, SessionTicket};
pub use crypto::{TlsContext, TlsSession};
pub use error::{ConnectionErrorKind, Error, Result};
pub use event::ConnectionEvent;
pub use reset::{
    MIN_STATELESS_RESET_SIZE, STATELESS_RESET_SECRET_LEN, STATELESS_RESET_TOKEN_LEN,
    StatelessResetSecret, StatelessResetToken, write_stateless_reset,
};
pub use retry::{
    AcceptedInitial, AddressValidationToken, AddressValidationTokenKind, MAX_NEW_TOKEN_LEN,
    MAX_RETRY_TOKEN_LEN, RETRY_SECRET_LEN, RetrySecret, TRANSPORT_ERROR_INVALID_TOKEN,
    accept_initial, generate_new_token, generate_retry_token, token_kind, verify_new_token,
    verify_retry_token, write_retry_packet, write_stateless_connection_close,
};
pub use settings::{
    CongestionAlgorithm, DEFAULT_INITIAL_RTT, DEFAULT_MAX_TX_UDP_PAYLOAD_SIZE, Settings,
};
pub use stats::ConnStats;
pub use types::{
    ConnectionId, NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2, PacketInfo, PathInfo, QuicVersion,
    StreamDirection, StreamId, StreamType,
};
pub use version::{
    LongHeaderType, PacketVersion, decode_packet_version, long_header_type,
    write_version_negotiation,
};

/// ngtcp2 のバージョン文字列を取得する
///
/// ビルドに使われた ngtcp2 のバージョンを返す。取得に失敗した場合は `"unknown"`。
pub fn ngtcp2_version() -> &'static str {
    // ngtcp2 のリポジトリは可動ブランチ `reliable-stream-reset` を取得するため、
    // 上流が進むと値が変わる。テストではこの定数と突き合わせる。
    version_string()
}

/// ビルドに使われた ngtcp2 のバージョン文字列 (コンパイル時定数)
///
/// `bindings.rs` の `NGTCP2_VERSION` と同じ値。
pub const NGTCP2_VERSION: &str = "1.25.90";

/// 実際にリンクされた ngtcp2 からバージョン文字列を取得する
fn version_string() -> &'static str {
    // SAFETY: ngtcp2_version は引数の age に対して有効な静的領域を返す
    unsafe {
        let info = shiguredo_ngtcp2_sys::ngtcp2_version(0);
        if info.is_null() {
            return "unknown";
        }
        let version_str = (*info).version_str;
        if version_str.is_null() {
            return "unknown";
        }
        // SAFETY: version_str は ngtcp2 が管理する NUL 終端文字列
        std::ffi::CStr::from_ptr(version_str)
            .to_str()
            .unwrap_or("unknown")
    }
}

/// 1 つの UDP データグラムに収まる最小バイト数 (RFC 9000 Section 14.1)
///
/// Initial パケットを含むデータグラムはこの長さ以上でなければならない。
pub const MIN_INITIAL_DATAGRAM_SIZE: usize =
    shiguredo_ngtcp2_sys::NGTCP2_MAX_UDP_PAYLOAD_SIZE as usize;

/// クライアントの最初の Initial の DCID に要求される最小長 (RFC 9000 Section 7.2)
pub const MIN_INITIAL_DCIDLEN: usize = shiguredo_ngtcp2_sys::NGTCP2_MIN_INITIAL_DCIDLEN as usize;

/// エラーコードから QUIC トランスポートエラーコードを導出する (RFC 9000 Section 20.1)
///
/// CONNECTION_CLOSE フレームでピアに通知するコードを求めるために使用する。
pub fn infer_quic_transport_error_code(code: libc::c_int) -> u64 {
    // SAFETY: ngtcp2_err_infer_quic_transport_error_code は引数のみに依存する純粋な変換
    unsafe { shiguredo_ngtcp2_sys::ngtcp2_err_infer_quic_transport_error_code(code) }
}

/// ngtcp2 の定数 `NGTCP2_WRITE_STREAM_FLAG_MORE`
///
/// 複数のストリームデータを 1 つのパケットにまとめるためのフラグ。
pub const WRITE_STREAM_FLAG_MORE: u32 = shiguredo_ngtcp2_sys::NGTCP2_WRITE_STREAM_FLAG_MORE;

#[cfg(test)]
pub(crate) mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// テスト用の自己署名証明書と秘密鍵を生成する
    ///
    /// 戻り値は `(証明書のパス, 秘密鍵のパス)`。テスト終了時に
    /// [`remove_test_certs`] で削除すること。
    pub(crate) fn generate_test_certs(label: &str) -> (PathBuf, PathBuf) {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!(
            "ngtcp2_test_{}_{}_{}",
            label,
            std::process::id(),
            unique_id
        ));
        std::fs::create_dir_all(&temp_dir).expect("テスト用ディレクトリを作成できること");

        let cert_path = temp_dir.join("cert.pem");
        let key_path = temp_dir.join("key.pem");

        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("証明書パラメータ");
        let key_pair = rcgen::KeyPair::generate().expect("鍵ペアを生成できること");
        let cert = params
            .self_signed(&key_pair)
            .expect("自己署名証明書を生成できること");

        std::fs::write(&cert_path, cert.pem()).expect("証明書を書き込めること");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("秘密鍵を書き込めること");

        (cert_path, key_path)
    }

    /// テスト用の証明書と秘密鍵を削除する
    pub(crate) fn remove_test_certs(cert_path: &Path, key_path: &Path) {
        if let Some(dir) = cert_path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
        let _ = key_path;
    }

    /// ngtcp2 のバージョン文字列が取得できること
    #[test]
    fn test_ngtcp2_version() {
        let version = crate::ngtcp2_version();
        assert_ne!(version, "unknown", "バージョン文字列が取得できること");
        assert_eq!(
            version,
            crate::NGTCP2_VERSION,
            "リンクされた ngtcp2 と bindings.rs のバージョンが一致すること"
        );
    }
}
