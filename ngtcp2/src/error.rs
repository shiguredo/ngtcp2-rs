//! ngtcp2 のエラー型と接続エラーの分類

use std::ffi::CStr;
use std::fmt;

/// ngtcp2 のエラー型
///
/// このクレートが実際に生成する variant だけを保持する。ライブラリが
/// 生成しない variant を公開すると、利用者が到達しない分岐を書くことになる。
#[derive(Debug)]
pub enum Error {
    /// ngtcp2 が返したエラー
    ///
    /// 1 つ目のフィールドは `ngtcp2_strerror` のメッセージ、
    /// 2 つ目は ngtcp2 のエラーコード。
    Ngtcp2(String, libc::c_int),

    /// 無効な引数
    InvalidArgument(String),

    /// 接続が完全に閉じた (ピアからの CONNECTION_CLOSE、アイドルタイムアウトを含む)
    ConnectionClosed,

    /// ストリームがフロー制御でブロックされている
    ///
    /// 接続エラーではなくストリーム単位のシグナル。ピアの MAX_STREAM_DATA を
    /// 待って再送すること (RFC 9000 Section 4.1)。
    StreamDataBlocked(i64),

    /// ストリームの書き込みがシャットダウンされている
    ///
    /// 接続エラーではなくストリーム単位のシグナル。ピアの STOP_SENDING や
    /// ローカルの RESET_STREAM によって発生する。
    StreamShutWr(i64),

    /// 内部エラー
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Ngtcp2(msg, code) => write!(f, "ngtcp2 error: {} ({})", msg, code),
            Error::InvalidArgument(msg) => write!(f, "invalid argument: {}", msg),
            Error::ConnectionClosed => write!(f, "connection is closed"),
            Error::StreamDataBlocked(id) => write!(f, "stream data blocked: {}", id),
            Error::StreamShutWr(id) => write!(f, "stream shut wr: {}", id),
            Error::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Result 型エイリアス
pub type Result<T> = std::result::Result<T, Error>;

/// 接続エラーの種別
///
/// ngtcp2 の API 契約では `ngtcp2_conn_read_pkt` や `ngtcp2_conn_handle_expiry` が
/// 返す一部の負エラーは接続単位の非致命的エラーであり、サーバー全体を停止させては
/// ならない (`ngtcp2_conn_read_pkt` のドキュメント参照)。I/O 実装はこの分類に
/// 従ってエラーを接続単位で処理する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionErrorKind {
    /// 無視してよいエラー (パケットの破棄指示やストリーム単位のシグナル)
    Ignore,

    /// 接続を黙って破棄する
    ///
    /// NGTCP2_ERR_DROP_CONN / NGTCP2_ERR_IDLE_CLOSE / NGTCP2_ERR_RETRY。
    /// CONNECTION_CLOSE は送らない。
    SilentDrop,

    /// 終了状態 (closing / draining) に移行済みの接続
    ///
    /// NGTCP2_ERR_DRAINING / NGTCP2_ERR_CLOSING。
    /// 接続は閉じられつつあるため、そのままにして除去処理に任せる。
    Terminal,

    /// トランスポートエラー。CONNECTION_CLOSE (0x1c) を送って closing 状態にする
    ///
    /// NGTCP2_ERR_CRYPTO などの致命的エラー (RFC 9000 Section 11.1)。
    TransportClose,

    /// アプリケーションエラー。CONNECTION_CLOSE (0x1d) を送って closing 状態にする
    ///
    /// アプリケーション層のエラー (RFC 9000 Section 11.1)。
    ApplicationClose,

    /// 内部エラー。CONNECTION_CLOSE を送らずに接続を破棄する
    ///
    /// プロトコル違反ではなく実装側の問題であるため、ピアに通知する
    /// エラーコードが存在しない。
    Internal,
}

impl Error {
    /// ngtcp2 エラーコードからエラーを生成する
    pub fn from_ngtcp2(code: libc::c_int) -> Self {
        // SAFETY: ngtcp2_strerror は引数に依存しない静的領域へのポインタを返す
        let msg = unsafe {
            let ptr = shiguredo_ngtcp2_sys::ngtcp2_strerror(code);
            if ptr.is_null() {
                "unknown error".to_string()
            } else {
                // SAFETY: ptr は ngtcp2 が管理する NUL 終端文字列
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        Error::Ngtcp2(msg, code)
    }

    /// ngtcp2 が Retry パケットの送信を要求しているかどうかを返す
    ///
    /// `NGTCP2_ERR_RETRY` はサーバーがトークンを持たない Initial を受け取った
    /// ときに返る (RFC 9000 Section 8.1.2)。この場合は接続を破棄して
    /// Retry を送り、クライアントの再接続を待つ。
    ///
    /// アドレス検証を行わない実装では発生しない。
    pub fn is_retry_required(&self) -> bool {
        matches!(self, Error::Ngtcp2(_, code)
            if *code == shiguredo_ngtcp2_sys::NGTCP2_ERR_RETRY)
    }

    /// エラーを接続単位の種別へ分類する
    ///
    /// 分類は ngtcp2 の API 契約 (`ngtcp2_conn_read_pkt` /
    /// `ngtcp2_conn_handle_expiry` のドキュメント) に従う。各種別の詳細は
    /// `ConnectionErrorKind` の各 variant のドキュメント参照。
    ///
    /// NGTCP2_ERR_RETRY は Retry パケット送信の要求であり、接続単位の
    /// エラーではない。接続を黙って破棄する SilentDrop に分類し、
    /// Retry の送信は I/O 層が [`Error::is_retry_required`] で判断する。
    pub fn classify_connection_error(&self) -> ConnectionErrorKind {
        match self {
            Error::Ngtcp2(_, code) => match *code {
                shiguredo_ngtcp2_sys::NGTCP2_ERR_DISCARD_PKT => ConnectionErrorKind::Ignore,
                shiguredo_ngtcp2_sys::NGTCP2_ERR_DROP_CONN
                | shiguredo_ngtcp2_sys::NGTCP2_ERR_IDLE_CLOSE
                | shiguredo_ngtcp2_sys::NGTCP2_ERR_RETRY => ConnectionErrorKind::SilentDrop,
                shiguredo_ngtcp2_sys::NGTCP2_ERR_DRAINING
                | shiguredo_ngtcp2_sys::NGTCP2_ERR_CLOSING => ConnectionErrorKind::Terminal,
                _ => ConnectionErrorKind::TransportClose,
            },
            // ストリーム単位のフロー制御シグナル。接続エラーとして扱わない
            Error::StreamDataBlocked(_) | Error::StreamShutWr(_) => ConnectionErrorKind::Ignore,
            Error::ConnectionClosed => ConnectionErrorKind::Terminal,
            Error::InvalidArgument(_) | Error::Internal(_) => ConnectionErrorKind::Internal,
        }
    }
}

/// ngtcp2 の結果をチェックする
pub(crate) fn check_ngtcp2(code: libc::c_int) -> Result<()> {
    if code < 0 {
        Err(Error::from_ngtcp2(code))
    } else {
        Ok(())
    }
}
