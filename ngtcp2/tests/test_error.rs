//! エラー型の統合テスト
//!
//! `Error` の表示と `ConnectionErrorKind` への分類を検証する。
//! 分類は ngtcp2 の API 契約 (`ngtcp2_conn_read_pkt` のドキュメント) に基づく。

use shiguredo_ngtcp2::{ConnectionErrorKind, Error};

// ngtcp2 のエラーコードの値。
//
// `shiguredo_ngtcp2_sys` を直接依存せずにテストするため、ngtcp2.h の
// #define の値をそのまま使う。値が変わった場合は
// shiguredo_ngtcp2_sys のテストで検出する。
/// NGTCP2_ERR_INVALID_ARGUMENT
const ERR_INVALID_ARGUMENT: i32 = -201;
/// NGTCP2_ERR_DISCARD_PKT
const ERR_DISCARD_PKT: i32 = -226;
/// NGTCP2_ERR_DROP_CONN
const ERR_DROP_CONN: i32 = -232;
/// NGTCP2_ERR_IDLE_CLOSE
const ERR_IDLE_CLOSE: i32 = -238;
/// NGTCP2_ERR_RETRY
const ERR_RETRY: i32 = -231;
/// NGTCP2_ERR_DRAINING
const ERR_DRAINING: i32 = -224;
/// NGTCP2_ERR_CLOSING
const ERR_CLOSING: i32 = -223;
/// NGTCP2_ERR_CRYPTO
const ERR_CRYPTO: i32 = -213;

/// `Error::from_ngtcp2` が ngtcp2 のエラーメッセージを取り込むこと
#[test]
fn test_error_from_ngtcp2_message() {
    let err = Error::from_ngtcp2(ERR_INVALID_ARGUMENT);
    match &err {
        Error::Ngtcp2(msg, code) => {
            assert_eq!(*code, ERR_INVALID_ARGUMENT, "エラーコード");
            assert!(!msg.is_empty(), "メッセージが空でないこと");
            assert_ne!(msg, "unknown error", "ngtcp2 のメッセージが取れること");
        }
        other => panic!("Ngtcp2 variant になること: {other:?}"),
    }

    // Display にコードが含まれること
    let displayed = format!("{err}");
    assert!(displayed.contains("ngtcp2 error"), "Display の接頭辞");
    assert!(
        displayed.contains(&ERR_INVALID_ARGUMENT.to_string()),
        "Display にエラーコードが含まれること"
    );
}

/// 未知の ngtcp2 エラーコードでも Display できること
#[test]
fn test_error_from_ngtcp2_unknown_code() {
    let err = Error::from_ngtcp2(-99999);
    let displayed = format!("{err}");
    assert!(
        displayed.contains("-99999"),
        "未知のコードでも表示できること: {displayed}"
    );
}

/// 各 variant の Display が期待どおりであること
#[test]
fn test_error_display() {
    assert_eq!(
        format!("{}", Error::InvalidArgument("bad input".to_string())),
        "invalid argument: bad input"
    );
    assert_eq!(
        format!("{}", Error::ConnectionClosed),
        "connection is closed"
    );
    assert_eq!(
        format!("{}", Error::StreamDataBlocked(8)),
        "stream data blocked: 8"
    );
    assert_eq!(format!("{}", Error::StreamShutWr(12)), "stream shut wr: 12");
    assert_eq!(
        format!("{}", Error::Internal("boom".to_string())),
        "internal error: boom"
    );
}

/// ngtcp2 の回復可能エラーが正しく分類されること
#[test]
fn test_classify_connection_error_ngtcp2() {
    // パケット破棄の指示は無視する
    assert_eq!(
        Error::from_ngtcp2(ERR_DISCARD_PKT).classify_connection_error(),
        ConnectionErrorKind::Ignore,
        "NGTCP2_ERR_DISCARD_PKT は Ignore"
    );

    // 接続を黙って破棄する
    for code in [ERR_DROP_CONN, ERR_IDLE_CLOSE, ERR_RETRY] {
        assert_eq!(
            Error::from_ngtcp2(code).classify_connection_error(),
            ConnectionErrorKind::SilentDrop,
            "code={code} は SilentDrop"
        );
    }

    // 終了状態
    for code in [ERR_DRAINING, ERR_CLOSING] {
        assert_eq!(
            Error::from_ngtcp2(code).classify_connection_error(),
            ConnectionErrorKind::Terminal,
            "code={code} は Terminal"
        );
    }

    // それ以外はトランスポートエラー
    assert_eq!(
        Error::from_ngtcp2(ERR_CRYPTO).classify_connection_error(),
        ConnectionErrorKind::TransportClose,
        "NGTCP2_ERR_CRYPTO は TransportClose"
    );
}

/// ngtcp2 以外のエラーが正しく分類されること
#[test]
fn test_classify_connection_error_other() {
    // ストリーム単位のフロー制御シグナルは接続エラーではない
    assert_eq!(
        Error::StreamDataBlocked(0).classify_connection_error(),
        ConnectionErrorKind::Ignore,
        "StreamDataBlocked は Ignore"
    );
    assert_eq!(
        Error::StreamShutWr(0).classify_connection_error(),
        ConnectionErrorKind::Ignore,
        "StreamShutWr は Ignore"
    );

    // 接続の終了は Terminal
    assert_eq!(
        Error::ConnectionClosed.classify_connection_error(),
        ConnectionErrorKind::Terminal,
        "ConnectionClosed は Terminal"
    );

    // 実装側の問題は Internal
    for err in [
        Error::InvalidArgument("x".to_string()),
        Error::Internal("x".to_string()),
    ] {
        assert_eq!(
            err.classify_connection_error(),
            ConnectionErrorKind::Internal,
            "{err:?} は Internal"
        );
    }
}

/// Retry の送信要求だけが `is_retry_required` で真になること
///
/// サーバーはこの判定で Retry の送信を決めるため、他のエラーを
/// Retry と取り違えないことを保証する。
#[test]
fn test_is_retry_required() {
    assert!(
        Error::from_ngtcp2(ERR_RETRY).is_retry_required(),
        "NGTCP2_ERR_RETRY だけが Retry の送信要求であること"
    );

    for code in [ERR_DISCARD_PKT, ERR_DROP_CONN, ERR_IDLE_CLOSE, ERR_CRYPTO] {
        assert!(
            !Error::from_ngtcp2(code).is_retry_required(),
            "code={code} を Retry と取り違えないこと"
        );
    }

    // 接続エラー以外の variant も Retry ではない
    for err in [
        Error::ConnectionClosed,
        Error::StreamDataBlocked(0),
        Error::StreamShutWr(0),
        Error::InvalidArgument("x".to_string()),
        Error::Internal("x".to_string()),
    ] {
        assert!(!err.is_retry_required(), "{err:?} は Retry ではない");
    }
}

/// `Error` が `std::error::Error` を実装していること
#[test]
fn test_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(Error::ConnectionClosed);
    assert_eq!(err.to_string(), "connection is closed");
}
