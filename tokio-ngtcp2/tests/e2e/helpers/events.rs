//! イベント受信のヘルパー
//!
//! 接続の確立過程で必ず発生するイベントはテストの対象外のため、
//! 読み飛ばすかどうかを判定する関数を提供する。
//!
//! 受信ループ自体をヘルパー関数にはしない。`AsyncFnMut` に渡すクロージャが
//! 接続を借用した future を返すと "captured variable cannot escape `FnMut`
//! closure body" となるため、各テストで明示的にループを書く。

use shiguredo_ngtcp2_tokio::ConnectionEvent;

/// 接続の確立過程で必ず発生するイベントかどうかを返す
///
/// 対象は以下の 2 種類。いずれもパケットの到着順に依存するタイミングで
/// 発生するため、他のイベントを検証するテストでは読み飛ばす。
///
/// - ハンドシェイクの進行 (`HandshakeCompleted` / `HandshakeConfirmed`)。
///   接続ごとに 1 回ずつ発生する (RFC 9001 Section 4.1)。
/// - ピアの初期ストリーム数の通知 (`MaxStreamsBidi` / `MaxStreamsUni`)。
///   ngtcp2 はハンドシェイク完了時に `extend_max_local_streams_*` を 1 回呼び、
///   ピアの `initial_max_streams_*` をアプリケーションに伝える。
///
/// MAX_STREAMS によるストリーム数の拡張そのものを検証するテストは、
/// この関数を使わずに `max_streams` の値で区別すること。
pub(crate) fn is_connection_setup_event(event: &ConnectionEvent) -> bool {
    matches!(
        event,
        ConnectionEvent::HandshakeCompleted
            | ConnectionEvent::HandshakeConfirmed
            | ConnectionEvent::MaxStreamsBidi { .. }
            | ConnectionEvent::MaxStreamsUni { .. }
    )
}
