//! 接続イベント
//!
//! ngtcp2 のコールバックを Rust の列挙型 1 本に集約する。コールバックは
//! ngtcp2 の内部から同期的に呼ばれるため、アプリケーションのコードを直接
//! 呼ぶことはできない。代わりに [`crate::Connection`] 内部のキューに積み、
//! [`crate::Connection::poll_event`] で発生順に取り出す。

use crate::types::{PathInfo, StreamId};

/// 接続で発生したイベント
///
/// ngtcp2 のコールバックを 1 対 1 で表現する。`data` を持つ variant は
/// ngtcp2 が呼び出し後に領域を解放するため、コールバック内でコピーする。
///
/// 接続の終了 (CONNECTION_CLOSE の送受信、アイドルタイムアウト) は
/// イベントではなく [`crate::Connection::is_in_closing_period`] /
/// [`crate::Connection::is_in_draining_period`] /
/// [`crate::Connection::get_connection_error`] で観測する。sans-IO 層は
/// ソケットもタイマーも持たないため、終了の検出は呼び出し側の責任とする。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// ハンドシェイクが完了した (RFC 9001 Section 4.1.1)
    ///
    /// 1-RTT の送受信鍵が使えるようになった時点で 1 回だけ発生する。
    /// [`crate::Connection::is_handshake_completed`] が true になるのと
    /// 同じタイミング。
    HandshakeCompleted,

    /// ハンドシェイクが確認された (RFC 9001 Section 4.1.2)
    ///
    /// 両エンドポイントがハンドシェイク完了に合意した時点で発生する。
    /// この時点以降に 1-RTT パケットが失われると再送される (確認前は
    /// 暗号レベルの再送に依存する)。
    ///
    /// **クライアントでのみ発生する。** ngtcp2 は HANDSHAKE_DONE を受信した
    /// クライアントだけで `handshake_confirmed` コールバックを呼ぶ。サーバーは
    /// `ngtcp2_conn_tls_handshake_completed` が確認済みフラグを立てるだけで
    /// コールバックを呼ばない (ngtcp2 の実装由来の非対称。将来変更される
    /// 可能性がある)。サーバー側では [`ConnectionEvent::HandshakeCompleted`]
    /// を使うこと。
    HandshakeConfirmed,

    /// 0-RTT (early data) が拒否された (RFC 9001 Section 4.6.2)
    ///
    /// **クライアントでのみ発生する。** サーバーが 0-RTT を受理しなかった
    /// 場合、またはクライアントが 0-RTT を送らないと判断した場合に発生する。
    /// ngtcp2 はこの時点で 0-RTT で開いたストリームと送信待ちのデータを
    /// 破棄するため、アプリケーションはストリームを開き直してデータを
    /// 送り直す必要がある ([`crate::Connection::is_early_data_rejected`] でも
    /// 観測できる)。
    ///
    /// 0-RTT のデータはリプレイ攻撃に対して脆弱であるため、サーバーは
    /// 受理しない判断をすることがある (RFC 9001 Section 9.2)。
    EarlyDataRejected,

    /// ピアが新しいストリームを開いた (RFC 9000 Section 2.1)
    ///
    /// ピア開始のストリームに初めてデータまたは RESET_STREAM /
    /// STOP_SENDING が届いたときに発生する。ローカルが
    /// [`crate::Connection::open_bidi_stream`] /
    /// [`crate::Connection::open_uni_stream`] で開いたストリームでは
    /// 発生しない。
    StreamOpened {
        /// ストリーム ID
        stream_id: StreamId,
    },

    /// ストリームデータを受信した (RFC 9000 Section 19.8)
    ///
    /// データはオフセットの非減少順に、重複なく渡される。
    /// フロー制御クレジットは [`crate::Connection::extend_max_stream_offset`]
    /// を呼ぶまで消費されない。
    StreamData {
        /// ストリーム ID
        stream_id: StreamId,
        /// 受信データ
        data: Vec<u8>,
        /// このデータでストリームの終端に達したか (RFC 9000 Section 19.8)
        ///
        /// `fin` が true かつ `data` が空の場合がある。
        fin: bool,
    },

    /// ストリームが閉じた (RFC 9000 Section 3.3)
    ///
    /// 送受信の両方向が終端またはリセットされたときに 1 回だけ発生する。
    /// QUIC はストリームの送信側と受信側を独立に閉じられるため
    /// (RFC 9000 Section 2.2 / 2.3)、エラーコードも方向ごとに分かれる。
    ///
    /// 接続自体が閉じた場合は、開いていたストリームに対してこの
    /// イベントは発生しない (ngtcp2 の `stream_close2` の仕様)。
    StreamClosed {
        /// ストリーム ID
        stream_id: StreamId,
        /// 受信側をエラーで閉じた場合のアプリケーションエラーコード
        ///
        /// ピアの RESET_STREAM、またはローカルの
        /// [`crate::Connection::shutdown_stream_read`] が運んだコード。
        /// `None` は受信側が正常に終端したことを意味する
        /// (RFC 9000 Section 19.4 / 19.5)。
        rx_app_error_code: Option<u64>,
        /// 送信側をエラーで閉じた場合のアプリケーションエラーコード
        ///
        /// ローカルの [`crate::Connection::shutdown_stream_write`]、または
        /// ピアの STOP_SENDING に応答して送った RESET_STREAM が運んだコード。
        /// `None` は送信側が FIN で正常に終端したことを意味する
        /// (RFC 9000 Section 19.4 / 19.5)。
        tx_app_error_code: Option<u64>,
    },

    /// ピアが RESET_STREAM を送った (RFC 9000 Section 19.4)
    ///
    /// このストリームの受信側は即座に終端する。`StreamClosed` は
    /// 送信側も閉じた後に続けて発生する。
    StreamReset {
        /// ストリーム ID
        stream_id: StreamId,
        /// ストリームの最終サイズ (RFC 9000 Section 19.4)
        final_size: u64,
        /// アプリケーションエラーコード
        app_error_code: u64,
    },

    /// ピアが STOP_SENDING を送った (RFC 9000 Section 19.5)
    ///
    /// ピアがこのストリームを受信しないことを宣言した。ngtcp2 は
    /// 自動的に RESET_STREAM を送り返すため、アプリケーションは
    /// 送信待ちのデータをこれ以上渡してはいけない。
    StreamStopSending {
        /// ストリーム ID
        stream_id: StreamId,
        /// アプリケーションエラーコード
        app_error_code: u64,
    },

    /// ピアが MAX_STREAM_DATA を送った (RFC 9000 Section 19.10)
    ///
    /// このストリームに送信できる累計バイト数の上限が増えた。
    /// [`crate::Error::StreamDataBlocked`] で止まっていた送信を
    /// 再開できる。
    StreamMaxData {
        /// ストリーム ID
        stream_id: StreamId,
        /// 送信可能な累計バイト数の上限
        max_data: u64,
    },

    /// ピアが MAX_STREAMS (双方向) を送った (RFC 9000 Section 19.11)
    ///
    /// ローカルが開ける双方向ストリームの累計上限が増えた。
    /// 上限に達していた [`crate::Connection::open_bidi_stream`] を
    /// 再開できる。残り数は [`crate::Connection::get_streams_bidi_left`]。
    ///
    /// ngtcp2 はハンドシェイク完了時にもこのコールバックを 1 回呼び、ピアの
    /// `initial_max_streams_bidi` を通知する (ngtcp2 の
    /// `conn_handshake_completed` の実装による)。したがって接続ごとに
    /// 必ず 1 回は発生する。
    MaxStreamsBidi {
        /// 開ける双方向ストリームの累計上限
        max_streams: u64,
    },

    /// ピアが MAX_STREAMS (単方向) を送った (RFC 9000 Section 19.11)
    ///
    /// ローカルが開ける単方向ストリームの累計上限が増えた。
    /// 残り数は [`crate::Connection::get_streams_uni_left`]。
    ///
    /// [`ConnectionEvent::MaxStreamsBidi`] と同様に、ハンドシェイク完了時に
    /// ピアの `initial_max_streams_uni` を通知するために 1 回発生する。
    MaxStreamsUni {
        /// 開ける単方向ストリームの累計上限
        max_streams: u64,
    },

    /// DATAGRAM を受信した (RFC 9221)
    ///
    /// DATAGRAM は信頼性のない配信であり、順序も再送も保証されない。
    Datagram {
        /// データグラムデータ
        data: Vec<u8>,
    },

    /// Stateless Reset を受信した (RFC 9000 Section 10.3)
    ///
    /// ピアがこの接続の状態を失っていることを意味する。トークンが
    /// 一致した場合にだけ発生し (RFC 9000 Section 10.3.1)、直後に接続は
    /// draining 状態に移行する。
    ///
    /// 再接続するかどうかはアプリケーションが判断する。
    StatelessResetReceived,

    /// 経路の検証が完了した (RFC 9000 Section 8.2)
    ///
    /// [`crate::Connection::initiate_migration`] /
    /// [`crate::Connection::initiate_immediate_migration`] で開始した検証、
    /// またはピアが新しいアドレスから送ってきたパケットに対する検証の結果。
    ///
    /// `success` が true の場合は `path` が接続の経路として使われる。
    /// false の場合は元の経路が使われ続ける
    /// (RFC 9000 Section 9.3.2 / 9.4)。
    PathValidated {
        /// 検証した経路
        path: PathInfo,
        /// 検証に成功したか
        success: bool,
    },
}
