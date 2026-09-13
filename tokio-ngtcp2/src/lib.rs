//! ngtcp2 を tokio と統合した非同期 QUIC クライアント / サーバー
//!
//! [ngtcp2](https://github.com/ngtcp2/ngtcp2) を tokio の非同期ランタイムで
//! 動かすための UDP ソケット統合を提供する。プロトコルの状態機械は
//! `shiguredo_ngtcp2` が担い、このクレートはソケット I/O とイベントループだけを持つ。
//!
//! # 設計
//!
//! - [`Client`] / [`ClientConnection`]: クライアント側の接続
//! - [`Server`] / [`AcceptedConnection`]: サーバー側の接続
//! - 受信したデータと接続の状態変化は [`ConnectionEvent`] として取り出す
//!
//! 受信したストリームデータはアプリケーションが処理し終えた時点で
//! [`ClientConnection::extend_max_stream_offset`] を呼んでフロー制御クレジットを
//! 戻す (RFC 9000 Section 19.9)。戻さない限りピアは次のデータを送れないため、
//! バッファが必要以上に膨らまない。
//!
//! # 使い方
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use shiguredo_ngtcp2_tokio::{Client, ConnectionEvent};
//!
//! # async fn example() -> shiguredo_ngtcp2::Result<()> {
//! let remote: SocketAddr = "127.0.0.1:4433".parse().expect("valid address");
//! let mut conn = Client::connect(remote, "localhost").await?;
//!
//! let stream_id = conn.open_bidi_stream()?;
//! // write_stream は送信待ちに積むだけ。flush で送信する
//! conn.write_stream(stream_id, b"hello", true)?;
//! conn.flush().await?;
//!
//! loop {
//!     match conn.recv_event().await? {
//!         ConnectionEvent::StreamData { stream_id, data, .. } => {
//!             conn.extend_max_stream_offset(stream_id, data.len() as u64)?;
//!         }
//!         ConnectionEvent::ConnectionClosed { .. } => break,
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

mod client;
mod qlog;
mod server;
mod socket;
mod streams;

pub use client::{Client, ClientConfig, ClientConnection};
pub use server::{AcceptedConnection, Server, ServerConfig};

// 利用者がこれらを直接使うため再公開する
pub use shiguredo_ngtcp2::{
    AddressValidationToken, CongestionAlgorithm, ConnStats, ConnectionErrorKind, ConnectionId,
    Error, PathInfo, QuicVersion, RemoteTransportParams, Result, RetrySecret, SessionTicket,
    Settings, StatelessResetSecret, StreamDirection, StreamType, TransportParams,
};

/// QUIC ストリーム ID (RFC 9000 Section 2.1)
pub type StreamId = i64;

/// DATAGRAM のローカル設定 (RFC 9221)
///
/// [`TransportParams`] がピアに通知する値であるのに対し、こちらは
/// 送受信の上限を決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramConfig {
    /// 受信を許可する最大 DATAGRAM サイズ。0 で無効
    pub max_datagram_frame_size: u64,
    /// 送信する DATAGRAM の最大サイズ
    pub max_tx_datagram_size: usize,
}

impl DatagramConfig {
    /// DATAGRAM を無効にした設定を返す
    pub fn disabled() -> Self {
        Self {
            max_datagram_frame_size: 0,
            max_tx_datagram_size: 0,
        }
    }

    /// DATAGRAM が有効かどうかを返す
    pub fn is_enabled(&self) -> bool {
        self.max_datagram_frame_size > 0 && self.max_tx_datagram_size > 0
    }
}

impl Default for DatagramConfig {
    /// DATAGRAM を有効にしたデフォルト設定
    ///
    /// 受信は 65535 バイトまで、送信は 1 パケットに収まる 1200 バイトを上限とする。
    fn default() -> Self {
        Self {
            max_datagram_frame_size: 65535,
            max_tx_datagram_size: 1200,
        }
    }
}

/// 接続で発生したイベント
///
/// [`ClientConnection::recv_event`] / [`AcceptedConnection::recv_event`] で取り出す。
///
/// sans-IO 層の [`shiguredo_ngtcp2::ConnectionEvent`] に、この層だけが検出できる
/// [`ConnectionEvent::ConnectionClosed`] を加えたもの。sans-IO 層の variant を
/// 追加した場合は [`From`] 実装の網羅的 `match` がコンパイルエラーになるため、
/// 変換の追加漏れが起きない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// ハンドシェイクが完了した (RFC 9001 Section 4.1.1)
    ///
    /// 接続ごとに 1 回だけ通知される。
    HandshakeCompleted,

    /// ハンドシェイクが確認された (RFC 9001 Section 4.1.2)
    ///
    /// 両エンドポイントがハンドシェイク完了に合意した時点で通知される。
    ///
    /// **クライアント側でのみ通知される。** ngtcp2 は HANDSHAKE_DONE を
    /// 受信したクライアントだけで `handshake_confirmed` コールバックを呼ぶ
    /// ため、サーバー側には届かない。サーバー側では
    /// [`ConnectionEvent::HandshakeCompleted`] を使うこと。
    HandshakeConfirmed,

    /// 0-RTT (early data) が拒否された (RFC 9001 Section 4.6.2)
    ///
    /// **クライアント側でのみ通知される。** [`Client::connect_with_early_data`]
    /// で 0-RTT を送ったのにサーバーが受理しなかった場合に届く。
    /// この時点で 0-RTT で開いたストリームと送信待ちのデータは破棄されるため、
    /// ストリームを開き直してデータを送り直すこと (0-RTT のデータが失われる
    /// ことは RFC 9001 Section 4.6.2 が想定する挙動であり、再送するかどうかは
    /// アプリケーションの責任)。
    EarlyDataRejected,

    /// ピアが新しいストリームを開いた (RFC 9000 Section 2.1)
    ///
    /// ピア開始のストリームで 1 回だけ通知される。ローカルが
    /// [`ClientConnection::open_bidi_stream`] などで開いたストリームでは
    /// 通知されない。
    StreamOpened {
        /// ストリーム ID
        stream_id: StreamId,
    },

    /// ストリームデータを受信した (RFC 9000 Section 19.8)
    StreamData {
        /// ストリーム ID
        stream_id: StreamId,
        /// 受信データ
        data: Vec<u8>,
        /// このイベントでストリームの終端に達したか
        fin: bool,
    },

    /// ストリームが閉じた (RFC 9000 Section 3.3)
    ///
    /// 送受信の両方向が終端またはリセットされたときに 1 回だけ通知される。
    /// エラーコードは方向ごとに分かれており、`None` はその方向が正常に
    /// 閉じたことを意味する。
    StreamClosed {
        /// ストリーム ID
        stream_id: StreamId,
        /// 受信側をエラーで閉じた場合のアプリケーションエラーコード
        rx_app_error_code: Option<u64>,
        /// 送信側をエラーで閉じた場合のアプリケーションエラーコード
        tx_app_error_code: Option<u64>,
    },

    /// ピアが RESET_STREAM を送った (RFC 9000 Section 19.4)
    StreamReset {
        /// ストリーム ID
        stream_id: StreamId,
        /// ストリームの最終サイズ
        final_size: u64,
        /// アプリケーションエラーコード
        app_error_code: u64,
    },

    /// ピアが STOP_SENDING を送った (RFC 9000 Section 19.5)
    ///
    /// ピアがこのストリームを受信しないことを宣言した。以降このストリームに
    /// [`ClientConnection::write_stream`] しても [`Error::StreamShutWr`] になる。
    StreamStopSending {
        /// ストリーム ID
        stream_id: StreamId,
        /// アプリケーションエラーコード
        app_error_code: u64,
    },

    /// ピアが MAX_STREAM_DATA を送った (RFC 9000 Section 19.10)
    ///
    /// このストリームに送信できる累計バイト数の上限が増えた。
    StreamMaxData {
        /// ストリーム ID
        stream_id: StreamId,
        /// 送信可能な累計バイト数の上限
        max_data: u64,
    },

    /// ピアが MAX_STREAMS (双方向) を送った (RFC 9000 Section 19.11)
    ///
    /// ハンドシェイク完了時にもピアの `initial_max_streams_bidi` を通知する
    /// ために 1 回発生する。
    MaxStreamsBidi {
        /// 開ける双方向ストリームの累計上限
        max_streams: u64,
    },

    /// ピアが MAX_STREAMS (単方向) を送った (RFC 9000 Section 19.11)
    ///
    /// [`ConnectionEvent::MaxStreamsBidi`] と同様にハンドシェイク完了時に
    /// 1 回発生する。
    MaxStreamsUni {
        /// 開ける単方向ストリームの累計上限
        max_streams: u64,
    },

    /// DATAGRAM を受信した (RFC 9221)
    Datagram {
        /// データグラムデータ
        data: Vec<u8>,
    },

    /// Stateless Reset を受信した (RFC 9000 Section 10.3)
    ///
    /// ピアがこの接続の状態を失っていることを意味する。トークンが一致した
    /// 場合にだけ通知され (RFC 9000 Section 10.3.1)、直後に
    /// [`ConnectionEvent::ConnectionClosed`] が続く。
    StatelessResetReceived,

    /// 経路の検証が完了した (RFC 9000 Section 8.2)
    ///
    /// [`ClientConnection::migrate`] による新しい経路の検証、またはピアが
    /// 新しいアドレスから送ってきたパケットに対する検証の結果。
    /// `success` が true の場合は `path` が接続の経路として使われる。
    PathValidated {
        /// 検証した経路
        path: PathInfo,
        /// 検証に成功したか
        success: bool,
    },

    /// 接続が閉じた
    ///
    /// ピアからの CONNECTION_CLOSE、アイドルタイムアウト、ローカルからの
    /// `close` のいずれかで発生する。このイベントを受け取った後に
    /// `recv_event` を呼ぶと [`Error::ConnectionClosed`] を返す。
    ConnectionClosed {
        /// エラーコード。正常終了の場合は 0
        error_code: u64,
        /// エラー理由 (ピアが指定した場合はその文字列)
        reason: String,
        /// エラーの種別
        kind: ConnectionErrorKind,
    },
}

impl From<shiguredo_ngtcp2::ConnectionEvent> for ConnectionEvent {
    /// sans-IO 層のイベントをこの層のイベントへ変換する
    ///
    /// ワイルドカードアームを書かないことで、sans-IO 層に variant が
    /// 追加されたときにコンパイルエラーで気づけるようにする。
    fn from(event: shiguredo_ngtcp2::ConnectionEvent) -> Self {
        use shiguredo_ngtcp2::ConnectionEvent as Core;

        match event {
            Core::HandshakeCompleted => Self::HandshakeCompleted,
            Core::HandshakeConfirmed => Self::HandshakeConfirmed,
            Core::EarlyDataRejected => Self::EarlyDataRejected,
            Core::StreamOpened { stream_id } => Self::StreamOpened { stream_id },
            Core::StreamData {
                stream_id,
                data,
                fin,
            } => Self::StreamData {
                stream_id,
                data,
                fin,
            },
            Core::StreamClosed {
                stream_id,
                rx_app_error_code,
                tx_app_error_code,
            } => Self::StreamClosed {
                stream_id,
                rx_app_error_code,
                tx_app_error_code,
            },
            Core::StreamReset {
                stream_id,
                final_size,
                app_error_code,
            } => Self::StreamReset {
                stream_id,
                final_size,
                app_error_code,
            },
            Core::StreamStopSending {
                stream_id,
                app_error_code,
            } => Self::StreamStopSending {
                stream_id,
                app_error_code,
            },
            Core::StreamMaxData {
                stream_id,
                max_data,
            } => Self::StreamMaxData {
                stream_id,
                max_data,
            },
            Core::MaxStreamsBidi { max_streams } => Self::MaxStreamsBidi { max_streams },
            Core::MaxStreamsUni { max_streams } => Self::MaxStreamsUni { max_streams },
            Core::Datagram { data } => Self::Datagram { data },
            Core::StatelessResetReceived => Self::StatelessResetReceived,
            Core::PathValidated { path, success } => Self::PathValidated { path, success },
        }
    }
}
