# shiguredo_ngtcp2_tokio

[![crates.io](https://img.shields.io/crates/v/shiguredo_ngtcp2_tokio.svg)](https://crates.io/crates/shiguredo_ngtcp2_tokio)
[![docs.rs](https://docs.rs/shiguredo_ngtcp2_tokio/badge.svg)](https://docs.rs/shiguredo_ngtcp2_tokio)

[ngtcp2](https://github.com/ngtcp2/ngtcp2) を tokio で動かすための非同期 QUIC
クライアント / サーバーを提供するクレートです。

## 概要

`shiguredo_ngtcp2` の sans-IO な状態機械に、tokio の UDP ソケット I/O と
イベントループを組み合わせます。HTTP/3 などの上位プロトコルは含みません。

## 使い方 (クライアント)

```rust
use std::net::SocketAddr;
use shiguredo_ngtcp2_tokio::{Client, ConnectionEvent};

# async fn example() -> shiguredo_ngtcp2::Result<()> {
let remote: SocketAddr = "127.0.0.1:4433".parse().expect("valid address");
// 証明書検証なしで接続する
let mut conn = Client::connect(remote, "localhost").await?;

let stream_id = conn.open_bidi_stream()?;
conn.write_stream(stream_id, b"hello", true)?;
conn.flush().await?;

loop {
    match conn.recv_event().await? {
        ConnectionEvent::StreamData { stream_id, data, .. } => {
            // 処理し終えたらフロー制御クレジットを戻す
            conn.extend_max_stream_offset(stream_id, data.len() as u64)?;
        }
        ConnectionEvent::ConnectionClosed { .. } => break,
        _ => {}
    }
}
# Ok(())
# }
```

## 使い方 (サーバー)

```rust
use shiguredo_ngtcp2_tokio::{Server, ServerConfig};

# async fn example() -> shiguredo_ngtcp2::Result<()> {
let mut server = Server::bind(
    "127.0.0.1:4433".parse().expect("valid address"),
    "cert.pem",
    "key.pem",
    Some(ServerConfig::new(&[b"hq-interop"])),
)
.await?;

while let Some(mut conn) = server.accept().await? {
    tokio::spawn(async move {
        while let Ok(event) = conn.recv_event().await {
            // イベントを処理する
            let _ = event;
        }
    });
}
# Ok(())
# }
```

## 設計上の注意

### `write_stream` は送信しない

`write_stream` はデータを送信待ちに積むだけで、パケットは送りません。送信するには
`flush` または `recv_event` を呼んでください。

QUIC は双方向なので、送信側も受信してピアの ACK と MAX_STREAM_DATA を処理しないと
輻輳ウィンドウとフロー制御ウィンドウが伸びません。大きなデータを送る場合は
`recv_event` を併用してください。送信待ちが残っているかは `has_pending_data` で
確認できます。

### フロー制御クレジットは消費側が戻す

`ConnectionEvent::StreamData` で受け取ったデータは、`extend_max_stream_offset` を
呼ぶまでピアに消費が伝わりません。処理し終えたら必ず呼んでください。

ピアが開けるストリーム数の上限は自動では増えません。ピアのストリームを処理し終えたら
`extend_max_streams_bidi` / `extend_max_streams_uni` を呼んでください
(RFC 9000 Section 19.11)。呼ばない限りピアは上限に達した後に新しいストリームを
開けません。残り数は `streams_bidi_left` / `streams_uni_left`、接続全体の
フロー制御の残りは `max_data_left` で確認できます。

### 鍵の更新

長期間生きる接続では `initiate_key_update` で 1-RTT 鍵を更新できます
(RFC 9001 Section 6 / 4.6.3)。ピアは自動的に追従するため、再接続は不要です。

ハンドシェイクの確認前と、前の更新の確定から 1 PTO が経過するまでは
`NGTCP2_ERR_INVALID_STATE` で拒否されます。いずれも一時的な状態なので
再試行してください。接続が終了状態のときは `Error::InvalidArgument` を返します。

### 0-RTT (early data)

前回の接続で得たセッション情報を使うと、ハンドシェイクの完了を待たずにデータを
送れます (RFC 9000 Section 7.4.1 / RFC 9001 Section 4.6)。往復を 1 回減らせますが、
リプレイ攻撃に対して脆弱になるため、リプレイされて困る要求を送ってはいけません
(RFC 9001 Section 9.2)。

```rust
use shiguredo_ngtcp2_tokio::Client;

# async fn example(remote: std::net::SocketAddr, local: std::net::SocketAddr, config: shiguredo_ngtcp2_tokio::ClientConfig)
#     -> shiguredo_ngtcp2::Result<()> {
// 1 回目の接続。セッションチケットはハンドシェイク完了後に届く
let mut conn = Client::connect_with_config(remote, local, "localhost", &config).await?;
let ticket = loop {
    if let Some(ticket) = conn.take_session_ticket()? {
        break ticket;
    }
    conn.recv_event().await?;
};

// 2 回目の接続。0-RTT を送れる状態で戻る
let mut conn =
    Client::connect_with_early_data(remote, local, "localhost", &config, &ticket).await?;
assert!(conn.is_in_early_data());
let stream_id = conn.open_bidi_stream()?;
conn.write_stream(stream_id, b"early data", true)?;
conn.flush().await?;
# Ok(())
# }
```

サーバーが受け入れるには `ServerConfig::with_early_data(true)` が必要です
(既定は無効)。0-RTT のデータはハンドシェイクが完了する前に `StreamData` として
届きます。

サーバーが受理しなかった場合、0-RTT で開いたストリームと送信待ちのデータは
破棄され、`EarlyDataRejected` が届きます。ハンドシェイクは通常どおり完了するため、
アプリケーションがストリームを開き直してデータを送り直してください
(自動では再送されません)。

サーバー側のアンチリプレイ機構はアプリケーションの責任です。本クレートは
アンチリプレイの仕組みを提供しないため、対策できる場合にだけ有効にしてください。

### Stateless Reset

サーバーは未知の DCID を持つ Short header パケットに Stateless Reset を返し、
接続状態を失ったことをピアにすぐ伝えます (RFC 9000 Section 10.3)。
ピアはアイドルタイムアウトを待たずに接続を終了できます。

トークンは `ServerConfig::with_stateless_reset_secret` で設定した秘密から
導出されます。設定しない場合は `Server::bind` が乱数から生成するため、
プロセスの再起動をまたぐとピアが持つトークンと一致しなくなります。
再起動後も動くようにするには秘密を永続化して渡してください。

送信はレート制限されます (RFC 9000 Section 10.3.3)。また `Server::accept` で
引き渡した接続の CID には Stateless Reset を返しません。接続は同じプロセス内で
生きているためです。

### 統計とフロー制御の残量

`stats` が RTT、輻輳ウィンドウ、送受信量、パケット喪失などのスナップショットを
返します。送信を続けるかどうかの判断には `cwnd_left` (輻輳ウィンドウの残り)、
`max_stream_data_left` (ストリーム単位で送信できる残り)、`max_data_left`
(接続全体で送信できる残り)、`streams_bidi_left` / `streams_uni_left`
(開けるストリーム数の残り) を使えます。

### 接続設定

`ClientConfig::with_settings` と `ServerConfig::with_settings` で `Settings` を
渡すと、輻輳制御アルゴリズムや初期 RTT、keep-alive などを変更できます。

```rust
use std::time::Duration;
use shiguredo_ngtcp2_tokio::{CongestionAlgorithm, Settings};

# fn example() {
let mut settings = Settings::new(0);
settings.congestion_algorithm = CongestionAlgorithm::Bbr2;
settings.keep_alive_timeout = Some(Duration::from_secs(15));
# let _ = settings;
# }
```

`Settings::initial_ts` は接続の作成時に実際の時刻で上書きされるため、
設定する必要はありません。

### ALPN の交渉結果

`selected_alpn_protocol` で交渉された ALPN プロトコルを取得できます
(RFC 7301 Section 3)。サーバーで複数の ALPN を登録している場合に、クライアントが
どれを選んだかを判別できます。ALPN が一致しなければハンドシェイク自体が失敗するため、
接続が確立したあとに `None` になることはありません。

### QUIC バージョン

QUIC v1 (RFC 9000) と QUIC v2 (RFC 9369) に対応しています。クライアントは
`ClientConfig::with_quic_version`、サーバーは `ServerConfig::with_quic_versions`
で使用するバージョンを指定します。サーバーの既定値は v1 と v2 の両方です。

サーバーはサポートしていないバージョンの Long header パケットを受け取ると
Version Negotiation パケットを返します (RFC 9000 Section 6)。クライアントは
Version Negotiation によるバージョンの切り替えを行わないため、サーバーが
サポートしていないバージョンを指定した場合はハンドシェイクがタイムアウトします。

実際に使われているバージョンは `negotiated_version` で確認できます。

### ストリームの中断

送信側を中断する (RESET_STREAM) には `reset_stream`、受信側を中断する
(STOP_SENDING) には `stop_sending`、両方を中断するには `close_stream` を
使います。送信側を**正常に**終端する (FIN を送る) 場合は `write_stream` に
`fin = true` を渡してください。

送信側を中断しつつ、リセットの時点までに送ったデータの配信を保証する
(RESET_STREAM_AT) には `reset_stream_reliable` を使います
(draft-ietf-quic-reliable-stream-reset)。ピアが `reset_stream_at` を通知して
いる場合にだけ保証が働き、通知していないピアには RESET_STREAM が送られます。
保証が要る場合は `supports_reset_stream_at` を先に確認してください。

有効にするには、ピアに `reset_stream_at` を通知させます。

```rust
use shiguredo_ngtcp2_tokio::{ClientConfig, ServerConfig, TransportParams};

let params = TransportParams::new().with_reset_stream_at(true);
let client_config = ClientConfig::new(&[b"hq-interop"]).with_transport_params(params.clone());
let server_config = ServerConfig::new(&[b"hq-interop"]).with_transport_params(params);
```

この保証は送信中のデータが対象です。`write_stream` で送信待ちに積んだまま
送っていないデータは、`reset_stream` と同じく破棄されます。保証の対象に
含める場合は先に `flush` してください。

### 接続の終了

`Drop` は非同期処理を行えないため、正常終了時は `close` を呼んでください。
呼ばずに破棄した場合は ngtcp2 のリソースを解放するだけになります。

`close` は CONNECTION_CLOSE を 1 回送るだけで、ピアの応答を待ちません。
draining 期間の維持 (RFC 9000 Section 10.2 の SHOULD) は行いません。

## 主な型

| 型 | 役割 |
| --- | --- |
| `Client` / `ClientConnection` | クライアント側の接続 |
| `Server` / `AcceptedConnection` | サーバー側の接続 |
| `ConnectionEvent` | 接続で発生したイベント (`HandshakeCompleted` / `HandshakeConfirmed` / `EarlyDataRejected` / `StreamOpened` / `StreamData` / `StreamClosed` / `StreamReset` / `StreamStopSending` / `StreamMaxData` / `MaxStreamsBidi` / `MaxStreamsUni` / `Datagram` / `StatelessResetReceived` / `ConnectionClosed`) |
| `ClientConfig` / `ServerConfig` | クライアントとサーバーの設定 |
| `QuicVersion` | QUIC バージョン (v1 / v2) |
| `Settings` / `CongestionAlgorithm` | 輻輳制御やタイマーなどの接続設定 |
| `ConnStats` | RTT / 輻輳ウィンドウ / 送受信量の統計 |
| `SessionTicket` | 0-RTT で使うセッション情報 (セッションチケットとトランスポートパラメータ) |
| `StatelessResetSecret` | Stateless Reset トークンの導出に使う秘密 |
| `TransportParams` / `DatagramConfig` | トランスポートパラメータと DATAGRAM の設定 |
| `RemoteTransportParams` | ピアが通知したトランスポートパラメータ |

## ライセンス

Apache License 2.0
