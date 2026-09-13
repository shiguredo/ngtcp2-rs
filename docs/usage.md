# 使い方

## 依存の追加

`shiguredo_ngtcp2_tokio` のみを依存に追加すれば使えます。

```toml
[dependencies]
shiguredo_ngtcp2_tokio = "2026.1"
```

Sans I/O 層だけを直接使う場合は `shiguredo_ngtcp2` を追加してください。

## クライアント

```rust
use std::net::SocketAddr;
use shiguredo_ngtcp2_tokio::{Client, ClientConfig, ConnectionEvent};

let remote: SocketAddr = "127.0.0.1:4433".parse().expect("valid address");
let config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
let local: SocketAddr = "127.0.0.1:0".parse().expect("valid address");
let mut conn = Client::connect_with_config(remote, local, "localhost", &config).await?;

// ストリームを開いてデータを送る。write_stream は送信待ちに積むだけで、
// 実際の送信は flush が行う
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
```

証明書検証を有効にしたまま自己署名証明書を使う場合は、`with_ca_cert_pem` でトラストストアに CA を追加します。

```rust
use shiguredo_ngtcp2_tokio::ClientConfig;

let config = ClientConfig::new(&[b"hq-interop"])
    .with_verify_peer(true)
    .with_ca_cert_pem(cert_pem);
```

0-RTT (early data) を使う場合は、前回の接続でセッション情報を保存し、次の接続に渡します。ハンドシェイクの完了前にデータを送れるため、往復を 1 回減らせます。

```rust
use shiguredo_ngtcp2_tokio::{Client, ClientConfig};

let config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);

// 1 回目の接続。セッションチケットはハンドシェイク完了後に届く
let mut conn = Client::connect_with_config(remote, local, "localhost", &config).await?;
let ticket = loop {
    if let Some(ticket) = conn.take_session_ticket()? {
        break ticket;
    }
    conn.recv_event().await?;
};
// アプリケーションが保存し、次回の起動で SessionTicket::new で復元する

// 2 回目の接続。0-RTT を送れる状態で戻る
let mut conn =
    Client::connect_with_early_data(remote, local, "localhost", &config, &ticket).await?;
if conn.is_in_early_data() {
    let stream_id = conn.open_bidi_stream()?;
    conn.write_stream(stream_id, b"early data", true)?;
    conn.flush().await?;
}
```

サーバーが受け入れるには `ServerConfig::with_early_data(true)` が必要です (既定は無効)。0-RTT のセキュリティ上の注意は [0-RTT (early data)](#0-rtt-early-data) を参照してください。

## サーバー

```rust
use shiguredo_ngtcp2_tokio::{ConnectionEvent, Server, ServerConfig};

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
            match event {
                ConnectionEvent::StreamData { stream_id, data, .. } => {
                    let _ = conn.extend_max_stream_offset(stream_id, data.len() as u64);
                }
                ConnectionEvent::ConnectionClosed { .. } => break,
                _ => {}
            }
        }
    });
}
```

`accept` は接続を返したあとも `Server` を生かし続ける必要があります。`Server` は UDP ソケットを接続ハンドルと `Arc` で共有しているため、`Server` を破棄しても既存の接続は動き続けますが、新しい接続は受け付けられません。

## 信頼性のあるストリームリセット

`reset_stream` は RESET_STREAM を送るため、まだ届いていないデータは破棄されます。リセットの時点までに送ったデータをピアに届けてから中断したい場合は `reset_stream_reliable` を使います (draft-ietf-quic-reliable-stream-reset)。ピアは RESET_STREAM_AT を受け取り、リセットより前のデータを欠落なく受け取れます。

保証が働くのはピアが `reset_stream_at` を通知している場合だけです。双方が通知するように設定します。

```rust
use shiguredo_ngtcp2_tokio::{ClientConfig, ServerConfig, TransportParams};

let params = TransportParams::new().with_reset_stream_at(true);
let client_config = ClientConfig::new(&[b"hq-interop"]).with_transport_params(params.clone());
let server_config = ServerConfig::new(&[b"hq-interop"]).with_transport_params(params);
```

送信側は `reset_stream_reliable` を呼びます。ピアが受理するかどうかは `supports_reset_stream_at` で事前に確認できます。

```rust
use shiguredo_ngtcp2_tokio::ClientConnection;

# fn example(conn: &mut ClientConnection, stream_id: shiguredo_ngtcp2_tokio::StreamId)
#     -> shiguredo_ngtcp2::Result<()> {
if conn.supports_reset_stream_at() {
    conn.reset_stream_reliable(stream_id, 42)?;
} else {
    // 通知していないピアには RESET_STREAM が送られ、保証は得られない
    conn.reset_stream(stream_id, 42)?;
}
# Ok(())
# }
```

保証の対象は送信中のデータです。`write_stream` で送信待ちに積んだまま送っていないデータは `reset_stream` と同じく破棄されるため、保証の対象に含める場合は先に `flush` を呼んでください。

## Sans I/O 層を直接使う

呼び出し側が UDP ソケットとタイマーを用意し、`read_pkt` と `write_pkt` を駆動します。サーバー側も同じ駆動方法です。`shiguredo_ngtcp2_tokio` が提供する `Client` / `Server` は、この手順を tokio の UDP ソケットで包んだものです。

### クライアント

```rust
use std::net::SocketAddr;
use shiguredo_ngtcp2::{
    Connection, ConnectionEvent, ConnectionId, PacketInfo, PathInfo, QuicVersion, Settings,
    TlsContext, TransportParams,
};

let local: SocketAddr = "127.0.0.1:50000".parse().expect("valid address");
let remote: SocketAddr = "127.0.0.1:4433".parse().expect("valid address");

let tls_ctx = TlsContext::new_client(&[b"hq-interop"])?;
let session = tls_ctx.create_session()?;
let dcid = ConnectionId::random(16).expect("valid connection id");
let scid = ConnectionId::random(16).expect("valid connection id");

// 時刻はナノ秒単位の単調増加する値ならよく、呼び出し側が用意した時計の
// 経過時間を使う (例: プロセス起動からの経過時間)
let now: u64 = elapsed_nanos();

let settings = Settings::new(now);
let mut conn = Connection::client_new(
    &dcid,
    &scid,
    local,
    remote,
    QuicVersion::V1,
    "localhost",
    session,
    &TransportParams::new(),
    &settings,
)?;

// 受信パケットを処理する (data は UDP で受信したペイロード)
let data: &[u8] = &[];
let path = PathInfo { local, remote };
let _ = conn.read_pkt(&path, &PacketInfo::default(), data, now);

// 送信パケットを書き出す
//
// 3 番目の戻り値は送信先の経路。マイグレーション中は経路検証のパケットだけ
// 別のアドレスへ送るため、パケットごとに従うこと (RFC 9000 Section 9.3)
let mut buf = [0u8; 1350];
loop {
    let (written, _info, path) = conn.write_pkt(&mut buf, now)?;
    if written == 0 {
        break;
    }
    let path = path.expect("パケットを書き出した場合は経路が返る");
    // buf[..written] を path.remote へ UDP で送信する
    let _ = path;
}

// get_expiry が返す時刻までに handle_expiry を呼ばないと、
// 再送やアイドルタイムアウトが機能しない
if conn.get_expiry() <= now {
    let _ = conn.handle_expiry(now);
}

// 発生したイベントを取り出す
while let Some(event) = conn.poll_event() {
    let _ = event;
}

// tls_ctx は conn が保持する SSL から参照されるため、
// 接続が生きている間は破棄してはいけない
```

### サーバー

サーバーは接続ごとに `Connection::server_new` を作ります。どのパケットから接続を作るかは `accept_initial` で判定します。受理できないパケット (Initial 以外、未対応のバージョン、1200 バイト未満など) では `None` が返ります。

```rust
use std::net::SocketAddr;
use std::path::Path;
use shiguredo_ngtcp2::{
    Connection, ConnectionId, QuicVersion, Settings, TlsContext, TransportParams, accept_initial,
};

# fn example(
#     data: &[u8],
#     local: SocketAddr,
#     remote: SocketAddr,
#     cert_path: &Path,
#     key_path: &Path,
#     now: u64,
# ) -> shiguredo_ngtcp2::Result<()> {
// クライアントの最初の Initial から接続に必要な情報を取り出す
let accepted = accept_initial(data).expect("受理できる Initial");

let tls_ctx = TlsContext::new_server(cert_path, key_path, &[b"hq-interop"])?;
let session = tls_ctx.create_session()?;
let scid = ConnectionId::random(16).expect("valid connection id");

// クライアントの最初の Initial の DCID を original_dcid として通知する
// (RFC 9000 Section 7.3)。設定しないとハンドシェイクが失敗する
let params = TransportParams::new().with_original_dcid(&accepted.dcid);

let mut conn = Connection::server_new(
    &accepted.scid,
    &scid,
    local,
    remote,
    QuicVersion::V1,
    session,
    &params,
    &Settings::new(now),
)?;

// 以降はクライアントと同じく read_pkt / write_pkt / handle_expiry を駆動する
let path = shiguredo_ngtcp2::PathInfo { local, remote };
let _ = conn.read_pkt(&path, &shiguredo_ngtcp2::PacketInfo::default(), data, now);
# Ok(())
# }
```

- 最初の Initial の DCID は `accepted.dcid`、クライアントの SCID は `accepted.scid` です
- `accepted.token` にはクライアントが載せたトークンが入ります。Retry や NEW_TOKEN でアドレスを検証する場合は `shiguredo_ngtcp2_tokio::Server` の実装か、`verify_retry_token` / `verify_new_token` を参照してください
- 未対応のバージョンの Long header パケットには `write_version_negotiation` で応答します (RFC 9000 Section 6)
