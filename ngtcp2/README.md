# shiguredo_ngtcp2

[![crates.io](https://img.shields.io/crates/v/shiguredo_ngtcp2.svg)](https://crates.io/crates/shiguredo_ngtcp2)
[![docs.rs](https://docs.rs/shiguredo_ngtcp2/badge.svg)](https://docs.rs/shiguredo_ngtcp2)

ngtcp2 の sans-IO な QUIC 実装を提供するクレートです。

## 概要

[ngtcp2](https://github.com/ngtcp2/ngtcp2) の接続状態機械と TLS コンテキストを
Rust から扱えるようにします。ソケット I/O を持たないため、tokio 以外のランタイムや
自前のイベントループに載せられます。

非同期ランタイムとの統合が必要な場合は `shiguredo_ngtcp2_tokio` を使ってください。

## 使い方

呼び出し側が UDP ソケットを用意し、`read_pkt` と `write_pkt` を駆動します。

```rust
use std::net::SocketAddr;
use shiguredo_ngtcp2::{Connection, ConnectionId, PacketInfo, PathInfo, QuicVersion, TlsContext, TransportParams};

# fn main() -> shiguredo_ngtcp2::Result<()> {
let local: SocketAddr = "127.0.0.1:50000".parse().expect("valid address");
let remote: SocketAddr = "127.0.0.1:4433".parse().expect("valid address");

let tls_ctx = TlsContext::new_client(&[b"hq-interop"])?;
let session = tls_ctx.create_session()?;
let dcid = ConnectionId::random(16).expect("valid connection id");
let scid = ConnectionId::random(16).expect("valid connection id");

let mut conn = Connection::client_new(
    &dcid, &scid, local, remote, QuicVersion::V1, "localhost", session, &TransportParams::new(), 0,
)?;

// 受信パケットを処理する (data は UDP で受信したペイロード)
let data: &[u8] = &[];
let path = PathInfo { local, remote };
let _ = conn.read_pkt(&path, &PacketInfo::default(), data, 0);

// 送信パケットを書き出す
let mut buf = [0u8; 1350];
loop {
    let (written, _info) = conn.write_pkt(&mut buf, 0)?;
    if written == 0 {
        break;
    }
    // buf[..written] を UDP で送信する
}

// 発生したイベントを取り出す
while let Some(event) = conn.poll_event() {
    // イベントを処理する
    let _ = event;
}
# Ok(())
# }
```

## イベント

ngtcp2 のコールバックは `ConnectionEvent` として内部キューに積まれ、
`poll_event` で発生順に取り出します。`read_pkt` / `write_pkt` / `handle_expiry`
を呼んだあとは `None` になるまで取り出してください。

| イベント | 意味 |
| --- | --- |
| `HandshakeCompleted` | ハンドシェイク完了 (RFC 9001 Section 4.1.1) |
| `HandshakeConfirmed` | ハンドシェイク確認。**クライアントでのみ発生する** (RFC 9001 Section 4.1.2) |
| `EarlyDataRejected` | 0-RTT が拒否された。**クライアントでのみ発生する** (RFC 9001 Section 4.6.2) |
| `StreamOpened` | ピアが新しいストリームを開いた (RFC 9000 Section 2.1) |
| `StreamData` | ストリームデータを受信した (RFC 9000 Section 19.8) |
| `StreamClosed` | ストリームが閉じた。送受信それぞれのエラーコードを含む (RFC 9000 Section 3.3) |
| `StreamReset` | ピアが RESET_STREAM を送った (RFC 9000 Section 19.4) |
| `StreamStopSending` | ピアが STOP_SENDING を送った (RFC 9000 Section 19.5) |
| `StreamMaxData` | ピアが MAX_STREAM_DATA を送った (RFC 9000 Section 19.10) |
| `MaxStreamsBidi` / `MaxStreamsUni` | ピアが MAX_STREAMS を送った (RFC 9000 Section 19.11) |
| `Datagram` | DATAGRAM を受信した (RFC 9221) |
| `StatelessResetReceived` | Stateless Reset を受信した (RFC 9000 Section 10.3) |

接続の終了はイベントではなく `is_in_closing_period` / `is_in_draining_period` /
`get_connection_error` で観測します。sans-IO 層はソケットもタイマーも持たない
ため、終了の検出は呼び出し側の責任です。

## フロー制御

受信したストリームデータは `StreamData` イベントで届きます。処理し終えたら
`extend_max_stream_offset` を呼んでクレジットを戻してください。戻さない限り
ピアは次のデータを送れません (RFC 9000 Section 19.9)。これによりバッファが
必要以上に膨らむのを防ぎます。

ピアが開けるストリーム数の上限は自動では増えません。ピアのストリームを処理し
終えたら `extend_max_streams_bidi` / `extend_max_streams_uni` を呼んでください
(RFC 9000 Section 19.11)。

## 信頼性のあるストリームリセット

`shutdown_stream_write` は RESET_STREAM を送るため、まだ届いていないデータは
破棄されます (RFC 9000 Section 19.4)。リセットの時点までに送ったデータを
ピアに届けてから中断したい場合は `shutdown_stream_write_reliable` を使います。
ピアは RESET_STREAM_AT を受け取り、リセットより前のデータを欠落なく受け取れます
(draft-ietf-quic-reliable-stream-reset)。

保証が働くのはピアが `reset_stream_at` を通知している場合だけです。
`supports_reset_stream_at` で確認できます。通知していないピアには
RESET_STREAM が送られ、`shutdown_stream_write` と同じ挙動になります。
相手が通知しているかどうかに関わらず、こちらから使うには
`shutdown_stream_write_reliable` を呼ぶ必要があります (既定の
`shutdown_stream_write` は RESET_STREAM のままです)。

自分が RESET_STREAM_AT を受理するには、`TransportParams::with_reset_stream_at`
で通知します。ピアの値は `RemoteTransportParams::reset_stream_at` で読めます。

```rust
use shiguredo_ngtcp2::TransportParams;

# fn main() {
// RESET_STREAM_AT を受理することをピアに通知する
let params = TransportParams::new().with_reset_stream_at(true);
# let _ = params;
# }
```

## タイマー

`get_expiry` が返す時刻までに `handle_expiry` を呼ぶ必要があります。呼ばないと
再送やアイドルタイムアウトが機能しません。

## 接続設定

`Settings` で ngtcp2 の実装固有の設定を変更できます。トランスポートパラメータ
(RFC 9000 Section 18) とは別に、輻輳制御やタイマーの挙動を制御するものです。

```rust
use std::time::Duration;
use shiguredo_ngtcp2::{CongestionAlgorithm, Settings};

# fn main() {
let mut settings = Settings::new(0);
settings.congestion_algorithm = CongestionAlgorithm::Bbr2;
settings.initial_rtt = Duration::from_millis(50);
settings.max_tx_udp_payload_size = 1200;
settings.keep_alive_timeout = Some(Duration::from_secs(15));
settings.no_pmtud = true;
# let _ = settings;
# }
```

`initial_ts` には接続を作成する時刻 (ナノ秒) を設定します。ngtcp2 のすべての
タイマー計算の基準になるため、単調増加する値を渡してください。

設定できる項目は以下のとおりです。

| 項目 | 既定値 | 意味 |
| --- | --- | --- |
| `congestion_algorithm` | `Cubic` | 輻輳制御アルゴリズム (Reno / Cubic / BBRv2) |
| `initial_rtt` | 333 ms | 初期 RTT の推定値 (RFC 9002 Section 6.2.2) |
| `handshake_timeout` | `None` | ハンドシェイクのタイムアウト |
| `max_tx_udp_payload_size` | 1350 | 送信する UDP ペイロードの最大サイズ |
| `max_window` | 0 (自動) | 接続レベルの輻輳ウィンドウの上限 |
| `max_stream_window` | 0 (自動) | ストリームレベルの輻輳ウィンドウの上限 |
| `ack_threshold` | 2 | 遅延 ACK までの未 ACK パケット数 (RFC 9002 Section 7.3.1) |
| `no_tx_udp_payload_size_shaping` | false | ペイロードサイズの成形を無効にするか |
| `no_pmtud` | false | PMTUD を無効にするか |
| `keep_alive_timeout` | `None` | keep-alive のタイムアウト |

ポインタを必要とする項目 (アドレス検証トークン、互換バージョン交渉のバージョン
一覧、PMTUD のプローブサイズ、qlog / ログのコールバック) は安全に扱えないため
表現していません。

## ALPN

`TlsSession::selected_alpn_protocol` と `Connection::selected_alpn_protocol` で
交渉された ALPN プロトコルを取得できます (RFC 7301 Section 3)。ハンドシェイクが
完了するまでは `None` です。サーバーでは複数の ALPN を登録している場合に、
クライアントがどれを選んだかを判別するのに使います。

## 鍵の更新

長期間生きる接続では前方秘匿性を保つために 1-RTT 鍵の定期的な更新が推奨されます
(RFC 9001 Section 6)。`Connection::initiate_key_update` で更新を開始すると、
次の `write_pkt` で新しい鍵に切り替わり、ピアも自動的に追従します。

接続がハンドシェイク完了後の状態でない場合に呼ぶと `Error::InvalidArgument` を
返します。ngtcp2 はこの状態で呼ばれるとプロセスを異常終了させるため、
ラッパー側で先に状態を確認しています。

またハンドシェイクの確認前と、前の更新の確定から 1 PTO が経過するまでは
`NGTCP2_ERR_INVALID_STATE` で拒否されます。いずれも一時的な状態なので、
時間をおいて再試行してください。

## 0-RTT (early data)

前回の接続で得たセッション情報を使うと、ハンドシェイクの完了を待たずにデータを
送れます (RFC 9001 Section 4.6)。クライアントは
`Connection::take_session_ticket` で `SessionTicket` (TLS セッションチケットと
0-RTT 用のトランスポートパラメータの組) を取り出し、
`Connection::client_new_with_0rtt` に渡します。

```rust
use std::net::SocketAddr;
use shiguredo_ngtcp2::{
    Connection, ConnectionId, QuicVersion, SessionTicket, Settings, TlsContext, TransportParams,
};

let tls_ctx = TlsContext::new_client(&[b"hq-interop"])?;
let session = tls_ctx.create_session()?;
let dcid = ConnectionId::random(16).expect("valid connection id");
let scid = ConnectionId::random(16).expect("valid connection id");
let settings = Settings::new(now);

// 前回の接続で take_session_ticket() が返した値を保存しておき、
// 次回の起動時に SessionTicket::new で復元する
let ticket = SessionTicket::new(saved_session, saved_transport_params);

let mut conn = Connection::client_new_with_0rtt(
    &dcid,
    &scid,
    local,
    remote,
    QuicVersion::V1,
    "localhost",
    session,
    &TransportParams::new(),
    &settings,
    &ticket,
)?;

// ハンドシェイクの完了前に 0-RTT のデータを送れる
if conn.is_in_early_data() {
    let stream_id = conn.open_bidi_stream()?;
    let mut buf = [0u8; 1350];
    let _ = conn.write_stream(&mut buf, stream_id, b"early data", true, now)?;
}
```

- `is_in_early_data` で 0-RTT を送受信している最中かを確認できる
- `is_early_data_accepted` と `EarlyDataRejected` で受理されたかを確認できる
- セッションが 0-RTT に対応していない場合 (サーバーが受け入れない設定の場合) は
  0-RTT を送らないため、`is_in_early_data` は false のままになる
- サーバーは `TlsContext::set_accept_early_data` を有効にした場合にだけ 0-RTT を
  受け入れる。0-RTT で送れるデータ量を決めるトランスポートパラメータは
  `Connection::server_new` がチケットに結び付ける

0-RTT のデータはリプレイ攻撃に対して脆弱であり
(RFC 9000 Section 7.4.1 / RFC 9001 Section 9.2)、
アンチリプレイの仕組みはアプリケーションの責任です。また、サーバーが受理しなかった
場合、ngtcp2 は 0-RTT で開いたストリームと送信待ちのデータを破棄します。
アプリケーションがストリームを開き直してデータを送り直してください。

## Stateless Reset

接続状態を失ったエンドポイントは、未知の DCID を持つ Short header パケットに
対して Stateless Reset を返し、ピアをアイドルタイムアウトまで待たせずに
終了させられます (RFC 9000 Section 10.3)。

Stateless Reset トークンはコネクション ID ごとに決まっているため、
`StatelessResetSecret` から導出します。秘密だけを持っていれば接続状態を
失った後でもピアが保持しているトークンを再現できます。

```rust
use shiguredo_ngtcp2::{ConnectionId, StatelessResetSecret, write_stateless_reset};

# fn main() -> shiguredo_ngtcp2::Result<()> {
let secret = StatelessResetSecret::generate().expect("failed to generate secret");
let cid = ConnectionId::random(16).expect("valid connection id");
let token = secret.token(&cid).expect("failed to derive token");

// NEW_CONNECTION_ID で配布するトークンとして使う
// (Settings::stateless_reset_secret に秘密を渡すと自動で導出される)

let mut buf = [0u8; 1200];
// 引き金になったパケットの長さを渡すと、それより長くならないように書き出す
let written = write_stateless_reset(&mut buf, &token, 1200)?;
# let _ = written;
# Ok(())
# }
```

サーバーは最初の SCID に対応するトークンを
`TransportParams::with_stateless_reset_token` で配布します。これをしないと
ピアは最初の DCID に対する Stateless Reset を受理できません
(RFC 9000 Section 18.2)。

秘密は `Debug` 出力に表示されません。トークンも同様です。

## 統計

`Connection::stats` が RTT、輻輳ウィンドウ、送受信量、パケット喪失などの
スナップショット (`ConnStats`) を返します。診断やメトリクスの収集に使えます。

あわせて以下の残量を取得できます。

| API | 意味 |
| --- | --- |
| `get_cwnd_left` | 輻輳ウィンドウの残り (RFC 9002 Section 7) |
| `get_max_data_left` | 接続全体で送信できる残り (RFC 9000 Section 4.1) |
| `get_max_stream_data_left` | ストリーム単位で送信できる残り |
| `get_streams_bidi_left` / `get_streams_uni_left` | 開けるストリーム数の残り (RFC 9000 Section 4.2) |

## QUIC バージョン

QUIC v1 (RFC 9000) と QUIC v2 (RFC 9369) に対応しています。`client_new` と
`server_new` に `QuicVersion` を渡して使用するバージョンを指定し、
`negotiated_version` で実際に使われているバージョンを確認できます。

Long header のパケット種別を表すビットの値はバージョンごとに異なるため、
先頭バイトを直接見てはいけません。`decode_packet_version` が返す
`PacketVersion::is_initial` で判定してください。

サーバーはサポートしていないバージョンの Long header パケットを受け取ったら
`write_version_negotiation` で Version Negotiation パケットを返します
(RFC 9000 Section 6)。

## トランスポートパラメータ

ローカルの設定は `TransportParams`、ピアが通知した値は
`Connection::remote_transport_params` が返す `RemoteTransportParams` で扱います。
ピアのパラメータはハンドシェイクが完了するまで `None` です。

RFC 9000 Section 18.2 の `initial_max_stream_data_bidi_local` /
`initial_max_stream_data_bidi_remote` の local / remote は **パラメータを送った側**
から見た向きを指します。そのためピアのパラメータでは
`initial_max_stream_data_bidi_remote` が「ローカルが開いた双方向ストリーム」に
適用される上限になります。

DATAGRAM (RFC 9221) の送受信上限は `TransportParams::with_datagram` でピアに通知し、
実際の送信バッファの上限は呼び出し側が管理します。

## 主な型

| 型 | 役割 |
| --- | --- |
| `Connection` | QUIC 接続の状態機械 |
| `ConnectionEvent` | コールバック由来のイベント |
| `QuicVersion` | QUIC バージョン (v1 / v2) |
| `PacketVersion` | Long header から取り出したバージョンと CID |
| `LongHeaderType` | Long header パケットの種別 (Initial / 0-RTT / Handshake / Retry) |
| `TlsContext` / `TlsSession` | aws-lc を使った TLS の設定と接続ごとのセッション |
| `SessionTicket` | 0-RTT で使うセッション情報 (セッションチケットとトランスポートパラメータ) |
| `TransportParams` | トランスポートパラメータのビルダー (RFC 9000 Section 18) |
| `Settings` | ngtcp2 の接続設定 (輻輳制御、タイマー、keep-alive など) |
| `ConnStats` | RTT / 輻輳ウィンドウ / 送受信量の統計 |
| `StatelessResetSecret` / `StatelessResetToken` | Stateless Reset トークンの導出 (RFC 9000 Section 10.3) |
| `CongestionAlgorithm` | 輻輳制御アルゴリズム |
| `RemoteTransportParams` | ピアが通知したトランスポートパラメータ |
| `ConnectionId` | コネクション ID (RFC 9000 Section 5.1) |
| `PathInfo` | パケットを受信したパス (ローカルとリモートのアドレスの組) |
| `PacketInfo` | ECN マーキングなどのパケット情報 |
| `varint` | 可変長整数のエンコードとデコード (RFC 9000 Section 16) |

## 設計上の注意

- ngtcp2 の生の FFI 型は公開 API に露出しません。`shiguredo_ngtcp2_sys` への
  直接依存は不要です
- `Connection` は `Send` / `Sync` ですが、1 つの接続を複数スレッドから同時に
  操作しないでください。ngtcp2 のコールバックは同期呼び出しです

## ライセンス

Apache License 2.0
