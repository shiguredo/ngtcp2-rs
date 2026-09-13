# ngtcp2-rs

[![crates.io](https://img.shields.io/crates/v/shiguredo_ngtcp2_tokio.svg)](https://crates.io/crates/shiguredo_ngtcp2_tokio)
[![docs.rs](https://docs.rs/shiguredo_ngtcp2_tokio/badge.svg)](https://docs.rs/shiguredo_ngtcp2_tokio)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub Actions](https://github.com/shiguredo/ngtcp2-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/shiguredo/ngtcp2-rs/actions/workflows/ci.yml)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.gg/shiguredo)

## About Shiguredo's open source software

We will not respond to PRs or issues that have not been discussed on Discord. Also, Discord is only available in Japanese.

Please read <https://github.com/shiguredo/oss> before use.

## 時雨堂のオープンソースソフトウェアについて

利用前に <https://github.com/shiguredo/oss> をお読みください。

## 概要

[ngtcp2](https://github.com/ngtcp2/ngtcp2) の Rust FFI バインディングです。ngtcp2 の C 実装をビルドしてリンクし、その QUIC トランスポート層を Rust から扱える API を提供します。

## 特徴

- Sans I/O
  - <https://sans-io.readthedocs.io/index.html>
  - プロトコルの状態機械はソケットもタイマーも持たず、パケットの読み書きと期限の通知だけを行う
  - tokio 以外のランタイムにも載せられる
  - 接続状態機械だけを決定的にテストできる
- ngtcp2 の C 実装を FFI で呼び出す
- [Reliable Stream Resets](https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/) に対応する
  - ストリームの中断で、リセットの時点までに送ったデータの配信を保証できる (RESET_STREAM_AT)
- 0-RTT (early data) に対応する (RFC 9001 Section 4.6)
- TLS と暗号に [aws-lc](https://github.com/aws/aws-lc) を使用する

## クレート構成

ngtcp2 の C API をそのまま Rust から呼べる FFI 層、その上に載る Sans I/O な状態機械、tokio 向けの非同期 I/O という 3 層構成です。上位のクレートは下位のクレートに依存するため、`shiguredo_ngtcp2_tokio` だけを追加すれば 3 クレートすべてが入ります。

| クレート | 層 | 役割 | 依存 |
| --- | --- | --- | --- |
| `shiguredo_ngtcp2_sys` | FFI | ngtcp2 の C API をそのまま Rust から呼べる低レベルバインディング | ngtcp2 / aws-lc |
| `shiguredo_ngtcp2` | 状態機械 | ngtcp2 の接続状態機械と TLS コンテキストを Rust の型でラップする。ソケットもタイマーも持たない (Sans I/O) | `shiguredo_ngtcp2_sys` |
| `shiguredo_ngtcp2_tokio` | 非同期 I/O | tokio の UDP ソケットとイベントループを組み合わせ、非同期クライアント / サーバーとして使えるようにする | `shiguredo_ngtcp2` / tokio |

```
shiguredo_ngtcp2_tokio  →  shiguredo_ngtcp2  →  shiguredo_ngtcp2_sys  →  ngtcp2 (C)
```

`shiguredo_ngtcp2_sys` は ngtcp2 の `ngtcp2_conn` や `ngtcp2_transport_params` といった生の C の型と関数を扱う層です。生のポインタを自分で管理する必要があり、使う場合は ngtcp2 の C API の知識が要ります。

`shiguredo_ngtcp2` はこの生の型を Rust の型でラップし、`pub(crate)` で内部に閉じ込めます。そのため `shiguredo_ngtcp2` 以降を使う場合に `shiguredo_ngtcp2_sys` への直接依存は不要です。tokio にも依存しないため、tokio 以外のランタイムに載せる場合や、接続状態機械だけを決定的にテストする場合にも使えます。

## 使い方

```toml
[dependencies]
shiguredo_ngtcp2_tokio = "2026.1"
```

クライアント:

```rust
use std::net::SocketAddr;
use shiguredo_ngtcp2_tokio::{Client, ClientConfig};

let remote: SocketAddr = "127.0.0.1:4433".parse().expect("valid address");
let local: SocketAddr = "127.0.0.1:0".parse().expect("valid address");
let config = ClientConfig::new(&[b"hq-interop"]).with_verify_peer(false);
let mut conn = Client::connect_with_config(remote, local, "localhost", &config).await?;

let stream_id = conn.open_bidi_stream()?;
conn.write_stream(stream_id, b"hello", true)?;
conn.flush().await?;
```

サーバー:

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

Sans I/O 層を直接使う場合や、証明書検証の設定は [使い方](docs/usage.md) を参照してください。

## QUIC

このライブラリが対応している主な仕組みです。詳細は [QUIC](docs/quic.md) を参照してください。

- QUIC v1 (RFC 9000) と QUIC v2 (RFC 9369)、Version Negotiation
- TLS 1.3 によるハンドシェイク (RFC 9001)、ALPN、証明書検証
- Retry によるアドレス検証 (RFC 9000 Section 8.1.2)
- 接続マイグレーション (RFC 9000 Section 9)
- ECN (RFC 9000 Section 13.4)
- 0-RTT (early data, RFC 9001 Section 4.6)
- ストリーム、フロー制御、輻輳制御 (Reno / CUBIC / BBRv2)、キー更新
- 信頼性のあるストリームリセット (draft-ietf-quic-reliable-stream-reset)
- DATAGRAM (RFC 9221)
- Stateless Reset、アイドルタイムアウト、CONNECTION_CLOSE

未対応は [QUIC](docs/quic.md#対応しない機能) を参照してください。

## ドキュメント

- [使い方](docs/usage.md)
- [QUIC](docs/quic.md)
- [ビルド](docs/build.md)
- [開発](docs/development.md)
- [相互運用テスト](docs/interop.md)

## ngtcp2 ライセンス

<https://github.com/ngtcp2/ngtcp2/blob/main/COPYING>

```text
The MIT License

Copyright (c) 2016 ngtcp2 contributors

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## ライセンス

Apache License 2.0

```text
Copyright 2026 Shiguredo Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
