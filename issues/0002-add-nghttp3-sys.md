# nghttp3 の FFI バインディング (shiguredo_nghttp3_sys) を追加する

- Created: 2026-09-18
- Completed: {YYYY-MM-DD}
- Branch: feature/add-nghttp3-sys
- Polished: {YYYY-MM-DD}

## 目的

nghttp3 の C ライブラリを Rust から扱えるようにする。http3-rs の相互運用テストで、shiguredo_http3 とは独立した HTTP/3 実装 (nghttp3) をピアとして使えるようにするため。

## 現状

- このリポジトリは HTTP/3 非対応を明記しており (`CODEBASE.md` の「対応しない機能」)、nghttp3 のバインディングは存在しない
- http3-rs は以前 `crates/nghttp3-sys` を持っていたが、ngtcp2 系の crates.io 移行に伴い削除された
- nghttp3 の WebTransport 対応は upstream の `webtransport` ブランチで開発中で、最新リリース (v1.18.0、2026-07-26) には含まれていない

## 設計方針

- `ngtcp2-sys` と同じ構成で nghttp3 をビルドする FFI クレート (`nghttp3-sys`) を追加する
- ビルドは `ngtcp2-sys/build.rs` の `[package.metadata.external-dependencies]` と prebuilt / `source-build` の仕組みを流用する。prebuilt が無いバージョンはソースからビルドする
- ソースは upstream の `webtransport` ブランチを追従し、タグがリリースされたら切り替える
- `wrapper.h` で `nghttp3/nghttp3.h` などのヘッダーを取り込み、`bindings.rs` を生成して同梱する
- 対応する場合は `CODEBASE.md` の「HTTP/3 には対応しない」の方針を見直す
- ACK 済みストリームデータの公開 (別 issue) が無いと `nghttp3_conn_add_ack_offset` を正しく呼べない

## 完了条件

- `shiguredo_nghttp3_sys` が nghttp3 をビルドしてリンクできる (macOS / Linux)
- 生成済みバインディングで nghttp3 の主要 API を呼べる
- `cargo test --all` と `cargo fmt --all -- --check` と `cargo clippy --all-targets --all-features -- -D warnings` が通る

## 解決方法

### 関連ファイル

- `ngtcp2-sys/build.rs` (流用元の外部依存ビルド)
- `ngtcp2-sys/Cargo.toml` (`[package.metadata.external-dependencies]` の書き方)
- `CODEBASE.md` (HTTP/3 非対応の方針)
- 一次資料: <https://github.com/ngtcp2/nghttp3>
