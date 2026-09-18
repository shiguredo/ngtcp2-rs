# nghttp3 の Sans I/O HTTP/3 ラッパー (shiguredo_nghttp3) を追加する

- Created: 2026-09-18
- Completed: {YYYY-MM-DD}
- Branch: feature/add-nghttp3-h3-wrapper
- Polished: {YYYY-MM-DD}

## 目的

nghttp3 を Rust の型でラップし、リクエスト / レスポンス / QPACK / WebTransport を扱える Sans I/O な HTTP/3 実装を提供する。http3-rs の相互運用テストで、shiguredo_http3 とは独立した HTTP/3 実装として使う。

## 現状

- http3-rs の削除前の `crates/ngtcp2-rs/src/h3.rs` が同等のラッパー (`Http3Connection` / `Http3Event`) を提供していた
- 同ファイルは ngtcp2 系の crates.io 移行に伴い削除され、現行のリポジトリには存在しない
- `shiguredo_nghttp3_sys` (別 issue) が未整備
- ACK 済みストリームデータの公開 (別 issue) が無いと `nghttp3_conn_add_ack_offset` に ACK を渡せない

## 設計方針

- 削除前の `crates/ngtcp2-rs/src/h3.rs` の API (クライアント / サーバー接続の生成、ストリーム読み書き、ヘッダー送受信、QPACK、WebTransport) を移植する
- QUIC 層とは分離し、ストリーム ID とデータの受け渡しだけで接続する Sans I/O の API にする
- ACK 済みストリームデータのイベントを `nghttp3_conn_add_ack_offset` に接続する
- nghttp3 のエラーコードを保持した Rust のエラー型に変換する

## 完了条件

- nghttp3 を使った HTTP/3 リクエスト / レスポンスが Rust の API で送受信できる
- QPACK のダイナミックテーブル参照と WebTransport のリクエスト / レスポンスが動作する
- テストが追加される
- `cargo test --all` と `cargo fmt --all -- --check` と `cargo clippy --all-targets --all-features -- -D warnings` が通る

## 解決方法

### 関連ファイル

- http3-rs の `crates/ngtcp2-rs/src/h3.rs` (削除前の実装。同リポジトリの git 履歴を参照)
- `nghttp3-sys` (別 issue)
- 一次資料: <https://github.com/ngtcp2/nghttp3>
