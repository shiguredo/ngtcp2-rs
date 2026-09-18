# ACK 済みストリームデータをイベントとして公開する

- Created: 2026-09-18
- Completed: {YYYY-MM-DD}
- Branch: feature/add-acked-stream-data-events
- Polished: {YYYY-MM-DD}

## 目的

送信したストリームデータがピアに ACK されたことをアプリケーションから観測できるようにする。nghttp3 などの Sans I/O な HTTP/3 実装を駆動するには、どのストリームデータが ACK されたかを `nghttp3_conn_add_ack_offset` に渡す必要がある。現状は ACK 情報が内部の送信バッファ解放にしか使われておらず、外部から観測できない。

## 現状

- `ngtcp2/src/conn.rs` の `acked_stream_data_offset_callback` が `ConnectionUserData::acked_stream_data` を呼び、`InFlightStreamData::ack_until` で ACK 済みの送信データを解放している
- この ACK 情報は `ConnectionUserData` の内部で完結しており、`ConnectionEvent` (`ngtcp2/src/event.rs`) として公開されていない
- `tokio-ngtcp2` の `ConnectionEvent` にも対応する variant が無い

## 設計方針

- `ngtcp2/src/event.rs` の `ConnectionEvent` に ACK 済みストリームデータを表す variant (例: `StreamDataAcked { stream_id, offset, datalen }`) を追加する
- `tokio-ngtcp2` の `ConnectionEvent` にも同じ情報を追加する (既存の `From` 実装に追加する)
- ngtcp2 の `acked_stream_data_offset` の契約 (アプリケーションが渡したバッファを解放してよいタイミングの通知) を doc コメントに明記する
- ACK は部分 ACK や遅延 ACK で複数回届くため、offset と datalen をそのまま通知する
- 既存の送信バッファ解放処理は残し、イベントは追加の通知として扱う

## 完了条件

- ACK の受信で `StreamDataAcked` イベントが発生し、stream_id / offset / datalen が正しい
- 部分 ACK と複数ストリームで正しく動作する
- `tokio-ngtcp2` からも同じイベントが取得できる
- テストが追加される (sans-IO 層と tokio 層の両方)
- `cargo test --all` と `cargo fmt --all -- --check` と `cargo clippy --all-targets --all-features -- -D warnings` が通る

## 解決方法

### 関連ファイル

- `ngtcp2/src/conn.rs` (`acked_stream_data_offset_callback` / `ConnectionUserData::acked_stream_data` / `InFlightStreamData::ack_until`)
- `ngtcp2/src/event.rs` (`ConnectionEvent`)
- `tokio-ngtcp2/src/lib.rs` (再公開する `ConnectionEvent`)
