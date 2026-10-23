# 輻輳制限中に積んだ 0 長 FIN を失わずに送信する

- Created: 2026-10-23
- Completed: {YYYY-MM-DD}
- Branch: feature/fix-fin-only-cwnd-exhaustion
- Polished: {YYYY-MM-DD}

## 目的

データ長 0 で FIN だけを送る `write_stream` の送信待ちが、ngtcp2 がパケットを書けない状況 (輻輳制限など) で「送信済み」と誤判定されて破棄され、ピアに FIN が届かない不具合を修正する。

FIN が届かないとピアはストリームの終端を観測できず、EOF を待つアプリケーションがハングする。下流プロジェクトの 100 ストリーム echo テストで 100 本中 1 本の FIN が欠落し、サーバー / クライアント双方の qlog で確認された。下流のテストは FIN を最終データと同時に送る形に変更して回避しており、その理由もコメントで残されている。

## 再現手順

下流プロジェクトで観測された症状は、以下の手順で実 UDP の e2e テストとして決定的に再現できる。2026.1.0-canary.2 の develop で確認した。

1. 両側の `TransportParams` で `initial_max_stream_data_bidi_local` / `initial_max_stream_data_bidi_remote` / `initial_max_data` を十分大きくし (例: 4 MiB)、フロー制御が制限にならないようにする
2. クライアントで 256 KiB のデータを `fin = false` で `write_stream` し、`flush` だけを行う (ACK を処理する `recv_event` を呼ばない)。直後に `cwnd_left()` が 0 になることを確認する (実測: cwnd 14400、bytes_in_flight 14473)
3. 輻輳ウィンドウが枯渇している間に、別のストリームへ `write_stream(stream_id, b"", true)` を積んで `flush` する
4. クライアントとサーバーを交互に `recv_event` で駆動する
5. 現行コードではデータ 262144 バイトはすべてサーバーに届くが、対象ストリームの FIN は 5 秒待っても届かない。
   `data_written == Some(data_len)` で FIN の受理を判定するよう修正すると、約 0.6 秒で FIN が届く
   (issue 作成時に、修正前は 4/4 回失敗、修正後は 6/6 回成功することを確認済み)

## 現状

- `tokio-ngtcp2/src/streams.rs` の `write_packets` は、`write_stream_with_flags` が返す
  `data_written` を `unwrap_or(0)` で 0 に丸めた `consumed` を使い、`PendingStreams` の送信待ち
  エントリの FIN を `fin && consumed >= data_len` で送信済みにする。送信済みになったエントリは
  `prune` で送信待ちから削除される
- データ長 0 の FIN では `data_len == 0` のため `consumed >= data_len` が常に真になる。`data_written == None` は ngtcp2 が STREAM フレームを書かなかったことを意味するが、これを `Some(0)` (0 バイトの STREAM フレームを書いた) と区別していない
- ngtcp2 の `ngtcp2_conn_writev_stream` の契約は `ngtcp2-sys/src/bindings.rs` の doc に明記されている
  - パケットに STREAM フレームが含まれない場合、`*pdatalen` は -1
  - 0 長 STREAM フレームのシリアライズに成功した場合のみ、`*pdatalen` は 0
  - バッファ不足や輻輳制限でフレームを書けない場合、戻り値は 0
- `ngtcp2/src/conn.rs` の `write_stream_with_flags` は、`datalen` が負のときに `data_written` を `None` にしており、C の契約を正しく Rust の型に写している。誤りは `write_packets` の判定側にある (ngtcp2 C 側は契約どおり)
- `wrote_any` も同じ条件で真になるため、進捗がないのにループを 1 回余分に回す
- `data_written == None` になる経路は輻輳制限だけではない。pacing 制限、サーバーの amplification 制限、再送キューの占有、ハンドシェイクとのパケット連結などでも起こりうる。そのため発生は負荷とタイミングに依存し、下流の 100 ストリーム echo では 1/100 だった
- 既存の `tokio-ngtcp2/tests/e2e/stream.rs` の `test_zero_length_data_with_fin` は輻輳ウィンドウに空きがある状態で FIN を送るため `None` 経路を通らず、この不具合を検出できない
- `write_stream` は常に `Ok(data.len())` を返すため、アプリケーションは FIN が送信待ちに残ったか破棄されたかを検知できない。
  `ClientConnection::write_stream` / `AcceptedConnection::write_stream` の doc コメントにある
  「送りきれなかったデータは内部に保持し、次の flush / recv_event で再送を試みる」という約束も、0 長 FIN については破られている
- 同リポジトリの `interop/src/lib.rs` の `echo_back` は、受け取ったデータが空の場合に `write_stream(stream_id, b"", true)` を呼ぶため、この経路を踏みうる
- 不具合はインポート時から存在する

## 設計方針

- `write_packets` の `Ok` 分岐で、FIN の受理を `data_written == Some(data_len)` で判定する。ngtcp2 は FIN フラグを渡しても、与えた全データが STREAM フレームに載ったときだけ FIN を立てる。そのとき `*pdatalen == datalen` になるため、この条件は FIN の受理と同値になる
- データ長 0 のときは `Some(0)` (0 長 STREAM フレーム + FIN を書いた) だけを受理とし、`None` (書けなかった) は送信待ちに残して次の `flush` / `recv_event` で再試行する
- `wrote_any` の判定も同じ条件に揃える
- データの drain は現状どおり `data_written` の値を使う (`None` は 0 バイト)
- 回帰テストを `tokio-ngtcp2/tests/e2e/stream.rs` に追加する。実 UDP の e2e で、輻輳ウィンドウを使い切った直後に `write_stream(stream_id, b"", true)` を積み、両側を駆動してサーバーが FIN を受信できることを検証する。修正前は失敗し、修正後は成功することを確認する
- `write_stream_with_flags` の `data_written` の意味 (`None` は未受理、`Some(0)` は 0 長 STREAM フレームの受理) を doc コメントに明記し、同じ混同を防ぐ
- 公開 API の変更は不要

## 完了条件

- 輻輳ウィンドウ枯渇中に積んだ 0 長 FIN がピアに届く (追加する回帰テストが修正前は失敗し、修正後は成功する)
- 0 長 FIN を複数回 flush しても、FIN の欠落や二重送信がない
- 部分送信 + FIN、`NGTCP2_WRITE_STREAM_FLAG_MORE` を使う経路で既存の挙動が変わらない
- `cargo test --workspace --tests --features source-build`、`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets --features source-build -- -D warnings` が成功する
- 下流プロジェクトの 100 ストリーム echo テストが、FIN を最終データと同時に送る回避策を外した状態でも成功する (下流側で確認)
