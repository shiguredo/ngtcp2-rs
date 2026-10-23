# 送信中のデータのバッファを ACK まで移動・解放しないようにする

- Created: 2026-10-23
- Completed: 2026-10-24
- Branch: feature/fix-in-flight-buffer-pointer-stability
- Polished: {YYYY-MM-DD}

## 目的

ngtcp2 に渡したストリームデータのバッファが、ACK されるまで同一領域に留まるという ngtcp2 の契約を満たすようにする。
現状は未 ACK のバイト列が `Vec` の詰め直しや再確保で移動するため、ACK が 64 KiB を超えたあとにパケット損失や PTO の再送が起きると、
ngtcp2 が移動前・解放済みの領域を読み、ストリームデータが silent に破損する。実 TLS ハンドシェイクをした実 `Connection` 間のパケット交換で、再送データの破損を決定論的に再現した。

0 長 FIN が破棄される不具合とは独立した問題である。

## 現状

- ngtcp2 の `ngtcp2_conn_writev_stream` の契約は `ngtcp2-sys/src/bindings.rs` の doc に明記されている
  - `*pdatalen` で示された範囲のバッファは `ngtcp2_callbacks.acked_stream_data_offset` が呼ばれるまで同一領域で保持すること
  - 保持が破れると、再送時に ngtcp2 が古いポインタを読む
- ngtcp2 の C 実装は、STREAM フレームを書くときに `ngtcp2_vec` (ポインタと長さ) をフレームチェーンにコピーし、再送キュー (`ngtcp2_rtb`) が ACK まで保持する。データ本体はコピーしない
- `ngtcp2/src/conn.rs` の `write_stream_with_flags` は、`InFlightStreamData` が持つ `Vec<u8>` のスライスへの生ポインタを ngtcp2 に渡す
- `InFlightStreamData` は `offset` / `data` / `start` を持ち、未 ACK のバイト列を 1 つの `Vec<u8>` で管理する
  - `append` は `Vec::extend_from_slice` で追加するため、容量を超えると再確保して旧領域を解放する
  - `ack_until` は `start` が `IN_FLIGHT_COMPACT_THRESHOLD` (64 KiB) 以上になると `Vec::drain(..start)` で先頭を詰め、未 ACK のバイト列をメモリ上で移動する
- したがって、64 KiB 以上が ACK されて `drain` が走ったあと、または未 ACK データがある状態での追加書き込みで再確保が起きたあとに、パケット損失 / PTO で再送が起きると、ngtcp2 は移動前・解放済みのアドレスから読む
- ストリームデータの破損は、オフセットもパケットの AEAD も正しいまま中身だけが別のバイト列になる。QUIC 層では検出できず、受信側は誤ったデータを正しいストリームデータとして受理する (silent data corruption)
- 再確保の経路では、解放済みメモリの読み出し (未定義動作) にもなる。可視の破損はアロケータの配置に依存する
- 既定設定でも、大容量転送で 64 KiB 超が ACK された時点で未 ACK のデータが残っていれば `drain` は発生する。そのあとに損失 / PTO が起きると破損するため、実運用の損失のある経路で踏みうる
- 既存の e2e テストはループバックでパケット損失が起きないため、この問題を検出できない

## 再現手順

issue 作成時に、実 TLS ハンドシェイクをしたクライアント / サーバーの `Connection` 間でパケットを手動配送するテストを作成し、`drain` 経路の破損を決定論的に再現した (モック・スタブなし)。

1. クライアントから 320 KiB の非一様なデータ (`data[i] = ((i * 131) ^ (i >> 3)) & 0xff`) を送信する。最初の `write_stream` で全量を渡して `Vec` の容量を 327680 バイトに確保し、以降の追記で再確保が起きないようにする (drain 経路に限定するため)
2. 設定は Reno、`ack_threshold = 1`、`no_pmtud = true`、`no_tx_udp_payload_size_shaping = true`、`max_tx_udp_payload_size = 65527` にする (短時間で 64 KiB 超の ACK を溜めるため)
3. ACK 済みが 65536 バイト未満になるまで配送し、しきい値を超える 1 パケット (offset 65487、1200 バイト) を配送する。ACK 済みが 66687 バイトになり `Vec::drain(..66687)` が走る
4. 1 秒進めて `handle_expiry` を呼び、未 ACK の最も古い 2 パケットを再送させる
5. サーバーが受信したデータをオフセット単位で元データと比較する

実測結果:

- 再送された 2 パケット (2400 バイト) の受信内容は、元データの `[133374..135774]` と 2400/2400 バイト完全一致した。これは `2 * 66687` の位置であり、ngtcp2 が `base + 66687` (drain 前のアドレス) を読んで、先頭に詰められた後のデータを送ったことを意味する
- 最初の不一致オフセットは 66687 で、drain で捨てた先頭オフセットと完全に一致した
- 複数回実行して 100% 再現した

`append` の再確保経路は、最初の容量 (80 KiB) から 81920 → 163840 → 327680 と倍々に再確保させ、パケット 0 だけを ACK して drain を起こさない構成で確認した。
通常モードでは可視の破損は出なかったが、macOS の `MallocScribble=1` (解放時に 0x55 で埋める) では 5 回中 3 回、解放済み領域由来の 0x55 と破損を観測した。
drain と併発する構成では 18 回中 9 回、再送 2400 バイトすべてが 0x55 になった。

## 設計方針

- ngtcp2 に渡した領域を ACK まで移動・解放しない
  - 案: 送信データをチャンク (`Vec<Box<[u8]>>` など) に分けて保持し、チャンクを移動させない。ACK されたチャンクだけを `acked_stream_data_offset` に合わせて解放する
  - 案: 再確保を避けるため、書き込み時に必要な容量を事前に確保し、`ack_until` の `drain` をやめて開始位置の前進だけにする。ただし長時間のストリームでは未 ACK メモリの解放を別途行う必要がある
- どちらの案でも公開 API は変更しない
- `InFlightStreamData` の `append` / `ack_until` / `truncate_unwritten` の契約を doc コメントに明記する
- 損失注入テスト (実 `Connection`、実パケット、モックなし) を追加し、ACK が 64 KiB を超えたあとに損失 / PTO で再送しても受信データが一致することを検証する
- 再確保経路の未定義動作は、ASAN もしくは `MallocScribble` 相当の手段で確認する
- 既存の大容量転送テストでメモリ使用量が増えすぎないことを確認する

## 完了条件

- ACK が 64 KiB を超えたあとにパケット損失 / PTO の再送が起きても、ピアが受け取るストリームデータが元のバイト列と一致する
- 追加する回帰テストが修正前は破損して失敗し、修正後は成功する
- 再送時に解放済みメモリを参照しない (ASAN もしくは等価な手段で確認する)
- 長大なストリームで未 ACK データの保持量がデータ量の二乗に増えない
- `cargo test --workspace --tests --features source-build`、`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets --features source-build -- -D warnings` が成功する

## 解決方法

`ngtcp2/src/conn.rs` の `InFlightStreamData` を、ngtcp2 に渡したバッファを ACK されるまで移動・解放しない構造に変更した。

- `ack_until` から `Vec::drain(..start)` による詰め直しを削除し、未 ACK のバイト列を移動しないようにした
- `append` で容量が足りない場合、`Vec` を再確保せずに新しい領域へ未 ACK のデータを写し、ngtcp2 が参照している旧領域は `RetiredBuffer` として ACK されるまで保持する
- `ack_until` で ACK が進んだときに、参照が不要になった `RetiredBuffer` を解放する
- doc コメントに、バッファを移動・解放しない理由と `RetiredBuffer` の役割を明記した

`ngtcp2/src/conn.rs` の単体テストに、領域を差し替えても旧領域の内容が変わらないことと、ACK で未 ACK のバイト列が移動しないことを追加した。また `ngtcp2/tests/test_buffer_lifetime.rs` を追加し、実 TLS ハンドシェイクをした 2 つの `Connection` 間でパケットを手動配送して、64 KiB 超の ACK 後の損失再送 (drain 経路) と追記による領域差し替え後の損失再送 (realloc 経路) の両方で、再送後の受信データが元のバイト列と一致することを検証する。

### 検証

- 追加した回帰テストは修正前のコードで、64 KiB 超の ACK 後の再送データが offset 66687 から破損して失敗し、修正後は成功した
- `cargo test --workspace --tests --features source-build` が成功した
- `cargo fmt --all -- --check` と `cargo clippy --workspace --all-targets --features source-build -- -D warnings` が成功した
