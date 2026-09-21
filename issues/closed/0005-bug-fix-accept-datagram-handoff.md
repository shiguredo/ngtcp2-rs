# accept 済み接続宛てのデータグラムを接続へ引き渡す

- Created: 2026-09-21
- Completed: 2026-09-21
- Branch: feature/fix-accept-datagram-handoff
- Polished: {YYYY-MM-DD}

## 目的

`Server::accept` を回しながら accept 済み接続を駆動する使い方で、その接続宛てのデータグラムが失われる問題を修正する。http3-rs の WebTransport 相互運用テスト (interop/wt) が macOS の CI で断続的に失敗していた原因であり、http3-rs 側に入れた回避策 (アクティブな接続がある間は `accept` を呼ばない) を不要にする。

## 現状

- `Server` と `AcceptedConnection` は同じ UDP ソケットを読む。`Server::take_connection` は引き渡した接続の CID を `cid_map` / `addr_map` から除去し、`taken_cids` に記録する
- `Server::handle_datagram` は、未知 DCID の short header パケットに Stateless Reset を送る経路で `taken_cids` を「Reset を送らない」ためだけに使い、そのデータグラムをそのまま破棄する (`send_stateless_reset` の `is_taken_cid` 分岐)
- そのため `Server::accept` を回し続けると、accept 済み接続宛てのパケットが `accept` 側で読まれるたびに失われ、転送が再送タイムアウト (RFC 9002 Section 6.2) まで止まる。README に書かれた使い方 (accept ループ + 接続ごとの駆動タスク) でも起きる
- 同根の問題が 2 つある。accept 済み接続が発行した CID は経路表に登録されないため、`Server::accept` が読んだ新しい CID 宛てのパケットは未知 DCID として破棄される。また退役した CID が記録されないため、遅れて届いたパケットに Stateless Reset を返しうる

## 設計方針

- `Server` と `AcceptedConnection` で共有する振り分け表 (`SharedRoutes`) を作り、accept 済み接続の CID / アドレス経路と受信キューを集約する
- ソケットを読んだ側は、自分のものではないデータグラムを所有者のキューへ引き渡す (待たない `try_send`)。どちらのリーダーも、既知の接続宛てデータグラムを破棄しない
- accept 済み接続が発行・退役した CID は `AcceptedConnection` から共有表へ反映する
- 引き渡しキューは上限付き (`MAX_QUEUED_DATAGRAMS`) にして、動されない接続でメモリが伸びるのを防ぐ。あふれた分は捨てるが、QUIC が再送で回復する
- 共有表は `Mutex` で保護する。ロック中に await せず保持時間が短いため、非同期タスク間で共有しても安全

## 完了条件

- accept ループと接続の駆動を並行させても、accept 済み接続宛てのデータグラムが失われない (ピアの再送なしで全量が届く)
- 回帰テスト `tokio-ngtcp2/tests/e2e/accept_handoff.rs` が修正前は失敗し、修正後は成功する
- 既存の e2e テスト (`cargo test --workspace --tests`) がすべて成功する
- `cargo fmt --all` と `cargo clippy --workspace --all-targets -- -D warnings` が成功する

## 解決方法

ソケットを読んだ側が、自分のものではないデータグラムを所有者へ引き渡すようにした。`Server` と接続ハンドルで経路表と受信キュー (`SharedRoutes`) を共有し、どちらのリーダーも既知の接続宛てデータグラムを破棄しない。

### 関連ファイル

- `tokio-ngtcp2/src/server.rs`
  - `SharedRoutes` を追加し、`Server` と `AcceptedConnection` で `Arc<Mutex<SharedRoutes>>` を共有する
  - `Server::take_connection` で accept 済み接続の CID / アドレス経路と受信キューを登録する
  - `Server::handle_datagram` は accept 済み接続宛てのデータグラムを `handoff_to_accepted` でその接続へ引き渡す
  - `Server::is_taken_cid` は接続ハンドル側で退役した CID も確認する
  - `AcceptedConnection::recv_event` は受信キューのデータグラムを処理し、別の accept 済み接続宛てのデータグラムをその接続へ引き渡す
  - `AcceptedConnection::sync_routes` で発行 / 退役した CID を共有表へ反映し、`Drop` で経路を除去する
- `tokio-ngtcp2/tests/e2e/accept_handoff.rs` と `tokio-ngtcp2/Cargo.toml`
  - accept を回したあとに接続を駆動したとき、クライアントの再送なしで全量が届くことを確認する回帰テストを追加する

### 検証

- 回帰テストは修正前の実装で 3 回中 3 回失敗し (クライアントのパケット喪失が 4 件)、修正後は 3 回中 3 回成功した
- `cargo test --workspace --tests` と `cargo test --workspace --tests --features source-build` が 25 テストターゲットすべて成功した
- `cargo fmt --all -- --check` と `cargo clippy --workspace --all-targets -- -D warnings` が成功した
- http3-rs の interop テストで、http3-rs 側の回避策を外した状態でも s2n クライアント → ngtcp2 サーバーが 10 回連続、ngtcp2 クライアント → s2n サーバーが 5 回連続で成功した (本修正をローカル patch して検証)
