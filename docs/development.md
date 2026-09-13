# 開発

## コマンド

```bash
make check         # cargo check
make clippy        # cargo clippy
make test          # cargo test
make doc-test      # doctest
make fmt           # cargo fmt
make interop-test  # s2n-quic / quiche との相互運用テスト
make fuzzing       # fuzz ターゲットを全件 30 秒ずつ実行する
make fuzzing-list  # fuzz ターゲットの一覧を表示する
make package-list  # パッケージに含まれるファイルを確認する
```

`make check` / `make clippy` / `make test` / `make doc-test` は `source-build` feature を指定します。既定は prebuilt のダウンロードですが、開発中のバージョンにはリリースが無いためです。詳細は [ビルド](build.md) を参照してください。

`make doc-test` は `shiguredo_ngtcp2_sys` を除外します。`bindings.rs` には bindgen が C ヘッダーのコメントから生成した doc コメントが含まれ、その中の Rust 風のサンプルが rustc でパースできないためです。

## Git フック

Git フックは [prek](https://prek.j178.dev) で管理しています。

```bash
prek install --prepare-hooks
```

## 相互運用テスト

s2n-quic と quiche という独立した QUIC 実装と接続し、ワイヤー上のやり取りを検証します。詳細は [相互運用テスト](interop.md) を参照してください。

## Fuzzing

`fuzz/` は [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) を使った fuzz ターゲットを置く独立した workspace です。ルートの workspace の `cargo` コマンドでは対象にならないため `fuzz` ディレクトリで実行します (Makefile のターゲットが `cd fuzz` を行います)。

```bash
make fuzzing-list  # ターゲットの一覧を表示する
make fuzzing       # 全ターゲットを 30 秒ずつ実行する
```

個別のターゲットを実行する場合:

```bash
cd fuzz
cargo +nightly fuzz run accept_initial -- -max_total_time=300
```

クラッシュを検出すると `fuzz/artifacts/<ターゲット名>/` に再現用の入力が保存されます。`fuzz/corpus` と `fuzz/artifacts` はコミットしません。

ngtcp2 は prebuilt ではなくソースからビルドしたもの (`source-build` feature) を対象にします。そのため Go と CMake が必要です。

| ターゲット | 対象 |
| --- | --- |
| `accept_initial` | 新規接続の Initial パケットの受理判定 (RFC 9000 Section 7.2 / 14.1) |
| `conn_read_pkt` | サーバー / クライアント接続の受信処理と、送信・イベントの駆動 |
| `decode_packet_version` | Long header パケットからのバージョンとコネクション ID の取り出し |
| `split_packets` | 書き出したバッファの QUIC パケット分割 |
| `varint_decode` | QUIC 可変長整数のデコードと再エンコード (RFC 9000 Section 16) |
| `verify_new_token` | NEW_TOKEN で配布したトークンの検証 (RFC 9000 Section 8.1.3) |
| `verify_retry_token` | Retry トークンの検証 (RFC 9000 Section 8.1.3) |

ngtcp2 本体は C で書かれており fuzz のカバレッジ計測の対象外です。そのため検出できるのは Rust 側のパニック (値の境界・コネクション ID の扱い・ngtcp2 から呼ばれるコールバック・エラー変換) が中心です。

fuzz は CI では実行しません。まとめて実行したい場合は [Fuzzing ワークフロー](../.github/workflows/fuzzing.yml) を Actions から手動で起動してください (fmt と clippy の検査もそこで行います)。

## バインディングの再生成

`ngtcp2-sys/src/bindings.rs` は ngtcp2 のブランチ `reliable-stream-reset` から生成したものを同梱しています。ngtcp2 側が更新されて構造体レイアウトが変わった場合は再生成してください。

`overwrite` feature を指定するとソースからビルドした上で再生成します (`source-build` も同時に有効になります)。

```bash
cargo build -p shiguredo_ngtcp2_sys --features overwrite
```

`overwrite` feature の使用時は libclang が必要です。macOS では Homebrew の LLVM を指定します。

```bash
LIBCLANG_PATH=/opt/homebrew/opt/llvm/lib \
  cargo build -p shiguredo_ngtcp2_sys --features overwrite
```

`ngtcp2-sys/src/lib.rs` のテストが、同梱した `bindings.rs` のバージョンと実際にリンクされた ngtcp2 のバージョンの一致を検証します。

再生成後は `shiguredo_ngtcp2_sys` のビルドキャッシュを破棄してください。`build.rs` はキャッシュが残っていると ngtcp2 を取得し直さないため、`bindings.rs` だけが新しくなり、リンクされる C ライブラリが古いままだと callbacks 構造体のバージョンが食い違って `ngtcp2_callbackslen_version: Unreachable.` で abort します。fuzz と interop は別の workspace なので、それぞれの target ディレクトリも対象です。

```bash
cargo clean -p shiguredo_ngtcp2_sys
cargo clean --manifest-path fuzz/Cargo.toml -p shiguredo_ngtcp2_sys
cargo clean --manifest-path interop/Cargo.toml -p shiguredo_ngtcp2_sys
```
