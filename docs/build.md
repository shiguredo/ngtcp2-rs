# ビルド

## 対応プラットフォーム

- macOS
- Linux

**Windows は非対応です。** パス情報の変換に POSIX ソケット型 (`libc::sockaddr_storage`) を使っているためです。

## ビルド要件

`shiguredo_ngtcp2_sys` は ngtcp2 の静的ライブラリを prebuilt として GitHub Releases からダウンロードします。そのため既定では C のビルド環境は不要です。

- curl と tar
  - ダウンロードと展開に使います
- ネットワーク接続
  - prebuilt を配布していないプラットフォームではビルドできません

prebuilt を配布しているプラットフォームは次のとおりです。

- Ubuntu 22.04 / 24.04 / 26.04 (x86_64 / arm64)
- macOS (arm64)

## ソースからビルドする

`source-build` feature を有効にすると ngtcp2 をソースからビルドします。次の場合はこちらを使ってください。

- prebuilt を配布していないプラットフォーム (macOS の x86_64 など)
- ngtcp2 のソースを変更してビルドしたい場合

```toml
[dependencies]
shiguredo_ngtcp2_tokio = { version = "2026.1", features = ["source-build"] }
```

ソースからのビルドには以下が必要です。

- CMake
  - 未インストールの場合は `shiguredo_cmake` が取得します
- C コンパイラ (clang / gcc)
- Go
  - aws-lc のビルドに必要です

ngtcp2 のソースは `ngtcp2-sys/build.rs` がビルド時に取得します。取得先は ngtcp2 のブランチ `reliable-stream-reset` です。ネットワークに接続できない環境ではビルドできません。

## 環境変数

- `NGTCP2_TARGET`
  - prebuilt アーカイブのターゲット名を上書きします (`ngtcp2-<target>.tar.gz` の `<target>`)
  - 既定では OS と CPU から決まります
