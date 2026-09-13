# shiguredo_ngtcp2_sys

[![crates.io](https://img.shields.io/crates/v/shiguredo_ngtcp2_sys.svg)](https://crates.io/crates/shiguredo_ngtcp2_sys)
[![docs.rs](https://docs.rs/shiguredo_ngtcp2_sys/badge.svg)](https://docs.rs/shiguredo_ngtcp2_sys)

[ngtcp2](https://github.com/ngtcp2/ngtcp2) の Rust バインディング (FFI) を提供するクレートです。

## 概要

ngtcp2 は C で実装された QUIC ライブラリです。このクレートは ngtcp2 をビルドし、
Rust から利用するための低レベル FFI バインディングを提供します。

## 特徴

- ngtcp2 のソースコードをブランチ指定で取得して CMake でビルド
- aws-lc を TLS バックエンドとして使用
- 生成済みバインディングを同梱 (通常ビルドでは libclang 不要)

## ngtcp2 のバージョン

`Cargo.toml` の `[package.metadata.external-dependencies]` でブランチ
`reliable-stream-reset` を指定しています。`build.rs` はビルドのたびにこのブランチの
最新コミットを取得するため、上流が進むと同梱の `bindings.rs` と構造体レイアウトが
食い違う可能性があります。`src/lib.rs` のテストがバージョンの一致を検証します。

バインディングを再生成する場合:

```bash
LIBCLANG_PATH=/opt/homebrew/opt/llvm/lib \
  cargo build -p shiguredo_ngtcp2_sys --features overwrite
```

## aws-lc-sys の再公開

TLS バックエンドの生ポインタ (`SSL` / `SSL_CTX`) は ngtcp2 の C API 越しにやり取りする
ため、sys クレートと利用側で同一の aws-lc を指す必要があります。別々に `aws-lc-sys` へ
依存すると、バージョン解決の結果によっては同一プロセスに 2 つの aws-lc がリンクされて
シンボルが衝突します。これを構造的に防ぐため、このクレートが `aws_lc_sys` を再公開して
います。利用側は `shiguredo_ngtcp2_sys::aws_lc_sys` を経由してください。

## ビルド要件

ngtcp2 の静的ライブラリは prebuilt として GitHub Releases からダウンロードします。そのため既定では C のビルド環境は不要です。詳細はリポジトリの [docs/build.md](https://github.com/shiguredo/ngtcp2-rs/blob/develop/docs/build.md) を参照してください。

`source-build` feature を有効にするとソースからビルドします。その場合は以下が必要です。

- CMake
- C コンパイラ (gcc, clang など)
- Go (aws-lc のビルドに必要)

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
