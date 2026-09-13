# 相互運用テスト

## 目的

`shiguredo_ngtcp2_tokio` のクライアントとサーバーはどちらも ngtcp2 を使うため、Rust 側のテストだけでは「ngtcp2 の使い方だけが誤っている」不具合を検出できません。このテストは **独立した QUIC 実装** と実際の UDP ソケットで接続し、ワイヤー上のやり取りが仕様どおりであることを検証します。

- [s2n-quic](https://github.com/aws/s2n-quic) (AWS) — Rust 実装。TLS は rustls + aws-lc-rs
- [quiche](https://github.com/cloudflare/quiche) (Cloudflare) — Rust 実装。TLS は BoringSSL

## 構成

```
interop/
  src/lib.rs                     我々側のヘルパー (証明書生成、サーバー / クライアントの駆動)
  tests/s2n_quic.rs              s2n-quic との相互運用テスト (同一プロセス)
  tests/quiche.rs                quiche との相互運用テスト (子プロセス起動)
  quiche-driver/                 quiche を動かす子プロセスのパッケージ
    src/tokio_quiche_driver.rs   tokio-quiche で動かすクライアントとサーバー
    src/raw_quiche.rs            生 quiche で動かすクライアント (0-RTT 送信 / マイグレーション)
    src/bin/quiche_driver.rs     client / server をサブコマンドで切り替える
```

検証する組み合わせ:

| 向き | s2n-quic | quiche |
| --- | --- | --- |
| 我々のサーバー ← 相手のクライアント | あり | あり |
| 我々のサーバー (Retry 有効) ← 相手のクライアント | あり | あり |
| 我々のサーバー (Retry + 0-RTT 有効) ← 相手のクライアント | なし | あり |
| 我々のサーバー (0-RTT 有効) ← 相手のクライアント (0-RTT) | 未対応 | あり |
| 我々のサーバー ← 相手のクライアント (マイグレーション) | 未対応 | あり |
| 我々のサーバー (長さ 0 のコネクション ID) ← 相手のクライアント | 未検証 | あり |
| 相手のサーバー ← 我々のクライアント | あり | あり |
| 相手のサーバー (0-RTT 有効) ← 我々のクライアント (0-RTT) | 未対応 | あり |
| 相手のサーバー (マイグレーション有効) ← 我々のクライアント (マイグレーション) | 未対応 | あり |

「未対応」は s2n-quic の公開 API に 0-RTT (early data) とクライアント主導のマイグレーションが無いためで、実装の不具合ではありません。

Retry の後に 0-RTT でデータを送り直すかは実装によります。ngtcp2 は 0-RTT で送り直しますが、quiche はハンドシェイクの完了後に 1-RTT で送ります。そのため Retry と 0-RTT を同時に有効にした組み合わせでは、データが届くことだけを検証しています。我々のクライアントが Retry の後も 0-RTT で送り直すことは `tokio-ngtcp2/tests/e2e/early_data.rs` の `test_early_data_with_retry` で検証しています。

長さ 0 のコネクション ID (RFC 9000 Section 5.1) は、サーバーがコネクション ID を
発行しない構成で quiche のクライアントとのみ検証しています。quiche のサーバーは
コネクション ID を必須とするため、我々のクライアントが長さ 0 のコネクション ID を
使う組み合わせは検証していません (s2n-quic のサーバーも同様です)。

ECN の相互運用は検証していません。quiche の `RecvInfo` に ECN のフィールドが無く ECN のコードポイントを渡す手段が無いこと、s2n-quic の公開 API にも ECN を観測する手段が無いことによります (`s2n-quic-transport` の内部には実装があります)。ECN は `tokio-ngtcp2` の e2e テスト (`tokio-ngtcp2/tests/e2e/`) でソケットの補助データまで含めて検証しています。

信頼性のあるストリームリセット (draft-ietf-quic-reliable-stream-reset) の相互運用は検証していません。s2n-quic 1.88 と quiche 0.29 はこのドラフトに対応していないためです (どちらも `reset_stream_at` を実装していません)。未対応のエンドポイントは未知のトランスポートパラメータを無視するため (RFC 9000 Section 7.4.2)、通知しても接続は壊れません。この仕組みは `tokio-ngtcp2` の e2e テストと sans-IO 層のテスト (`ngtcp2/tests/test_conn.rs`) で検証しています。

## 検証している内容

- ハンドシェイクとストリームの往復 (双方向)
- Retry によるアドレス検証 (RFC 9000 Section 8.1.2)。相手が生成したトークンは検証できないため、相手が Retry を受理して Initial を送り直せることを検証する
- 0-RTT (RFC 9001 Section 4.6)。セッションチケットを発行した側で再開し、ハンドシェイクの完了前に送ったデータが届くことを検証する。我々のサーバーは受け取ったデータを 0-RTT として受理したかを接続から観測し、quiche のサーバーには受理したかどうかを結果として書き出させる
- マイグレーション (RFC 9000 Section 9)。経路の検証が完了してから移った先の経路でデータを送り、相手がそのデータを受け取ってエコーを返すことを検証する。我々のサーバーは受け取った経路の検証に成功したかを接続から観測する

## quiche ドライバ

`quiche_driver` はクライアントとサーバーをサブコマンドで切り替えます。

```
quiche_driver client <server_addr> <ca_cert_path> <payload> [--early-data] [--migrate]
quiche_driver server <cert_path> <key_path> [--early-data] [--migration]
```

- `--early-data` (client): 1 回目の接続でセッション情報を保存し、2 回目の接続で 0-RTT を送る
- `--migrate` (client): ハンドシェイクの完了後に別のローカルアドレスで経路を検証し、その経路へ移ってからデータを送る
- `--early-data` / `--migration` (server): 0-RTT の受理 / ピアのマイグレーションの受理を有効にする

サーバーは接続を終了しません。エコーするたびに `<バイト数> bytes (early data: <真偽>)` を標準出力に 1 行で書き出すので、テストはその行を読んでからプロセスを終了させます。tokio-quiche のワーカーはピアが CONNECTION_CLOSE を送っても draining が終わるまで終了しないため、接続の終了を待ってプロセスを終わらせるとアイドルタイムアウトまで待たされるためです。

### tokio-quiche と生 quiche の使い分け

quiche 側は原則 [tokio-quiche](https://github.com/cloudflare/quiche/tree/master/tokio-quiche) (quiche の tokio 統合) で動かします。次の 2 つだけは tokio-quiche では表現できないため、生 quiche を直接駆動します。

- 0-RTT のデータ送信: tokio-quiche のワーカーは `process_writes` をハンドシェイク完了後 (`is_established()`) にしか呼ばないため、クライアントが early data を送れない
- マイグレーション: tokio-quiche に経路の検証 / 移行の API が無く、ワーカーがソケットを 1 つ所有するためローカルアドレスを変えられない (tokio-quiche 自身の migration テストも、クライアントは生 quiche で書かれている)

どちらも quiche の接続を直接駆動し、送信するパケットとその送信元アドレスをアプリケーションが決める必要があります。

また tokio-quiche の設定にはクライアントが信頼する CA 証明書を指定する項目が無いため、クライアントは `ConnectionHook` で BoringSSL の SSL_CTX を自前で作り、CA 証明書を読み込んでいます。証明書検証は有効なままです。

tokio-quiche は `foundations` 経由で `opentelemetry_sdk` を引くため、`interop/Cargo.lock` に Dependabot のアラート (`opentelemetry_sdk` の W3C Baggage のメモリ割り当て) が出ます。修正版 (0.32.1) は tokio-quiche が要求するバージョン (0.31) と一致せず、tokio-quiche の最新版は 0.19.1 のため上流が上がるまで解消できません。公開している 3 クレートは tokio-quiche に依存しないため影響はありません。

quiche は未使用のコネクション ID を自分では発行しないため、マイグレーションの検証ではドライバとサーバーの両方が `new_scid()` で明示的に発行します (RFC 9000 Section 9.5)。

## 実行

```bash
make interop-test
```

または直接:

```bash
cd interop
cargo build --workspace --bins   # quiche のドライバをビルドする
cargo test
```

## quiche を別プロセスで動かす理由

quiche が静的リンクする BoringSSL と、ngtcp2 系が使う aws-lc は `SSL_CTX_new` や `X509_STORE_add_cert` などの unprefixed なシンボルを共有します。

同一バイナリに両方をリンクすると、リンカがどちらか一方の実装だけを選びます。その結果、構造体のレイアウトが食い違って `pthread_rwlock_wrlock` の失敗で abort します (実際に発生しました)。

そのため quiche 側は `quiche-driver` パッケージのバイナリとして別プロセスで動かし、テストからは子プロセスとして起動します。`quiche-driver` は ngtcp2 系に依存しないため、この衝突は起きません。

s2n-quic は ngtcp2 と同じ aws-lc を使うため、同一プロセスで動かせます。

## CI

`.github/workflows/interop.yml` で実行します。quiche (BoringSSL) と s2n-quic (aws-lc) のビルドに時間がかかるため、通常の CI とは別のジョブにしています。通常の CI は `.github/workflows/ci.yml` です。
