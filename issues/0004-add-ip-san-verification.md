# TlsContext::set_server_name に IP SAN 検証と検証失敗理由の診断性を追加する

- Created: 2026-09-18
- Completed: {YYYY-MM-DD}
- Branch: feature/add-ip-san-verification
- Polished: {YYYY-MM-DD}

## 目的

IP アドレス直結のサーバーへ検証付きで接続できるようにし、検証失敗の理由を利用者に伝えられるようにする。http3-rs の issue 0173 (pending) から移管された。

## 現状

- `TlsContext::set_server_name` (`ngtcp2/src/crypto.rs`) は `server_name` を DNS 名に限定し、IP アドレスを `InvalidArgument` で拒否する。IP アドレス直結のサーバー (テスト環境・社内ネットワークで典型的) への検証付き接続ができない
- aws-lc には `X509_VERIFY_PARAM_set1_ip_asc` が存在し、IP SAN 照合は実装可能
- 検証失敗時、`SSL_CTX_set_verify` の verify_callback を設定していないため、チェーン切れとホスト名不一致の切り分けがログだけでは不可能 (ngtcp2 の汎用 crypto エラーしか見えない)

## 設計方針

- `server_name` が IP アドレスの場合、SNI は送信せず (RFC 6066 Section 3 は HostName を FQDN に限定) ホスト名検証に `X509_VERIFY_PARAM_set1_ip_asc` を使う。DNS 名の場合は現状どおり `SSL_set1_host` を使う
- 検証失敗理由の診断: `SSL_CTX_set_custom_verify` または `SSL_get_verify_result` を参照し、検証エラーの種別 (証明書チェーン切れ / ホスト名不一致 / 期限切れ等) をエラーに含める (ログは英語)
- 公開 API のシグネチャは現状を維持する (`server_name` の制約が緩和されるだけで呼び出し方は変わらない)

## 完了条件

- IP アドレスを `server_name` に渡して、IP SAN を持つ証明書のサーバーへの検証付き接続が成功する
- IP アドレス + ホスト名不一致 (SAN にその IP が無い) の場合は失敗する
- 検証失敗時に、チェーン検証失敗とホスト名不一致を区別できるエラー情報が得られる
- 既存の DNS 名限定のテストが引き続き成立する
- `cargo test --all` と `cargo fmt --all -- --check` と `cargo clippy --all-targets --all-features -- -D warnings` が通る

## 解決方法

### 関連ファイル

- `ngtcp2/src/crypto.rs` (`TlsContext::set_server_name` / `TlsContext::new_client`)
- `tokio-ngtcp2/src/client.rs` (`ClientConfig::with_ca_cert_pem` 経由の接続)
- 一次資料: RFC 6066 Section 3、aws-lc (BoringSSL) の `X509_VERIFY_PARAM_set1_ip_asc`
