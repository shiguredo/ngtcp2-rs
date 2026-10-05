//! Retry / NEW_TOKEN のトークンとパケット書き出しの統合テスト (RFC 9000 Section 8.1)
//!
//! `RetrySecret` / `generate_retry_token` / `verify_retry_token` /
//! `generate_new_token` / `verify_new_token` / `write_retry_packet` /
//! `write_stateless_connection_close` の公開 API を検証する。

use std::net::SocketAddr;
use std::time::Duration;

use shiguredo_ngtcp2::{
    AddressValidationTokenKind, ConnectionId, Error, MAX_NEW_TOKEN_LEN, MAX_RETRY_TOKEN_LEN,
    QuicVersion, RETRY_SECRET_LEN, RetrySecret, TRANSPORT_ERROR_INVALID_TOKEN, generate_new_token,
    generate_retry_token, token_kind, verify_new_token, verify_retry_token, write_retry_packet,
    write_stateless_connection_close,
};
use shiguredo_ngtcp2_sys::{NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR, NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2};

/// テスト用の秘密
fn secret() -> RetrySecret {
    RetrySecret::from_bytes([0x77; RETRY_SECRET_LEN])
}

/// テスト用のクライアントアドレス
fn client_addr() -> SocketAddr {
    "127.0.0.1:50000".parse().expect("リテラルアドレスは有効")
}

/// NEW_TOKEN のトークンを検証できること (RFC 9000 Section 8.1.3)
#[test]
fn test_new_token_roundtrip() {
    let secret = secret();
    let ts = 1_000_000_000;

    let token = generate_new_token(&secret, client_addr(), ts).expect("トークンを生成できること");

    assert!(
        token.as_bytes().len() <= MAX_NEW_TOKEN_LEN,
        "トークンが最大長を超えないこと"
    );
    assert_eq!(
        token.kind(),
        AddressValidationTokenKind::NewToken,
        "種別が NEW_TOKEN であること"
    );
    assert_eq!(
        token_kind(token.as_bytes()),
        Some(AddressValidationTokenKind::NewToken),
        "マジックバイトから種別を判定できること"
    );

    verify_new_token(
        &secret,
        token.as_bytes(),
        client_addr(),
        Duration::from_secs(10),
        ts + 1,
    )
    .expect("同じ秘密とアドレスで検証できること");

    // 期限切れのトークンは検証できない
    assert!(
        verify_new_token(
            &secret,
            token.as_bytes(),
            client_addr(),
            Duration::from_secs(10),
            ts + 11_000_000_000,
        )
        .is_err(),
        "有効期間を過ぎたトークンは検証に失敗すること"
    );

    // 別の秘密では検証できない
    let other = RetrySecret::from_bytes([0x78; RETRY_SECRET_LEN]);
    assert!(
        verify_new_token(
            &other,
            token.as_bytes(),
            client_addr(),
            Duration::from_secs(10),
            ts + 1,
        )
        .is_err(),
        "別の秘密では検証に失敗すること"
    );
}

/// NEW_TOKEN のトークンが IP アドレスに束縛されること
///
/// ポートは含まれない (アドレス付け替えで正当に変わることがあるため)。
#[test]
fn test_new_token_is_bound_to_address() {
    let secret = secret();
    let ts = 1_000_000_000;
    let token = generate_new_token(&secret, client_addr(), ts).expect("トークンを生成できること");

    // 同じ IP アドレスならポートが変わっても検証できる
    let other_port: SocketAddr = "127.0.0.1:50001".parse().expect("リテラルアドレスは有効");
    verify_new_token(
        &secret,
        token.as_bytes(),
        other_port,
        Duration::from_secs(10),
        ts + 1,
    )
    .expect("同じ IP アドレスなら検証できること");

    // 別の IP アドレスでは検証できない
    let other_addr: SocketAddr = "127.0.0.2:50000".parse().expect("リテラルアドレスは有効");
    assert!(
        verify_new_token(
            &secret,
            token.as_bytes(),
            other_addr,
            Duration::from_secs(10),
            ts + 1,
        )
        .is_err(),
        "別の IP アドレスでは検証に失敗すること"
    );
}

/// Debug 出力に秘密が含まれないこと
#[test]
fn test_debug_redacts_secret() {
    let debug = format!("{:?}", secret());
    assert_eq!(debug, "RetrySecret(<redacted>)", "秘密を表示しないこと");
}

/// 生成したトークンを検証して Original DCID を取り出せること
#[test]
fn test_retry_token_roundtrip() {
    let secret = secret();
    let retry_scid = ConnectionId::new(&[0xaa; 16]).expect("CID を作れること");
    let odcid = ConnectionId::new(&[0xbb; 16]).expect("CID を作れること");
    let ts = 1_000_000_000;

    let token = generate_retry_token(
        &secret,
        QuicVersion::V1,
        client_addr(),
        &retry_scid,
        &odcid,
        ts,
    )
    .expect("トークンを生成できること");

    assert!(
        token.as_bytes().len() <= MAX_RETRY_TOKEN_LEN,
        "トークンが最大長を超えないこと"
    );
    assert_eq!(token.kind(), AddressValidationTokenKind::Retry, "種別");
    assert_eq!(
        token_kind(token.as_bytes()),
        Some(AddressValidationTokenKind::Retry),
        "マジックバイトから種別を判定できること"
    );

    // 検証すると Retry の SCID を DCID に持つ Initial から
    // 最初の DCID を取り出せること
    let verified = verify_retry_token(
        &secret,
        token.as_bytes(),
        QuicVersion::V1,
        client_addr(),
        &retry_scid,
        Duration::from_secs(10),
        ts + 1,
    )
    .expect("トークンを検証できること");
    assert_eq!(verified, odcid, "Original DCID が取り出せること");
}

/// 乱数から生成した秘密でもトークンを生成・検証できること
#[test]
fn test_retry_secret_generate() {
    let first = RetrySecret::generate().expect("秘密を生成できること");
    let second = RetrySecret::generate().expect("秘密を生成できること");
    assert_ne!(first, second, "生成のたびに異なる秘密になること");

    let retry_scid = ConnectionId::new(&[0xcc; 16]).expect("CID を作れること");
    let odcid = ConnectionId::new(&[0xdd; 16]).expect("CID を作れること");
    let ts = 2_000_000_000;

    let token = generate_retry_token(
        &first,
        QuicVersion::V1,
        client_addr(),
        &retry_scid,
        &odcid,
        ts,
    )
    .expect("トークンを生成できること");

    assert_eq!(
        verify_retry_token(
            &first,
            token.as_bytes(),
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            Duration::from_secs(10),
            ts + 1,
        )
        .expect("生成した秘密でトークンを検証できること"),
        odcid,
        "生成した秘密でも Original DCID を取り出せること"
    );

    assert!(
        verify_retry_token(
            &second,
            token.as_bytes(),
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            Duration::from_secs(10),
            ts + 1,
        )
        .is_err(),
        "別の秘密では検証に失敗すること"
    );
}

/// 別のアドレスから再送されたトークンは検証に失敗すること
///
/// これがアドレス検証の実体 (RFC 9000 Section 8.1.2)。
#[test]
fn test_retry_token_is_bound_to_address() {
    let secret = secret();
    let retry_scid = ConnectionId::new(&[0xaa; 16]).expect("CID を作れること");
    let odcid = ConnectionId::new(&[0xbb; 16]).expect("CID を作れること");
    let ts = 1_000_000_000;

    let token = generate_retry_token(
        &secret,
        QuicVersion::V1,
        client_addr(),
        &retry_scid,
        &odcid,
        ts,
    )
    .expect("トークンを生成できること");

    let other_addr: SocketAddr = "127.0.0.1:50001".parse().expect("リテラルアドレスは有効");
    let err = verify_retry_token(
        &secret,
        token.as_bytes(),
        QuicVersion::V1,
        other_addr,
        &retry_scid,
        Duration::from_secs(10),
        ts + 1,
    )
    .expect_err("別のアドレスでは検証に失敗すること");
    assert!(
        matches!(err, Error::InvalidArgument(_)),
        "InvalidArgument が返ること: {err:?}"
    );
}

/// 有効期限が切れたトークンは検証に失敗すること
#[test]
fn test_retry_token_expires() {
    let secret = secret();
    let retry_scid = ConnectionId::new(&[0xaa; 16]).expect("CID を作れること");
    let odcid = ConnectionId::new(&[0xbb; 16]).expect("CID を作れること");
    let ts = 1_000_000_000;

    let token = generate_retry_token(
        &secret,
        QuicVersion::V1,
        client_addr(),
        &retry_scid,
        &odcid,
        ts,
    )
    .expect("トークンを生成できること");

    // 有効期間 10 秒に対して 1 時間後の時刻で検証する
    let err = verify_retry_token(
        &secret,
        token.as_bytes(),
        QuicVersion::V1,
        client_addr(),
        &retry_scid,
        Duration::from_secs(10),
        ts + Duration::from_secs(3600).as_nanos() as u64,
    )
    .expect_err("期限切れのトークンは検証に失敗すること");
    assert!(
        matches!(err, Error::InvalidArgument(_)),
        "InvalidArgument が返ること: {err:?}"
    );
}

/// 別の秘密で検証すると失敗すること
#[test]
fn test_retry_token_requires_same_secret() {
    let secret = secret();
    let other = RetrySecret::from_bytes([0x88; RETRY_SECRET_LEN]);
    let retry_scid = ConnectionId::new(&[0xaa; 16]).expect("CID を作れること");
    let odcid = ConnectionId::new(&[0xbb; 16]).expect("CID を作れること");
    let ts = 1_000_000_000;

    let token = generate_retry_token(
        &secret,
        QuicVersion::V1,
        client_addr(),
        &retry_scid,
        &odcid,
        ts,
    )
    .expect("トークンを生成できること");

    assert!(
        verify_retry_token(
            &other,
            token.as_bytes(),
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            Duration::from_secs(10),
            ts + 1,
        )
        .is_err(),
        "別の秘密では検証に失敗すること"
    );
}

/// 壊れたトークンは検証に失敗すること
#[test]
fn test_verify_rejects_garbage_token() {
    let err = verify_retry_token(
        &secret(),
        &[0u8; 8],
        QuicVersion::V1,
        client_addr(),
        &ConnectionId::new(&[0xaa; 16]).expect("CID を作れること"),
        Duration::from_secs(10),
        0,
    )
    .expect_err("壊れたトークンは拒否されること");
    assert!(
        matches!(err, Error::InvalidArgument(_)),
        "InvalidArgument が返ること: {err:?}"
    );
}

/// Retry パケットのヘッダーが RFC 9000 Section 17.2.5 の形式であること
#[test]
fn test_write_retry_packet_format() {
    let secret = secret();
    let client_scid = ConnectionId::new(&[0x11; 16]).expect("CID を作れること");
    let retry_scid = ConnectionId::new(&[0x22; 16]).expect("CID を作れること");
    let odcid = ConnectionId::new(&[0x33; 16]).expect("CID を作れること");
    let token = generate_retry_token(
        &secret,
        QuicVersion::V1,
        client_addr(),
        &retry_scid,
        &odcid,
        0,
    )
    .expect("トークンを生成できること");

    let mut buf = [0u8; 1200];
    let written = write_retry_packet(
        &mut buf,
        QuicVersion::V1,
        &client_scid,
        &retry_scid,
        &odcid,
        token.as_bytes(),
    )
    .expect("Retry パケットを書き出せること");

    // Long header + Retry の種別ビット (v1 では 0x3 → 先頭バイト 0xF0)
    assert_ne!(buf[0] & 0x80, 0, "Long header form bit が立っていること");
    assert_eq!(
        &buf[1..5],
        &QuicVersion::V1.as_u32().to_be_bytes(),
        "バージョンフィールド"
    );

    // DCID にはクライアントの SCID が入ること
    let dcid_len = buf[5] as usize;
    assert_eq!(dcid_len, client_scid.len(), "DCID 長");
    assert_eq!(
        &buf[6..6 + dcid_len],
        client_scid.as_bytes(),
        "DCID はクライアントの SCID であること"
    );

    // SCID にはサーバーが選んだ CID が入ること
    let scid_offset = 6 + dcid_len;
    let scid_len = buf[scid_offset] as usize;
    assert_eq!(scid_len, retry_scid.len(), "SCID 長");
    assert_eq!(
        &buf[scid_offset + 1..scid_offset + 1 + scid_len],
        retry_scid.as_bytes(),
        "SCID はサーバーが選んだ CID であること"
    );

    assert!(
        written > scid_offset + 1 + scid_len,
        "トークンと整合性タグを含むこと: {written}"
    );
}

/// 状態を持たない CONNECTION_CLOSE を書き出せること
#[test]
fn test_write_stateless_connection_close() {
    let client_scid = ConnectionId::new(&[0x11; 16]).expect("CID を作れること");
    let server_scid = ConnectionId::new(&[0x22; 16]).expect("CID を作れること");

    let mut buf = [0u8; 1200];
    let written = write_stateless_connection_close(
        &mut buf,
        QuicVersion::V1,
        &client_scid,
        &server_scid,
        TRANSPORT_ERROR_INVALID_TOKEN,
        b"invalid address validation token",
    )
    .expect("CONNECTION_CLOSE を書き出せること");

    assert!(written > 0, "パケットが生成されること");
    // 接続状態を持たない応答なので、引き金になった Initial (1200 バイト以上)
    // より小さくなり増幅攻撃に使われないこと (RFC 9000 Section 8.1)
    assert!(
        written < 1200,
        "応答が引き金になったパケットより小さいこと: {written}"
    );
    assert_ne!(buf[0] & 0x80, 0, "Long header form bit が立っていること");
}

/// トークンの種別を判定できること
#[test]
fn test_token_kind() {
    assert_eq!(
        token_kind(&[NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2 as u8, 1, 2]),
        Some(AddressValidationTokenKind::Retry),
        "Retry のマジックバイト"
    );
    assert_eq!(
        token_kind(&[NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR as u8, 1, 2]),
        Some(AddressValidationTokenKind::NewToken),
        "NEW_TOKEN のマジックバイト"
    );
    assert_eq!(token_kind(&[0x00, 1, 2]), None, "未知のマジックバイト");
    assert_eq!(token_kind(&[]), None, "空のトークン");
}
