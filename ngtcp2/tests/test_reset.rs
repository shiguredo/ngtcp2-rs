//! Stateless Reset の統合テスト (RFC 9000 Section 10.3)
//!
//! `StatelessResetSecret` と `write_stateless_reset` の公開 API を検証する。

use shiguredo_ngtcp2::{
    ConnectionId, Error, MIN_STATELESS_RESET_SIZE, STATELESS_RESET_SECRET_LEN,
    STATELESS_RESET_TOKEN_LEN, StatelessResetSecret, write_stateless_reset,
};

/// 秘密を生成できること
#[test]
fn test_secret_generate() {
    let a = StatelessResetSecret::generate().expect("秘密を生成できること");
    let b = StatelessResetSecret::generate().expect("秘密を生成できること");
    assert_ne!(a, b, "生成のたびに異なる秘密になること");
}

/// Debug 出力に秘密やトークンの中身が含まれないこと
#[test]
fn test_debug_redacts_secret_material() {
    let secret = StatelessResetSecret::from_bytes([0xab; STATELESS_RESET_SECRET_LEN]);
    let cid = ConnectionId::new(&[0x01; 8]).expect("CID を作れること");
    let token = secret.token(&cid).expect("トークンを導出できること");

    let secret_debug = format!("{secret:?}");
    assert!(
        !secret_debug.contains("ab"),
        "Debug 出力に秘密のバイト列を含めないこと: {secret_debug}"
    );

    let token_debug = format!("{token:?}");
    assert!(
        !token_debug
            .to_lowercase()
            .contains(&hex(&token.as_bytes()[..4])),
        "Debug 出力にトークンのバイト列を含めないこと: {token_debug}"
    );
}

/// バイト列を 16 進文字列にする (テストの期待値表示用)
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 同じ秘密と CID からは同じトークンが導出されること
///
/// これが成り立たないと、接続状態を失ったサーバーはピアが保持している
/// トークンを再現できない。
#[test]
fn test_token_is_deterministic() {
    let secret = StatelessResetSecret::from_bytes([0x11; STATELESS_RESET_SECRET_LEN]);
    let cid = ConnectionId::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        .expect("CID を作れること");

    let first = secret.token(&cid).expect("トークンを導出できること");
    let second = secret.token(&cid).expect("トークンを導出できること");
    assert_eq!(first, second, "同じ入力からは同じトークンになること");

    // CID が違えばトークンも違うこと
    let other_cid = ConnectionId::new(&[0x09; 8]).expect("CID を作れること");
    let other = secret.token(&other_cid).expect("トークンを導出できること");
    assert_ne!(first, other, "CID が違えばトークンも違うこと");

    // 秘密が違えばトークンも違うこと
    let other_secret = StatelessResetSecret::from_bytes([0x22; STATELESS_RESET_SECRET_LEN]);
    let other = other_secret.token(&cid).expect("トークンを導出できること");
    assert_ne!(first, other, "秘密が違えばトークンも違うこと");
}

/// Stateless Reset パケットが RFC 9000 Section 10.3.3 の形式で書けること
#[test]
fn test_write_stateless_reset_packet() {
    let secret = StatelessResetSecret::from_bytes([0x33; STATELESS_RESET_SECRET_LEN]);
    let cid = ConnectionId::new(&[0x0a; 16]).expect("CID を作れること");
    let token = secret.token(&cid).expect("トークンを導出できること");

    let mut buf = [0u8; 1200];
    let written = write_stateless_reset(&mut buf, &token, 1200).expect("書き出せること");

    // 末尾 16 バイトがトークンであること
    assert!(
        written > STATELESS_RESET_TOKEN_LEN,
        "トークンより長いパケットであること: {written}"
    );
    assert_eq!(
        &buf[written - STATELESS_RESET_TOKEN_LEN..written],
        token.as_bytes(),
        "末尾にトークンが入ること"
    );

    // Short header 形式: 先頭 2 ビットが 01 (RFC 9000 Section 10.3.3)
    assert_eq!(buf[0] >> 6, 0b01, "先頭 2 ビットが 01 であること");

    // 引き金になったパケットより長くないこと
    assert!(
        written <= 1200,
        "応答は元のパケットより長くしないこと: {written}"
    );
}

/// 元のパケットが短ければそれより短い応答になること (RFC 9000 Section 10.3.3)
#[test]
fn test_write_stateless_reset_is_shorter_than_trigger() {
    let secret = StatelessResetSecret::from_bytes([0x44; STATELESS_RESET_SECRET_LEN]);
    let cid = ConnectionId::new(&[0x0b; 16]).expect("CID を作れること");
    let token = secret.token(&cid).expect("トークンを導出できること");

    let mut buf = [0u8; 1200];
    for received_len in [MIN_STATELESS_RESET_SIZE, 30, 43, 100] {
        let written = write_stateless_reset(&mut buf, &token, received_len)
            .unwrap_or_else(|e| panic!("{received_len} バイトで書き出せること: {e}"));
        assert!(written > 0, "{received_len} バイトなら応答できること");
        assert!(
            written <= received_len,
            "応答 ({written}) が元のパケット ({received_len}) より長くないこと"
        );
    }
}

/// 短すぎるパケットには応答しないこと (RFC 9000 Section 10.3.3)
#[test]
fn test_write_stateless_reset_rejects_short_packet() {
    let secret = StatelessResetSecret::from_bytes([0x55; STATELESS_RESET_SECRET_LEN]);
    let cid = ConnectionId::new(&[0x0c; 16]).expect("CID を作れること");
    let token = secret.token(&cid).expect("トークンを導出できること");

    let mut buf = [0u8; 1200];
    for received_len in [0, 1, 21, MIN_STATELESS_RESET_SIZE - 1] {
        let written = write_stateless_reset(&mut buf, &token, received_len)
            .expect("短すぎるパケットはエラーではなく 0 を返すこと");
        assert_eq!(
            written, 0,
            "{received_len} バイトのパケットには応答しないこと"
        );
    }
}

/// バッファが足りない場合はエラーになること
#[test]
fn test_write_stateless_reset_rejects_small_buffer() {
    let secret = StatelessResetSecret::from_bytes([0x66; STATELESS_RESET_SECRET_LEN]);
    let cid = ConnectionId::new(&[0x0d; 16]).expect("CID を作れること");
    let token = secret.token(&cid).expect("トークンを導出できること");

    let mut buf = [0u8; 8];
    let err =
        write_stateless_reset(&mut buf, &token, 1200).expect_err("バッファ不足はエラーになること");
    assert!(
        matches!(err, Error::Ngtcp2(_, _)),
        "ngtcp2 のエラーが返ること: {err:?}"
    );
}
