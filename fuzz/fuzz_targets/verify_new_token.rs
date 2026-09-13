#![no_main]

//! NEW_TOKEN で配布したトークンの検証の fuzz ターゲット
//! (RFC 9000 Section 8.1.3)
//!
//! 有効なトークンを生成してから fuzz 入力で壊し、`verify_new_token` に通す。
//! ランダムなバイト列は必ず整合性検査で弾かれるため、この形にする。

use std::net::SocketAddr;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;

use shiguredo_ngtcp2::{RETRY_SECRET_LEN, RetrySecret, generate_new_token, verify_new_token};

/// 生成したトークンに fuzz 入力を重ねて壊す
///
/// 入力が尽きたら残りはそのままにする。入力が空の場合はトークンが生成したまま
/// になるため、検証に成功する経路も実行される (libFuzzer は空の入力から始める)。
fn corrupt(token: &[u8], data: &[u8]) -> Vec<u8> {
    let mut corrupted = token.to_vec();
    for (i, byte) in data.iter().enumerate() {
        match corrupted.get_mut(i) {
            Some(dst) => *dst ^= byte,
            // トークンより長い入力はトークンを伸ばし、長さの検査を対象にする
            None => corrupted.push(*byte),
        }
    }
    corrupted
}

fuzz_target!(|data: &[u8]| {
    // トークンに束縛される値は固定にする
    let secret = RetrySecret::from_bytes([0x42; RETRY_SECRET_LEN]);
    let client_addr: SocketAddr = "127.0.0.1:4433".parse().expect("valid address");

    let Ok(token) = generate_new_token(&secret, client_addr, 0) else {
        return;
    };
    let token = corrupt(token.as_bytes(), data);

    // 壊れたトークンは検証に失敗する (パニックしないこと)
    let _ = verify_new_token(&secret, &token, client_addr, Duration::from_secs(10), 0);
});
