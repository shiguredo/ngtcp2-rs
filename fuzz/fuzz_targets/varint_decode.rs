#![no_main]

//! QUIC 可変長整数のデコードの fuzz ターゲット (RFC 9000 Section 16)
//!
//! 任意のバイト列を `varint::decode` に通し、パニックしないことと、デコードした
//! 値をエンコードし直すと元に戻ることを検証する。

use libfuzzer_sys::fuzz_target;

use shiguredo_ngtcp2::varint;

fuzz_target!(|data: &[u8]| {
    let Some((value, len)) = varint::decode(data) else {
        return;
    };

    // 消費バイト数は先頭 2 ビットが示す 1 / 2 / 4 / 8 のいずれか
    assert!(
        matches!(len, 1 | 2 | 4 | 8),
        "消費バイト数が 1 / 2 / 4 / 8 のいずれかであること"
    );
    assert!(len <= data.len(), "消費バイト数が入力長以下であること");
    assert!(value <= varint::MAX, "値が可変長整数の最大値以下であること");

    // デコードした値をエンコードし直すと、同じ値と同じバイト数に戻ること
    let mut buf = Vec::new();
    varint::encode_to_vec(value, &mut buf);
    assert_eq!(
        buf.len(),
        varint::encoded_len(value),
        "エンコードに必要なバイト数であること"
    );
    assert_eq!(
        varint::decode(&buf),
        Some((value, buf.len())),
        "エンコード結果をデコードすると元に戻ること"
    );
});
