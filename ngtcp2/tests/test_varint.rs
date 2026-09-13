//! 可変長整数の統合テスト (RFC 9000 Section 16)
//!
//! 境界値の長さ・ワイヤーフォーマット・ラウンドトリップを検証する。

use shiguredo_ngtcp2::varint::{self, MAX};

/// 境界値が正しい長さにエンコードされること
#[test]
fn test_encoded_len_boundaries() {
    assert_eq!(varint::encoded_len(0), 1);
    assert_eq!(varint::encoded_len(63), 1);
    assert_eq!(varint::encoded_len(64), 2);
    assert_eq!(varint::encoded_len(16383), 2);
    assert_eq!(varint::encoded_len(16384), 4);
    assert_eq!(varint::encoded_len(1073741823), 4);
    assert_eq!(varint::encoded_len(1073741824), 8);
    assert_eq!(varint::encoded_len(MAX), 8);
}

/// 全ての境界値でラウンドトリップすること
#[test]
fn test_varint_roundtrip() {
    for value in [0u64, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, MAX] {
        let mut buf = Vec::new();
        varint::encode_to_vec(value, &mut buf);
        assert_eq!(
            buf.len(),
            varint::encoded_len(value),
            "エンコード長: {value}"
        );

        let (decoded, consumed) = varint::decode(&buf).expect("デコードに成功するべき");
        assert_eq!(decoded, value, "ラウンドトリップ: {value}");
        assert_eq!(consumed, buf.len(), "消費バイト数: {value}");
    }
}

/// 固定長バッファへのエンコードが書き込みバイト数を返すこと
#[test]
fn test_varint_encode_into_slice() {
    let mut buf = [0u8; 8];
    let written = varint::encode(&mut buf, 15293);
    assert_eq!(written, 2, "書き込んだバイト数");
    assert_eq!(&buf[..2], &[0x7b, 0xbd], "ワイヤーフォーマット");
}

/// 続けてエンコードした値を順にデコードできること
#[test]
fn test_varint_sequential_decode() {
    let mut buf = Vec::new();
    varint::encode_to_vec(37, &mut buf);
    varint::encode_to_vec(1_000_000, &mut buf);
    varint::encode_to_vec(MAX, &mut buf);

    let (v1, n1) = varint::decode(&buf).expect("デコードに成功するべき");
    assert_eq!(v1, 37);
    let (v2, n2) = varint::decode(&buf[n1..]).expect("デコードに成功するべき");
    assert_eq!(v2, 1_000_000);
    let (v3, n3) = varint::decode(&buf[n1 + n2..]).expect("デコードに成功するべき");
    assert_eq!(v3, MAX);
    assert_eq!(n1 + n2 + n3, buf.len(), "全てのバイトを消費すること");
}

/// 空入力は None を返すこと
#[test]
fn test_varint_decode_empty() {
    assert!(varint::decode(&[]).is_none(), "空入力は None");
}

/// 必要な長さに満たない入力は None を返すこと
#[test]
fn test_varint_decode_truncated() {
    // 2 バイト必要なのに 1 バイトしかない
    assert!(
        varint::decode(&[0x40]).is_none(),
        "2 バイト必要な入力の切り詰め"
    );
    // 4 バイト必要なのに 3 バイトしかない
    assert!(
        varint::decode(&[0x80, 0x00, 0x00]).is_none(),
        "4 バイト必要な入力の切り詰め"
    );
    // 8 バイト必要なのに 7 バイトしかない
    assert!(
        varint::decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_none(),
        "8 バイト必要な入力の切り詰め"
    );
}

/// RFC 9000 Section A.1 の例とワイヤーフォーマットが一致すること
#[test]
fn test_varint_wire_format() {
    let cases: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (37, &[0x25]),
        (15293, &[0x7b, 0xbd]),
        (494878333, &[0x9d, 0x7f, 0x3e, 0x7d]),
        (
            151288809941952652,
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
        ),
    ];

    for (value, expected) in cases {
        let mut buf = Vec::new();
        varint::encode_to_vec(*value, &mut buf);
        assert_eq!(&buf[..], *expected, "ワイヤーフォーマット: {value}");

        let (decoded, consumed) = varint::decode(expected).expect("デコードに成功するべき");
        assert_eq!(decoded, *value, "デコード結果: {value}");
        assert_eq!(consumed, expected.len(), "消費バイト数: {value}");
    }
}

/// 先頭 2 ビット以外の値が正しく取り出されること
#[test]
fn test_varint_decode_ignores_length_prefix() {
    // 2 バイト形式で表現できる最大値 (16383)
    assert_eq!(
        varint::decode(&[0x7f, 0xff]),
        Some((16383, 2)),
        "2 バイトの最大値"
    );
    // 4 バイト形式で表現できる最大値 (1073741823)
    assert_eq!(
        varint::decode(&[0xbf, 0xff, 0xff, 0xff]),
        Some((1073741823, 4)),
        "4 バイトの最大値"
    );
    // 8 バイト形式で表現できる最大値 (2^62 - 1)
    assert_eq!(
        varint::decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        Some((MAX, 8)),
        "8 バイトの最大値"
    );
}
