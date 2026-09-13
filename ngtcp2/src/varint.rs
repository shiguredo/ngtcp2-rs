//! QUIC 可変長整数 (RFC 9000 Section 16)
//!
//! 先頭 2 ビットで全長を表す方式を実装する。
//!
//! | 先頭 2 ビット | 全長 | 値の範囲 |
//! | --- | --- | --- |
//! | `00` | 1 バイト | 0 〜 63 |
//! | `01` | 2 バイト | 0 〜 16383 |
//! | `10` | 4 バイト | 0 〜 1073741823 |
//! | `11` | 8 バイト | 0 〜 4611686018427387903 |

/// 可変長整数が表現できる最大値 (2^62 - 1)
pub const MAX: u64 = (1 << 62) - 1;

/// 値をエンコードするのに必要なバイト数を返す (1 / 2 / 4 / 8)
///
/// `n` が `MAX` を超える場合も 8 を返すが、その値はエンコードできない。
pub fn encoded_len(n: u64) -> usize {
    if n < 64 {
        1
    } else if n < 16384 {
        2
    } else if n < 1073741824 {
        4
    } else {
        8
    }
}

/// 可変長整数を `buf` にエンコードする
///
/// `buf` は [`encoded_len`] バイト以上必要。書き込んだバイト数を返す。
///
/// # Panics
///
/// `buf` が `encoded_len(n)` バイトに満たない場合、または `n` が [`MAX`] を
/// 超える場合にパニックする。
pub fn encode(buf: &mut [u8], n: u64) -> usize {
    assert!(
        n <= MAX,
        "varint encode: value {n} exceeds the maximum {MAX}"
    );
    let len = encoded_len(n);
    assert!(
        buf.len() >= len,
        "varint encode: buffer too short (need {len}, got {})",
        buf.len()
    );

    match len {
        1 => {
            buf[0] = n as u8;
        }
        2 => {
            let v = (n as u16 | 0x4000).to_be_bytes();
            buf[..2].copy_from_slice(&v);
        }
        4 => {
            let v = (n as u32 | 0x8000_0000).to_be_bytes();
            buf[..4].copy_from_slice(&v);
        }
        _ => {
            let v = (n | 0xc000_0000_0000_0000).to_be_bytes();
            buf[..8].copy_from_slice(&v);
        }
    }

    len
}

/// 可変長整数を `Vec<u8>` に追記する
///
/// # Panics
///
/// `n` が [`MAX`] を超える場合にパニックする。
pub fn encode_to_vec(n: u64, buf: &mut Vec<u8>) {
    let len = encoded_len(n);
    let start = buf.len();
    buf.resize(start + len, 0);
    encode(&mut buf[start..], n);
}

/// 可変長整数をデコードする
///
/// 成功時は `(値, 消費バイト数)` を返す。
/// `buf` が空、または先頭 2 ビットが示す長さに満たない場合は `None` を返す。
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);

    if buf.len() < len {
        return None;
    }

    let value = match len {
        1 => first as u64,
        2 => {
            let v = u16::from_be_bytes([buf[0], buf[1]]);
            (v & 0x3fff) as u64
        }
        4 => {
            let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            (v & 0x3fff_ffff) as u64
        }
        _ => {
            let v = u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            v & 0x3fff_ffff_ffff_ffff
        }
    };

    Some((value, len))
}
