#![no_main]

//! 書き出したバッファのパケット分割の fuzz ターゲット
//!
//! 任意のバイト列を `split_packets` に通し、パニックしないことと、分割の
//! 結果が入力と一致することを検証する。

use libfuzzer_sys::fuzz_target;

use shiguredo_ngtcp2::packet::split_packets;

fuzz_target!(|data: &[u8]| {
    let packets = split_packets(data);

    // 分割はパケットの境界を求めるだけなので、連結すると元のバッファに戻ること
    let total = packets.iter().map(|packet| packet.len()).sum::<usize>();
    assert_eq!(total, data.len(), "分割結果の合計長が入力長と一致すること");

    // 空のパケットを返すと、呼び出し側が 0 バイトの送信を繰り返すことになる
    for packet in &packets {
        assert!(!packet.is_empty(), "空のパケットが含まれないこと");
    }
});
