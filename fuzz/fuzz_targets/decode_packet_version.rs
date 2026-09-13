#![no_main]

//! Long header パケットからのバージョンとコネクション ID の取り出しの fuzz ターゲット
//!
//! 任意のバイト列を `decode_packet_version` に通し、パニックしないことを検証する。
//! ngtcp2 のパケット解析は C 側にあるため、ここで検証できるのは Rust 側の
//! ラッパー (CID の長さの扱いとエラー変換) になる。

use libfuzzer_sys::fuzz_target;

use shiguredo_ngtcp2::{NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2, decode_packet_version};

fuzz_target!(|data: &[u8]| {
    let Some(packet_version) = decode_packet_version(data) else {
        return;
    };

    // Version Negotiation パケット (バージョン 0) は返らない。
    // バージョン 0 に Version Negotiation を返してはいけない (RFC 9000 Section 6)
    assert_ne!(packet_version.version, 0, "バージョン 0 は返らないこと");

    // 種別を判定できた場合はサポートしているバージョンであること。
    // 種別ビットの意味はバージョンごとに異なる (RFC 9369 Section 3.2)
    if packet_version.header_type.is_some() {
        assert!(
            matches!(
                packet_version.version,
                NGTCP2_PROTO_VER_V1 | NGTCP2_PROTO_VER_V2
            ),
            "種別を判定できた場合はサポートしているバージョンであること"
        );
    }
});
