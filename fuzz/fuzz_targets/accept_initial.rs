#![no_main]

//! 新規接続の Initial パケットの受理判定の fuzz ターゲット
//!
//! 任意のバイト列を `accept_initial` に通し、パニックしないことと、受理した
//! パケットが RFC 9000 の要件を満たしていることを検証する。

use libfuzzer_sys::fuzz_target;

use shiguredo_ngtcp2::{
    MIN_INITIAL_DATAGRAM_SIZE, MIN_INITIAL_DCIDLEN, NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2,
    accept_initial,
};

fuzz_target!(|data: &[u8]| {
    let Some(initial) = accept_initial(data) else {
        return;
    };

    // 受理するのはサポートしているバージョンの Initial だけ (RFC 9000 Section 6)
    assert!(
        matches!(initial.version, NGTCP2_PROTO_VER_V1 | NGTCP2_PROTO_VER_V2),
        "受理するバージョンがサポートしているものであること"
    );

    // Initial を含むデータグラムは 1200 バイト以上でなければならない
    // (RFC 9000 Section 14.1)
    assert!(
        data.len() >= MIN_INITIAL_DATAGRAM_SIZE,
        "受理したデータグラムが 1200 バイト以上であること"
    );

    // トークンが無い場合、クライアントの DCID は 8 バイト以上でなければ
    // ならない (RFC 9000 Section 7.2)
    if initial.token.is_empty() {
        assert!(
            initial.dcid.len() >= MIN_INITIAL_DCIDLEN,
            "トークンが無い場合の DCID が 8 バイト以上であること"
        );
    }
});
