//! バージョン解析と Version Negotiation のテスト
//!
//! `decode_packet_version` / `write_version_negotiation` / `QuicVersion` の
//! 公開 API を検証する。

use shiguredo_ngtcp2::{
    ConnectionId, LongHeaderType, MIN_INITIAL_DATAGRAM_SIZE, NGTCP2_PROTO_VER_V1,
    NGTCP2_PROTO_VER_V2, QuicVersion, decode_packet_version, long_header_type,
    write_version_negotiation,
};

/// テストでサポート対象とする QUIC バージョン
const SUPPORTED: [QuicVersion; 2] = [QuicVersion::V1, QuicVersion::V2];

/// Initial パケットの先頭バイトを返す
///
/// 種別ビットは QUIC バージョンごとに異なり、Initial は v1 が 0x0
/// (RFC 9000 Section 17.2)、v2 が 0x1 (RFC 9369 Section 3.2)。
/// 先頭バイトは Header Form(1) + Fixed Bit(1) + Long Packet Type(2) + 予約(4)。
fn initial_first_byte(version: u32) -> u8 {
    let type_bits = if version == NGTCP2_PROTO_VER_V2 {
        0x1
    } else {
        0x0
    };
    0x80 | 0x40 | (type_bits << 4)
}

/// Long header パケットを組み立てる
///
/// RFC 9000 Section 17.2 の先頭部分だけを埋める。Version Negotiation の
/// 判定と CID の抽出にはそれ以降の内容は使われないため、残りはゼロ埋め。
fn make_long_header(
    version: u32,
    first_byte: u8,
    dcid: &[u8],
    scid: &[u8],
    total_len: usize,
) -> Vec<u8> {
    let mut data = vec![0u8; total_len];
    data[0] = first_byte;
    data[1..5].copy_from_slice(&version.to_be_bytes());
    data[5] = dcid.len() as u8;
    data[6..6 + dcid.len()].copy_from_slice(dcid);
    let scid_offset = 6 + dcid.len();
    data[scid_offset] = scid.len() as u8;
    data[scid_offset + 1..scid_offset + 1 + scid.len()].copy_from_slice(scid);
    data
}

/// 十分な大きさの Initial を組み立てる
fn make_initial(version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    make_long_header(
        version,
        initial_first_byte(version),
        dcid,
        scid,
        MIN_INITIAL_DATAGRAM_SIZE,
    )
}

/// `QuicVersion` がワイヤーフォーマットの値と相互に変換できること
#[test]
fn test_quic_version_roundtrip() {
    assert_eq!(QuicVersion::V1.as_u32(), NGTCP2_PROTO_VER_V1, "v1 の値");
    assert_eq!(QuicVersion::V2.as_u32(), NGTCP2_PROTO_VER_V2, "v2 の値");
    assert_eq!(
        QuicVersion::from_u32(NGTCP2_PROTO_VER_V1),
        Some(QuicVersion::V1),
        "v1 に変換できること"
    );
    assert_eq!(
        QuicVersion::from_u32(NGTCP2_PROTO_VER_V2),
        Some(QuicVersion::V2),
        "v2 に変換できること"
    );
    // 未知のバージョンは変換できないこと
    assert_eq!(
        QuicVersion::from_u32(0xdead_beef),
        None,
        "未知のバージョンは None であること"
    );
}

/// QUIC v1 と v2 の Initial からバージョンと CID を取り出せること
#[test]
fn test_decode_packet_version_extracts_cids() {
    let dcid = [0x11u8; 8];
    let scid = [0x22u8; 16];

    for version in [QuicVersion::V1, QuicVersion::V2] {
        let data = make_initial(version.as_u32(), &dcid, &scid);
        let info = decode_packet_version(&data)
            .unwrap_or_else(|| panic!("{version:?} の Initial を解析できること"));

        assert_eq!(info.version, version.as_u32(), "バージョン");
        assert_eq!(info.dcid.as_bytes(), &dcid, "DCID");
        assert_eq!(info.scid.as_bytes(), &scid, "SCID");
    }
}

/// Short header はバージョンフィールドを持たないため解析できないこと
/// (RFC 9000 Section 17.3)
#[test]
fn test_decode_packet_version_rejects_short_header() {
    // 先頭バイトの最上位ビットが 0 の Short header
    let mut data = vec![0x40u8; MIN_INITIAL_DATAGRAM_SIZE];
    data[1] = 16;
    data[2..18].copy_from_slice(&[0xaa; 16]);

    assert!(
        decode_packet_version(&data).is_none(),
        "Short header は解析できないこと"
    );
}

/// Version Negotiation パケット (バージョン 0) には応答しないこと
///
/// RFC 9000 Section 6 により Version Negotiation に対して Version Negotiation を
/// 返してはいけないため、解析対象から外す。
#[test]
fn test_decode_packet_version_rejects_version_negotiation_packet() {
    let data = make_initial(0, &[0x11; 8], &[0x22; 8]);

    assert!(
        decode_packet_version(&data).is_none(),
        "バージョン 0 は解析できないこと"
    );
}

/// サポート外のバージョンでも 1200 バイト未満は解析できないこと
///
/// RFC 9000 Section 14.1 は 1200 バイト未満のデータグラムで運ばれた Initial の
/// 破棄を求めており、ngtcp2 も解析を拒否する。
#[test]
fn test_decode_packet_version_rejects_small_datagram_for_unknown_version() {
    let data = make_long_header(0xdead_beef, 0xc0, &[0x11; 8], &[0x22; 8], 100);

    assert!(
        decode_packet_version(&data).is_none(),
        "サポート外のバージョンで 1200 バイト未満は解析できないこと"
    );
}

/// サポートするバージョンでは 1200 バイト未満でも解析できること
///
/// 最小サイズの強制は RFC 9000 Section 14.1 の受信側の責務であり、
/// バージョンと CID の抽出自体は長さに依存しない。
#[test]
fn test_decode_packet_version_accepts_small_datagram_for_known_version() {
    let data = make_long_header(NGTCP2_PROTO_VER_V1, 0xc0, &[0x11; 8], &[0x22; 8], 100);

    let info = decode_packet_version(&data).expect("サポートするバージョンは解析できること");
    assert_eq!(info.version, NGTCP2_PROTO_VER_V1, "バージョン");
}

/// CID 長がヘッダーの宣言より長いパケットは解析できないこと
#[test]
fn test_decode_packet_version_rejects_truncated_cids() {
    // DCID 長を 200 と宣言しつつ実際は 1200 バイトに収まらない形にする
    let mut data = vec![0u8; 32];
    data[0] = 0xc0;
    data[1..5].copy_from_slice(&NGTCP2_PROTO_VER_V1.to_be_bytes());
    data[5] = 200;

    assert!(
        decode_packet_version(&data).is_none(),
        "途中で切れたパケットは解析できないこと"
    );
}

/// 空のデータグラムは解析できないこと
#[test]
fn test_decode_packet_version_rejects_empty() {
    assert!(
        decode_packet_version(&[]).is_none(),
        "空のデータは解析できないこと"
    );
}

/// Version Negotiation パケットの形式が RFC 9000 Section 17.2.1 に従うこと
///
/// クライアントの SCID が DCID に、クライアントの DCID が SCID に入れ替わり、
/// バージョンフィールドは 0、末尾にサポートするバージョンが並ぶ。
#[test]
fn test_write_version_negotiation_packet_format() {
    let client_dcid = ConnectionId::new(&[0x11; 8]).expect("DCID を作れること");
    let client_scid = ConnectionId::new(&[0x22; 16]).expect("SCID を作れること");

    let mut buf = [0u8; 1500];
    let written = write_version_negotiation(&mut buf, &client_scid, &client_dcid, &SUPPORTED)
        .expect("Version Negotiation を書き出せること");

    // Long header form bit が立ち、バージョンは 0 (RFC 9000 Section 17.2.1)
    assert_ne!(buf[0] & 0x80, 0, "Header Form が 1 であること");
    assert_eq!(&buf[1..5], &[0, 0, 0, 0], "バージョンが 0 であること");

    // DCID にはクライアントの SCID が入ること
    let dcid_len = buf[5] as usize;
    assert_eq!(dcid_len, client_scid.len(), "DCID 長");
    assert_eq!(
        &buf[6..6 + dcid_len],
        client_scid.as_bytes(),
        "DCID はクライアントの SCID であること"
    );

    // SCID にはクライアントの DCID が入ること
    let scid_offset = 6 + dcid_len;
    let scid_len = buf[scid_offset] as usize;
    assert_eq!(scid_len, client_dcid.len(), "SCID 長");
    assert_eq!(
        &buf[scid_offset + 1..scid_offset + 1 + scid_len],
        client_dcid.as_bytes(),
        "SCID はクライアントの DCID であること"
    );

    // 末尾にサポートするバージョンが 4 バイトずつ並ぶこと
    let mut versions = Vec::new();
    let mut pos = scid_offset + 1 + scid_len;
    while pos + 4 <= written {
        versions.push(u32::from_be_bytes([
            buf[pos],
            buf[pos + 1],
            buf[pos + 2],
            buf[pos + 3],
        ]));
        pos += 4;
    }
    assert_eq!(
        versions,
        vec![NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2],
        "サポートするバージョンが順に並ぶこと"
    );
    assert_eq!(pos, written, "余分なバイトが無いこと");
}

/// Version Negotiation を書き出したパケットを再び解析対象にしないこと
///
/// 書き出したパケットを [`decode_packet_version`] に渡すと `None` になり、
/// Version Negotiation の応答ループが起きないことを確認する。
#[test]
fn test_version_negotiation_packet_is_not_renegotiated() {
    let client_dcid = ConnectionId::new(&[0x11; 8]).expect("DCID を作れること");
    let client_scid = ConnectionId::new(&[0x22; 16]).expect("SCID を作れること");

    let mut buf = vec![0u8; MIN_INITIAL_DATAGRAM_SIZE];
    let written = write_version_negotiation(&mut buf, &client_scid, &client_dcid, &SUPPORTED)
        .expect("Version Negotiation を書き出せること");

    assert!(
        decode_packet_version(&buf[..written]).is_none(),
        "Version Negotiation パケットは解析対象外であること"
    );
}

/// サポートするバージョンが空の場合はエラーになること
#[test]
fn test_write_version_negotiation_rejects_empty_versions() {
    let client_dcid = ConnectionId::new(&[0x11; 8]).expect("DCID を作れること");
    let client_scid = ConnectionId::new(&[0x22; 16]).expect("SCID を作れること");

    let mut buf = [0u8; 1500];
    let err = write_version_negotiation(&mut buf, &client_scid, &client_dcid, &[])
        .expect_err("空のバージョン一覧は拒否されること");
    assert!(
        matches!(err, shiguredo_ngtcp2::Error::InvalidArgument(_)),
        "InvalidArgument が返ること: {err:?}"
    );
}

/// バッファが足りない場合はエラーになること
#[test]
fn test_write_version_negotiation_rejects_small_buffer() {
    let client_dcid = ConnectionId::new(&[0x11; 8]).expect("DCID を作れること");
    let client_scid = ConnectionId::new(&[0x22; 16]).expect("SCID を作れること");

    // ヘッダー (7 バイト) + DCID + SCID + バージョン 2 つ (8 バイト) に足りない
    let mut buf = [0u8; 8];
    let err = write_version_negotiation(&mut buf, &client_scid, &client_dcid, &SUPPORTED)
        .expect_err("バッファ不足はエラーになること");
    assert!(
        matches!(err, shiguredo_ngtcp2::Error::Ngtcp2(_, _)),
        "ngtcp2 のエラーが返ること: {err:?}"
    );
}

/// Long header の種別ビットがバージョンごとに異なること
///
/// v1 は RFC 9000 Section 17.2、v2 は RFC 9369 Section 3.2 が定める。
/// 同じ先頭バイトでもバージョンが違えば別のパケット種別になるため、
/// バージョンを見ずに判定してはいけない。
#[test]
fn test_long_header_type_is_version_dependent() {
    // RFC 9000 Section 17.2: Initial=0x0, 0-RTT=0x1, Handshake=0x2, Retry=0x3
    assert_eq!(
        long_header_type(NGTCP2_PROTO_VER_V1, 0xc0),
        Some(LongHeaderType::Initial),
        "v1 の 0xC0 は Initial"
    );
    assert_eq!(
        long_header_type(NGTCP2_PROTO_VER_V1, 0xd0),
        Some(LongHeaderType::ZeroRtt),
        "v1 の 0xD0 は 0-RTT"
    );
    assert_eq!(
        long_header_type(NGTCP2_PROTO_VER_V1, 0xe0),
        Some(LongHeaderType::Handshake),
        "v1 の 0xE0 は Handshake"
    );
    assert_eq!(
        long_header_type(NGTCP2_PROTO_VER_V1, 0xf0),
        Some(LongHeaderType::Retry),
        "v1 の 0xF0 は Retry"
    );

    // RFC 9369 Section 3.2: Initial=0x1, 0-RTT=0x2, Handshake=0x3, Retry=0x0
    assert_eq!(
        long_header_type(NGTCP2_PROTO_VER_V2, 0xd0),
        Some(LongHeaderType::Initial),
        "v2 の 0xD0 は Initial"
    );
    assert_eq!(
        long_header_type(NGTCP2_PROTO_VER_V2, 0xe0),
        Some(LongHeaderType::ZeroRtt),
        "v2 の 0xE0 は 0-RTT"
    );
    assert_eq!(
        long_header_type(NGTCP2_PROTO_VER_V2, 0xf0),
        Some(LongHeaderType::Handshake),
        "v2 の 0xF0 は Handshake"
    );
    assert_eq!(
        long_header_type(NGTCP2_PROTO_VER_V2, 0xc0),
        Some(LongHeaderType::Retry),
        "v2 の 0xC0 は Retry"
    );

    // v1 と v2 で同じ先頭バイトが別の種別になること
    assert_ne!(
        long_header_type(NGTCP2_PROTO_VER_V1, 0xd0),
        long_header_type(NGTCP2_PROTO_VER_V2, 0xd0),
        "0xD0 は v1 では 0-RTT、v2 では Initial"
    );
}

/// 未知のバージョンと Version Negotiation では種別を判定できないこと
///
/// サポートしていないバージョンではヘッダーの解釈が異なる可能性があり
/// (RFC 9000 Section 6)、Version Negotiation パケットは種別ビットが
/// ランダム (RFC 9000 Section 17.2.1) ため判定できない。
#[test]
fn test_long_header_type_rejects_unknown_version() {
    assert_eq!(
        long_header_type(0xdead_beef, 0xc0),
        None,
        "未知のバージョンは判定できないこと"
    );
    assert_eq!(
        long_header_type(0, 0xc0),
        None,
        "Version Negotiation (バージョン 0) は判定できないこと"
    );
}

/// 解析したパケットの種別がバージョンに従って決まること
#[test]
fn test_decode_packet_version_sets_header_type() {
    let dcid = [0x11u8; 8];
    let scid = [0x22u8; 8];

    // v2 の Initial (先頭バイト 0xD0)
    let data = make_initial(NGTCP2_PROTO_VER_V2, &dcid, &scid);
    assert_eq!(data[0], 0xd0, "v2 の Initial の先頭バイト");
    let info = decode_packet_version(&data).expect("v2 の Initial を解析できること");
    assert!(info.is_initial(), "v2 の 0xD0 は Initial であること");

    // 同じ先頭バイトを v1 として扱うと 0-RTT になる
    let mut data = make_initial(NGTCP2_PROTO_VER_V1, &dcid, &scid);
    data[0] = 0xd0;
    let info = decode_packet_version(&data).expect("v1 の Long header を解析できること");
    assert!(!info.is_initial(), "v1 の 0xD0 は Initial ではないこと");
    assert_eq!(
        info.header_type,
        Some(LongHeaderType::ZeroRtt),
        "v1 の 0xD0 は 0-RTT であること"
    );

    // 未知のバージョンでは種別を判定できないこと
    let data = make_initial(0xdead_beef, &dcid, &scid);
    let info = decode_packet_version(&data).expect("未知のバージョンでも CID は取り出せること");
    assert_eq!(
        info.header_type, None,
        "未知のバージョンは種別不明であること"
    );
    assert!(!info.is_initial(), "種別不明なら Initial 扱いしないこと");
}
