//! 基本型の統合テスト
//!
//! `ConnectionId` / `StreamType` / `StreamDirection` / `QuicVersion` /
//! `PacketInfo` / `PathInfo` の公開 API を検証する。

use std::net::SocketAddr;

use shiguredo_ngtcp2::{
    ConnectionId, NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2, PacketInfo, PathInfo, QuicVersion,
    StreamDirection, StreamType,
};

/// コネクション ID が長さの範囲内で作成できること
#[test]
fn test_connection_id_new() {
    // 1 バイト (最小)
    let cid = ConnectionId::new(&[1]).expect("1 バイトの CID が作成できること");
    assert_eq!(cid.len(), 1, "CID 長");
    assert_eq!(cid.as_bytes(), &[1], "CID の内容");
    assert!(!cid.is_empty(), "1 バイトの CID は空ではない");

    // 20 バイト (最大)
    let cid = ConnectionId::new(&[0xab; 20]).expect("20 バイトの CID が作成できること");
    assert_eq!(cid.len(), 20, "CID 長");
}

/// 長さ 0 のコネクション ID を作成できること (RFC 9000 Section 5.1)
///
/// パケットから読んだコネクション ID は長さ 0 になりうる。長さ 0 の
/// コネクション ID を使うエンドポイントは、パケットをアドレスで振り分ける。
#[test]
fn test_connection_id_empty() {
    let cid = ConnectionId::new(&[]).expect("0 バイトの CID が作成できること");
    assert_eq!(cid.len(), 0, "CID 長");
    assert!(cid.is_empty(), "0 バイトの CID は空である");
    assert_eq!(ConnectionId::empty(), cid, "empty と同じであること");
}

/// 20 バイトを超えるコネクション ID は作成できないこと
#[test]
fn test_connection_id_new_rejects_too_long() {
    assert!(
        ConnectionId::new(&[0u8; 21]).is_none(),
        "21 バイトは拒否されること"
    );
}

/// ランダムなコネクション ID が生成できること
#[test]
fn test_connection_id_random() {
    let cid = ConnectionId::random(16).expect("16 バイトの CID が生成できること");
    assert_eq!(cid.len(), 16, "CID 長");

    // 2 回生成して異なる値になること (乱数が機能していることの確認)
    let other = ConnectionId::random(16).expect("CID が生成できること");
    assert_ne!(cid, other, "毎回異なる CID が生成されること");

    assert!(
        ConnectionId::random(0).is_none(),
        "0 バイトは拒否されること"
    );
    assert!(
        ConnectionId::random(21).is_none(),
        "21 バイトは拒否されること"
    );
}

/// コネクション ID が等価比較とハッシュの対象になること
#[test]
fn test_connection_id_equality() {
    let a = ConnectionId::new(&[1, 2, 3]).expect("test must succeed");
    let b = ConnectionId::new(&[1, 2, 3]).expect("test must succeed");
    let c = ConnectionId::new(&[1, 2, 4]).expect("test must succeed");

    assert_eq!(a, b, "同じバイト列の CID は等しいこと");
    assert_ne!(a, c, "異なるバイト列の CID は等しくないこと");

    // HashMap のキーとして使えること (Eq + Hash が実装されていること)
    let mut map = std::collections::HashMap::new();
    map.insert(a, "first");
    assert_eq!(map.get(&b), Some(&"first"), "ハッシュで引けること");
}

/// コネクション ID の Debug / Display が 16 進数表記になること
#[test]
fn test_connection_id_format() {
    let cid = ConnectionId::new(&[0x0a, 0x1b, 0xff]).expect("test must succeed");
    assert_eq!(format!("{}", cid), "0a1bff", "Display は 16 進数");
    assert_eq!(format!("{:?}", cid), "ConnectionId(0a1bff)", "Debug の表記");
}

/// ストリーム ID からタイプが正しく判定されること (RFC 9000 Section 2.1)
#[test]
fn test_stream_type_from_stream_id() {
    // bit 1 が 0 なら双方向
    assert_eq!(StreamType::from_stream_id(0), StreamType::Bidirectional);
    assert_eq!(StreamType::from_stream_id(1), StreamType::Bidirectional);
    assert_eq!(StreamType::from_stream_id(4), StreamType::Bidirectional);

    // bit 1 が 1 なら単方向
    assert_eq!(StreamType::from_stream_id(2), StreamType::Unidirectional);
    assert_eq!(StreamType::from_stream_id(3), StreamType::Unidirectional);
    assert_eq!(StreamType::from_stream_id(6), StreamType::Unidirectional);
}

/// ストリーム ID から方向が正しく判定されること (RFC 9000 Section 2.1)
#[test]
fn test_stream_direction_from_stream_id() {
    // bit 0 が 0 ならクライアント開始
    assert_eq!(
        StreamDirection::from_stream_id(0),
        StreamDirection::ClientInitiated
    );
    assert_eq!(
        StreamDirection::from_stream_id(2),
        StreamDirection::ClientInitiated
    );

    // bit 0 が 1 ならサーバー開始
    assert_eq!(
        StreamDirection::from_stream_id(1),
        StreamDirection::ServerInitiated
    );
    assert_eq!(
        StreamDirection::from_stream_id(3),
        StreamDirection::ServerInitiated
    );
}

/// QUIC バージョン定数が RFC の値と一致すること
#[test]
fn test_quic_version_constants() {
    // RFC 9000 Section 15: QUIC v1 は 0x00000001
    assert_eq!(NGTCP2_PROTO_VER_V1, 0x00000001, "QUIC v1");
    // RFC 9369 Section 3: QUIC v2 は 0x6b3343cf
    assert_eq!(NGTCP2_PROTO_VER_V2, 0x6b3343cf, "QUIC v2");
}

/// QUIC バージョンが定数と相互変換できること
#[test]
fn test_quic_version_conversion() {
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
    assert_eq!(
        QuicVersion::from_u32(0xdeadbeef),
        None,
        "未知のバージョンは None になること"
    );

    assert_eq!(
        QuicVersion::default(),
        QuicVersion::V1,
        "デフォルトは v1 であること"
    );
    assert_eq!(QuicVersion::V1 as u32, NGTCP2_PROTO_VER_V1, "V1 の値");
    assert_eq!(QuicVersion::V2 as u32, NGTCP2_PROTO_VER_V2, "V2 の値");
}

/// パケット情報のデフォルト値が ECN 未設定であること
#[test]
fn test_packet_info_default() {
    let info = PacketInfo::default();
    assert_eq!(info.ecn, 0, "ECN のデフォルトは 0 (Not-ECT)");

    let info = PacketInfo { ecn: 3 };
    assert_eq!(info.ecn, 3, "ECN を設定できること");
}

/// パス情報がローカルとリモートのアドレスを保持すること
#[test]
fn test_path_info() {
    let local: SocketAddr = "127.0.0.1:50000".parse().expect("test must succeed");
    let remote: SocketAddr = "127.0.0.1:4433".parse().expect("test must succeed");
    let path = PathInfo { local, remote };

    assert_eq!(path.local, local, "ローカルアドレス");
    assert_eq!(path.remote, remote, "リモートアドレス");
}
