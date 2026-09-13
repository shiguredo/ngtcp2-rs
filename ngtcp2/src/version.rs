//! QUIC バージョンの解析と Version Negotiation (RFC 9000 Section 6)
//!
//! サーバーはサポートしていないバージョンの Long header パケットを受け取った
//! とき、Version Negotiation パケットで自分がサポートするバージョンを返す。
//! サポートしていないバージョンではヘッダーのレイアウトが RFC 9000 と
//! 異なる可能性があるため、解析は自前で行わず ngtcp2 の
//! `ngtcp2_pkt_decode_version_cid` に任せる。

use shiguredo_ngtcp2_sys::*;

use crate::error::{Error, Result};
use crate::types::{ConnectionId, NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2, QuicVersion};

/// Long header パケットの種別
///
/// 種別を表す 2 ビットの値は QUIC バージョンごとに異なる。v1 は
/// RFC 9000 Section 17.2、v2 は RFC 9369 Section 3.2 が定める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongHeaderType {
    /// Initial パケット
    Initial,
    /// 0-RTT パケット
    ZeroRtt,
    /// Handshake パケット
    Handshake,
    /// Retry パケット
    Retry,
}

/// Long header パケットの種別を判定する
///
/// `first_byte` はパケットの先頭バイト、`version` はバージョンフィールドの値。
///
/// サポートしていないバージョンではヘッダーの解釈が異なる可能性があるため
/// `None` を返す (RFC 9000 Section 6)。Version Negotiation パケット
/// (バージョン 0) も先頭バイトの種別ビットがランダムなので `None` になる。
pub fn long_header_type(version: u32, first_byte: u8) -> Option<LongHeaderType> {
    // 先頭バイトの内訳: Header Form(1) + Fixed Bit(1) + Long Packet Type(2) + 予約(4)
    let bits = (first_byte >> 4) & 0x3;

    let kind = match version {
        // RFC 9000 Section 17.2: Initial=0x0, 0-RTT=0x1, Handshake=0x2, Retry=0x3
        NGTCP2_PROTO_VER_V1 => match bits {
            0x0 => LongHeaderType::Initial,
            0x1 => LongHeaderType::ZeroRtt,
            0x2 => LongHeaderType::Handshake,
            _ => LongHeaderType::Retry,
        },
        // RFC 9369 Section 3.2: Initial=0x1, 0-RTT=0x2, Handshake=0x3, Retry=0x0
        NGTCP2_PROTO_VER_V2 => match bits {
            0x1 => LongHeaderType::Initial,
            0x2 => LongHeaderType::ZeroRtt,
            0x3 => LongHeaderType::Handshake,
            _ => LongHeaderType::Retry,
        },
        // 未知のバージョンでは種別を判定できない
        _ => return None,
    };

    Some(kind)
}

/// Long header パケットから取り出したバージョンとコネクション ID
///
/// [`decode_packet_version`] が返す。Version Negotiation パケットを書くために
/// 必要な情報だけを保持する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketVersion {
    /// バージョンフィールドの生の値
    ///
    /// サポートしていないバージョンの可能性があるため [`QuicVersion`] には
    /// 変換せずに生の値で保持する。
    pub version: u32,
    /// パケットの Destination Connection ID
    ///
    /// Version Negotiation パケットでは Source Connection ID になる
    /// (RFC 9000 Section 17.2.1)。
    pub dcid: ConnectionId,
    /// パケットの Source Connection ID
    ///
    /// Version Negotiation パケットでは Destination Connection ID になる
    /// (RFC 9000 Section 17.2.1)。
    pub scid: ConnectionId,
    /// Long header パケットの種別
    ///
    /// 種別ビットの意味はバージョンごとに異なるため
    /// ([`long_header_type`] を参照)、サポートしていないバージョンでは
    /// 判定できず `None` になる。
    pub header_type: Option<LongHeaderType>,
}

impl PacketVersion {
    /// Initial パケットかどうかを返す
    ///
    /// サポートしていないバージョンでは種別を判定できないため false になる。
    pub fn is_initial(&self) -> bool {
        self.header_type == Some(LongHeaderType::Initial)
    }
}

/// Long header パケットからバージョンとコネクション ID を取り出す
///
/// サポートしていないバージョンのパケットに対しても動作する
/// (RFC 9000 Section 6)。
///
/// 以下の場合に `None` を返す:
///
/// - Short header パケット (バージョンフィールドを持たない)
/// - Version Negotiation パケット (バージョン 0。応答してはいけない)
/// - パースできないパケット (短すぎる、CID 長が不正)
/// - サポートしていないバージョンで、データグラムが
///   [`crate::MIN_INITIAL_DATAGRAM_SIZE`] 未満。RFC 9000 Section 14.1 の
///   破棄要件に合わせるため ngtcp2 が拒否する
/// - CID がゼロ長、または [`ConnectionId`] の許容長 (20 バイト) を超える。
///   本クレートはゼロ長のコネクション ID をサポートしない
pub fn decode_packet_version(data: &[u8]) -> Option<PacketVersion> {
    // Short header はバージョンフィールドを持たないため対象外
    // (RFC 9000 Section 17.3)
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return None;
    }

    let mut raw: ngtcp2_version_cid =
        // SAFETY: ngtcp2_version_cid はポインタと整数の集合で、
        // すべてのビットパターンが有効な POD
        unsafe { std::mem::zeroed() };

    // SAFETY: raw は書き込み可能な領域。data は呼び出し中のみ有効で、
    // ngtcp2 は解析中だけ参照する。short_dcidlen は Short header 専用の
    // 引数だが、Short header は上で除外しているため 0 を渡す。
    let rv = unsafe { ngtcp2_pkt_decode_version_cid(&mut raw, data.as_ptr(), data.len(), 0) };

    // NGTCP2_ERR_VERSION_NEGOTIATION の場合も全てのフィールドは埋まる
    // (ngtcp2_pkt_decode_version_cid のドキュメント参照)
    if rv != 0 && rv != NGTCP2_ERR_VERSION_NEGOTIATION {
        return None;
    }
    // Version Negotiation パケットに対して Version Negotiation を返してはいけない
    // (RFC 9000 Section 6)
    if raw.version == 0 || raw.dcid.is_null() || raw.scid.is_null() {
        return None;
    }

    // SAFETY: dcid / scid は data の中を指す有効な領域で、長さは
    // ngtcp2 がパケットから読み取った値
    let (dcid_bytes, scid_bytes) = unsafe {
        (
            std::slice::from_raw_parts(raw.dcid, raw.dcidlen),
            std::slice::from_raw_parts(raw.scid, raw.scidlen),
        )
    };

    Some(PacketVersion {
        version: raw.version,
        dcid: ConnectionId::new(dcid_bytes)?,
        scid: ConnectionId::new(scid_bytes)?,
        header_type: long_header_type(raw.version, first),
    })
}

/// Version Negotiation パケットを書き出す (RFC 9000 Section 6 / 17.2.1)
///
/// サポートしていないバージョンの Long header パケットを受け取ったサーバーが、
/// サポートするバージョンの一覧をクライアントに返すために使う。
///
/// `client_scid` と `client_dcid` には、クライアントが送ってきたパケットの
/// Source / Destination Connection ID をそのまま渡す。Version Negotiation
/// パケットでは両者が入れ替わり、`client_scid` が DCID に、`client_dcid` が
/// SCID になる (RFC 9000 Section 17.2.1)。
///
/// 戻り値は書き込んだバイト数。1 バイト目の Unused (7 ビット) は乱数で埋める。
///
/// # Errors
///
/// `supported_versions` が空の場合、または `buf` が足りない場合にエラーを返す。
pub fn write_version_negotiation(
    buf: &mut [u8],
    client_scid: &ConnectionId,
    client_dcid: &ConnectionId,
    supported_versions: &[QuicVersion],
) -> Result<usize> {
    if supported_versions.is_empty() {
        return Err(Error::InvalidArgument(
            "supported_versions must not be empty".to_string(),
        ));
    }

    // 1 バイト目の Unused (7 ビット) はランダムで埋める (RFC 9000 Section 17.2.1)
    let mut unused_random = [0u8; 1];
    aws_lc_rs::rand::fill(&mut unused_random)
        .map_err(|_| Error::Internal("failed to generate random bits".to_string()))?;

    let versions: Vec<u32> = supported_versions.iter().map(|v| v.as_u32()).collect();

    // SAFETY: buf は書き込み可能な領域。CID と versions は呼び出し中のみ
    // 参照され、ngtcp2 は内部に複製する。
    let rv = unsafe {
        ngtcp2_pkt_write_version_negotiation(
            buf.as_mut_ptr(),
            buf.len(),
            unused_random[0],
            client_scid.as_bytes().as_ptr(),
            client_scid.len(),
            client_dcid.as_bytes().as_ptr(),
            client_dcid.len(),
            versions.as_ptr(),
            versions.len(),
        )
    };

    if rv < 0 {
        return Err(Error::from_ngtcp2(rv as libc::c_int));
    }

    Ok(rv as usize)
}
