//! QUIC の基本型 (バージョン / コネクション ID / ストリーム ID / パス情報)

use std::net::SocketAddr;

// ============================================================================
// QUIC バージョン定数
// ============================================================================
//
// ngtcp2.h では NGTCP2_PROTO_VER_V1/V2 がキャスト式を含むマクロで定義されている:
//   #define NGTCP2_PROTO_VER_V1 ((uint32_t)0x00000001u)
//   #define NGTCP2_PROTO_VER_V2 ((uint32_t)0x6b3343cfu)
//
// bindgen は単純なリテラルマクロ (#define FOO 42) は Rust 定数として生成できるが、
// キャスト式 ((uint32_t)...) を含むマクロは処理できないため、
// ここで同等の定数を独自に定義する。

/// QUIC v1 (RFC 9000)
pub const NGTCP2_PROTO_VER_V1: u32 = 0x00000001;
/// QUIC v2 (RFC 9369)
pub const NGTCP2_PROTO_VER_V2: u32 = 0x6b3343cf;

/// QUIC バージョン
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum QuicVersion {
    /// QUIC v1 (RFC 9000)
    #[default]
    V1 = NGTCP2_PROTO_VER_V1,
    /// QUIC v2 (RFC 9369)
    V2 = NGTCP2_PROTO_VER_V2,
}

impl QuicVersion {
    /// ワイヤフォーマットのバージョン値を返す
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// 数値から QUIC バージョンを得る
    ///
    /// 未知のバージョンは `None` を返す。
    pub fn from_u32(version: u32) -> Option<Self> {
        match version {
            NGTCP2_PROTO_VER_V1 => Some(QuicVersion::V1),
            NGTCP2_PROTO_VER_V2 => Some(QuicVersion::V2),
            _ => None,
        }
    }
}

// ============================================================================
// コネクション ID
// ============================================================================
//
// ngtcp2_cid は固定サイズ配列 (data: [u8; 20], datalen: usize) を持つ C 構造体。
// Rust では Vec<u8> を使用することで:
// - 可変長データの自然な表現
// - Clone, PartialEq, Eq, Hash の derive が可能
// - メモリ安全なインターフェース
// を提供する。

/// コネクション ID (RFC 9000 Section 5.1)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    data: Vec<u8>,
}

impl ConnectionId {
    /// バイト列からコネクション ID を作成する
    ///
    /// 長さ 0 はコネクション ID を使わないエンドポイントを表すため許す
    /// (RFC 9000 Section 5.1)。パケットから読んだコネクション ID は長さ 0 に
    /// なりうる。長さが 20 バイトを超える場合は `None` を返す。
    ///
    /// 長さ 1 以上のコネクション ID を生成する場合は
    /// [`ConnectionId::random`] を使うこと。
    pub fn new(data: &[u8]) -> Option<Self> {
        let max = shiguredo_ngtcp2_sys::NGTCP2_MAX_CIDLEN as usize;
        if data.len() > max {
            return None;
        }
        Some(Self {
            data: data.to_vec(),
        })
    }

    /// 長さ 0 のコネクション ID を作る (RFC 9000 Section 5.1)
    ///
    /// コネクション ID を使わないエンドポイントが、パケットに載せる
    /// コネクション ID として使う。相手はコネクション ID でパケットを
    /// 識別できないため、アドレスで振り分けることになる。
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    /// ランダムなコネクション ID を生成する
    ///
    /// 長さが許容範囲を外れる場合は `None` を返す。
    pub fn random(len: usize) -> Option<Self> {
        let min = shiguredo_ngtcp2_sys::NGTCP2_MIN_CIDLEN as usize;
        let max = shiguredo_ngtcp2_sys::NGTCP2_MAX_CIDLEN as usize;
        if len < min || len > max {
            return None;
        }
        let mut data = vec![0u8; len];
        aws_lc_rs::rand::fill(&mut data).ok()?;
        Some(Self { data })
    }

    /// バイト列として取得する
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// 長さを取得する
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 空かどうかを返す
    ///
    /// 長さ 0 のコネクション ID の場合に true になる。`ConnectionId::random`
    /// は 1 バイト未満を拒否するため、[`ConnectionId::new`] か
    /// [`ConnectionId::empty`] で作った場合だけ true になる。
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnectionId(")?;
        for b in &self.data {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.data {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

// ============================================================================
// パス情報
// ============================================================================
//
// ngtcp2_path は ngtcp2_addr 構造体へのポインタを持ち、
// ngtcp2_addr は sockaddr* (生ポインタ) を使用する。
// Rust の SocketAddr を使用することで型安全なインターフェースを提供する。

/// パス情報 (ローカルアドレスとリモートアドレスの組)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathInfo {
    /// ローカルアドレス
    pub local: SocketAddr,
    /// リモートアドレス
    pub remote: SocketAddr,
}

// ============================================================================
// パケット情報
// ============================================================================
//
// ngtcp2_pkt_info は ecn フィールドのみを持つ単純な構造体。
// FFI 境界を超えるため、独自の Rust 構造体として再定義し、
// Default trait などの Rust 慣用的なインターフェースを提供する。

/// パケット情報 (ECN マーキング)
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketInfo {
    /// ECN マーキング
    pub ecn: u8,
}

// ============================================================================
// ストリーム関連の型
// ============================================================================
//
// ngtcp2 はストリーム ID として int64_t を使用する。
// ストリームタイプと方向はストリーム ID のビットフラグで判定する
// (RFC 9000 Section 2.1):
// - bit 0: 0 = クライアント開始, 1 = サーバー開始
// - bit 1: 0 = 双方向, 1 = 単方向
// Rust の enum で型安全に表現することで、誤用を防止する。

/// ストリーム ID (RFC 9000 Section 2.1)
pub type StreamId = i64;

/// ストリームタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// 双方向ストリーム
    Bidirectional,
    /// 単方向ストリーム
    Unidirectional,
}

impl StreamType {
    /// ストリーム ID からタイプを判定する (RFC 9000 Section 2.1)
    pub fn from_stream_id(stream_id: StreamId) -> Self {
        if stream_id & 0x2 == 0 {
            Self::Bidirectional
        } else {
            Self::Unidirectional
        }
    }
}

/// ストリーム方向 (クライアント開始 or サーバー開始)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// クライアント開始
    ClientInitiated,
    /// サーバー開始
    ServerInitiated,
}

impl StreamDirection {
    /// ストリーム ID から方向を判定する (RFC 9000 Section 2.1)
    pub fn from_stream_id(stream_id: StreamId) -> Self {
        if stream_id & 0x1 == 0 {
            Self::ClientInitiated
        } else {
            Self::ServerInitiated
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 長さ 0 のコネクション ID が作れること (RFC 9000 Section 5.1)
    #[test]
    fn test_connection_id_empty() {
        let cid = ConnectionId::empty();
        assert_eq!(cid.len(), 0, "長さが 0 であること");
        assert!(cid.is_empty(), "空であること");
        assert_eq!(cid.as_bytes(), &[] as &[u8], "バイト列が空であること");
    }

    /// パケットから読んだ長さ 0 のコネクション ID を受け付けること
    #[test]
    fn test_connection_id_new_accepts_empty() {
        let cid = ConnectionId::new(&[]).expect("長さ 0 を受け付けること");
        assert!(cid.is_empty(), "空であること");
    }

    /// 生成するコネクション ID は 1 バイト以上であること
    ///
    /// 長さ 0 のコネクション ID は生成しない。パケットに載せる SCID として
    /// 使う場合は [`ConnectionId::empty`] を使う。
    #[test]
    fn test_connection_id_random_rejects_empty() {
        assert!(ConnectionId::random(0).is_none(), "random が拒否すること");
    }

    /// 20 バイトを超えるコネクション ID は拒否すること (RFC 9000 Section 17.2)
    #[test]
    fn test_connection_id_rejects_too_long() {
        assert!(
            ConnectionId::new(&[0u8; 21]).is_none(),
            "new が拒否すること"
        );
        assert!(ConnectionId::random(21).is_none(), "random が拒否すること");
    }
}
