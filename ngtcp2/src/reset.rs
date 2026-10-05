//! Stateless Reset (RFC 9000 Section 10.3)
//!
//! 接続状態を失ったエンドポイント (再起動したサーバーや、接続を破棄した
//! サーバー) が、ピアに「その接続はもう存在しない」ことを 1 パケットで
//! 知らせる仕組み。ピアはこれを受けてアイドルタイムアウトを待たずに
//! 接続を終了できる。
//!
//! Stateless Reset トークンはコネクション ID ごとに決まっており、
//! NEW_CONNECTION_ID フレーム (RFC 9000 Section 19.15) とサーバーの
//! トランスポートパラメータ (RFC 9000 Section 18.2) でピアに配布する。
//! 接続状態を失った後も同じトークンを導出できるよう、トークンは
//! [`StatelessResetSecret`] とコネクション ID から HKDF で導出する。

use shiguredo_ngtcp2_sys::*;

use crate::error::{Error, Result};
use crate::types::ConnectionId;

/// Stateless Reset トークンの長さ (バイト。RFC 9000 Section 10.3.1)
pub const STATELESS_RESET_TOKEN_LEN: usize = NGTCP2_STATELESS_RESET_TOKENLEN as usize;

/// Stateless Reset トークン導出に使う秘密の長さ (バイト)
pub const STATELESS_RESET_SECRET_LEN: usize = 32;

/// トークンの前に置く乱数の最小長 (バイト)
///
/// ngtcp2 の `NGTCP2_MIN_STATELESS_RESET_RANDLEN`。
const MIN_RANDOM_LEN: usize = NGTCP2_MIN_STATELESS_RESET_RANDLEN as usize;

/// トークンの前に置く乱数の最大長 (バイト)
///
/// ngtcp2 の example server と同じく「最大 CID 長 + 最小拡張 22 バイト -
/// トークン長」を上限にする。
const MAX_RANDOM_LEN: usize = NGTCP2_MAX_CIDLEN as usize + 22 - STATELESS_RESET_TOKEN_LEN;

/// Stateless Reset パケットの最小長 (バイト)
///
/// 先頭 1 バイト、乱数 (ngtcp2 の `NGTCP2_MIN_STATELESS_RESET_RANDLEN` バイト)、
/// トークン ([`STATELESS_RESET_TOKEN_LEN`] バイト) を足した長さ。
/// これより短いパケットに対しては増幅攻撃を避けるため Stateless Reset を
/// 送れない (RFC 9000 Section 10.3.3)。
pub const MIN_STATELESS_RESET_SIZE: usize = 1 + MIN_RANDOM_LEN + STATELESS_RESET_TOKEN_LEN;

/// Stateless Reset トークン (RFC 9000 Section 10.3.1)
///
/// 予測不可能でなければならない。トークンを知っている者はそのコネクション ID に
/// 対する偽の Stateless Reset を作れるため、[`std::fmt::Debug`] では中身を出さない。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StatelessResetToken([u8; STATELESS_RESET_TOKEN_LEN]);

impl StatelessResetToken {
    /// バイト列からトークンを作る
    pub fn from_bytes(bytes: [u8; STATELESS_RESET_TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    /// トークンのバイト列を返す
    pub fn as_bytes(&self) -> &[u8; STATELESS_RESET_TOKEN_LEN] {
        &self.0
    }

    /// ngtcp2 の生のトークン型に変換する
    pub(crate) fn as_raw(&self) -> ngtcp2_stateless_reset_token {
        ngtcp2_stateless_reset_token { data: self.0 }
    }
}

impl std::fmt::Debug for StatelessResetToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // トークンは予測不可能である必要があるため中身を表示しない
        f.write_str("StatelessResetToken(<redacted>)")
    }
}

/// Stateless Reset トークンを導出するための秘密 (RFC 9000 Section 10.3.1)
///
/// 同じ秘密からは同じコネクション ID に対して常に同じトークンが導出される。
/// そのためサーバーは秘密だけを持っていれば、接続状態を失った後でも
/// ピアが保持しているトークンと一致する Stateless Reset を送れる。
///
/// 秘密を漏らすと誰でも偽の Stateless Reset を作れるため、
/// [`std::fmt::Debug`] では中身を出さない。
#[derive(Clone, PartialEq, Eq)]
pub struct StatelessResetSecret([u8; STATELESS_RESET_SECRET_LEN]);

impl StatelessResetSecret {
    /// 暗号学的に安全な乱数から秘密を生成する
    ///
    /// 生成した秘密はサーバーの寿命の間だけ有効。プロセスの再起動をまたいで
    /// 同じトークンを導出したい場合は [`StatelessResetSecret::from_bytes`] に
    /// 永続化した値を渡すこと。
    pub fn generate() -> Option<Self> {
        let mut bytes = [0u8; STATELESS_RESET_SECRET_LEN];
        aws_lc_rs::rand::fill(&mut bytes).ok()?;
        Some(Self(bytes))
    }

    /// 既知のバイト列から秘密を作る
    pub fn from_bytes(bytes: [u8; STATELESS_RESET_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// コネクション ID から Stateless Reset トークンを導出する
    ///
    /// ngtcp2 の `ngtcp2_crypto_generate_stateless_reset_token` (HKDF-Extract) を使う。
    pub fn token(&self, cid: &ConnectionId) -> Option<StatelessResetToken> {
        let raw = cid_to_raw(cid);
        let mut token = [0u8; STATELESS_RESET_TOKEN_LEN];

        // SAFETY: token は 16 バイトの書き込み可能な領域。self.0 と raw は
        // 呼び出し中のみ参照される。
        let rv = unsafe {
            ngtcp2_crypto_generate_stateless_reset_token(
                token.as_mut_ptr(),
                self.0.as_ptr(),
                self.0.len(),
                &raw,
            )
        };
        if rv != 0 {
            return None;
        }

        Some(StatelessResetToken(token))
    }
}

impl std::fmt::Debug for StatelessResetSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 秘密は表示しない
        f.write_str("StatelessResetSecret(<redacted>)")
    }
}

/// `ConnectionId` を `ngtcp2_cid` に変換する
fn cid_to_raw(cid: &ConnectionId) -> ngtcp2_cid {
    let mut raw = ngtcp2_cid {
        datalen: cid.len(),
        data: [0u8; NGTCP2_MAX_CIDLEN as usize],
    };
    raw.data[..cid.len()].copy_from_slice(cid.as_bytes());
    raw
}

/// Stateless Reset パケットを書き出す (RFC 9000 Section 10.3.3)
///
/// `received_len` には引き金になったパケットの長さを渡す。増幅攻撃に
/// 使われないよう、応答は元のデータグラムより長くしてはいけない。
///
/// 戻り値は書き込んだバイト数。`received_len` が [`MIN_STATELESS_RESET_SIZE`]
/// 未満で応答を作れない場合は 0 を返す (これはエラーではない)。
///
/// # Errors
///
/// 乱数の生成に失敗した場合、または `buf` が足りない場合にエラーを返す。
pub fn write_stateless_reset(
    buf: &mut [u8],
    token: &StatelessResetToken,
    received_len: usize,
) -> Result<usize> {
    // 短すぎるパケットには応答しない (RFC 9000 Section 10.3.3)。
    // また応答は必ず元のパケットより短くなるように乱数長を決める。
    let random_len = MAX_RANDOM_LEN.min(received_len.saturating_sub(1 + STATELESS_RESET_TOKEN_LEN));
    if random_len < MIN_RANDOM_LEN {
        return Ok(0);
    }

    let mut random = [0u8; MAX_RANDOM_LEN];
    aws_lc_rs::rand::fill(&mut random[..random_len])
        .map_err(|_| Error::Internal("failed to generate random bytes".to_string()))?;

    let raw_token = token.as_raw();

    // SAFETY: buf は書き込み可能な領域。raw_token と random は呼び出し中のみ
    // 参照され、ngtcp2 は内容を buf に複製する。
    let rv = unsafe {
        ngtcp2_pkt_write_stateless_reset2(
            buf.as_mut_ptr(),
            buf.len(),
            &raw_token,
            random.as_ptr(),
            random_len,
        )
    };

    if rv < 0 {
        return Err(Error::from_ngtcp2(rv as libc::c_int));
    }

    Ok(rv as usize)
}
