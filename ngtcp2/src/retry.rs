//! アドレス検証トークン (RFC 9000 Section 8.1.2 / 8.1.3 / 8.1.4)
//!
//! Initial パケットの AEAD は強力な認証を提供しないため、偽造した送信元
//! アドレスを使った反射型の増幅攻撃に使える。サーバーは接続状態を作る前に
//! Retry パケットを返し、クライアントが同じアドレスから再送してきたことを
//! もってアドレスを検証できる。
//!
//! Retry パケットに載せるトークンは [`RetrySecret`] とクライアントのアドレス・
//! 時刻から暗号的に生成し、再送時に [`verify_retry_token`] で検証する。
//! トークンにはクライアントが最初に選んだ DCID (Original Destination
//! Connection ID) が埋め込まれており、検証に成功するとそれを取り出せる。
//!
//! NEW_TOKEN フレームで配布するトークンは [`generate_new_token`] で生成し、
//! 次の接続の Initial に載ってきたところを [`verify_new_token`] で検証する。
//! こちらは Retry と違い、DCID を埋め込まない (クライアントは新しい DCID を
//! 選ぶため)。

use std::net::SocketAddr;
use std::time::Duration;

use shiguredo_ngtcp2_sys::*;

use crate::conn::sockaddr_to_raw;
use crate::error::{Error, Result};
use crate::types::{ConnectionId, QuicVersion};

/// Retry トークンの導出に使う秘密の長さ (バイト)
pub const RETRY_SECRET_LEN: usize = 32;

/// `ngtcp2_crypto_generate_retry_token2` が生成するトークンの最大長 (バイト)
///
/// ngtcp2 の `NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2` と同じ式。
/// マクロが算出式を含むため bindgen が定数として取り込めない。
pub const MAX_RETRY_TOKEN_LEN: usize = 1 // magic
    + std::mem::size_of::<ngtcp2_sockaddr_union>()
    + 1 // cid len
    + NGTCP2_MAX_CIDLEN as usize
    + std::mem::size_of::<u64>() // timestamp
    + 16 // aead tag
    + NGTCP2_CRYPTO_TOKEN_RAND_DATALEN as usize;

/// `ngtcp2_crypto_generate_regular_token` が生成するトークンの最大長 (バイト)
///
/// ngtcp2 の `NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN` と同じ式。
/// マクロが算出式を含むため bindgen が定数として取り込めない。
pub const MAX_NEW_TOKEN_LEN: usize = 1 // magic
    + std::mem::size_of::<u64>() // timestamp
    + 16 // aead tag
    + NGTCP2_CRYPTO_TOKEN_RAND_DATALEN as usize;

/// CONNECTION_CLOSE に載せる理由文字列の最大長 (バイト)
const MAX_CLOSE_REASON_LEN: usize = 64;

/// アドレス検証トークンの種別
///
/// ngtcp2 の `ngtcp2_token_type` に対応する。サーバーは Initial に載っていた
/// トークンの種別を ngtcp2 に伝えることで、アドレス検証済みかどうかと
/// Original Destination Connection ID の扱いを正しく決められる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressValidationTokenKind {
    /// Retry パケットで配布したトークン (RFC 9000 Section 8.1.3)
    Retry,
    /// NEW_TOKEN フレームで配布したトークン (RFC 9000 Section 8.1.4)
    NewToken,
}

impl AddressValidationTokenKind {
    /// ngtcp2 の値へ変換する
    fn as_raw(self) -> ngtcp2_token_type {
        match self {
            Self::Retry => ngtcp2_token_type_NGTCP2_TOKEN_TYPE_RETRY,
            Self::NewToken => ngtcp2_token_type_NGTCP2_TOKEN_TYPE_NEW_TOKEN,
        }
    }
}

/// アドレス検証トークン
///
/// クライアントが Initial に載せて送り返してきたトークン。
/// [`crate::Settings::address_validation_token`] に設定すると ngtcp2 に渡され、
/// アドレス検証済みとして扱われる (RFC 9000 Section 8.1)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressValidationToken {
    /// トークンのバイト列
    bytes: Vec<u8>,
    /// トークンの種別
    kind: AddressValidationTokenKind,
}

impl AddressValidationToken {
    /// Initial に載っていたトークンから作る
    ///
    /// 種別は ngtcp2 が生成したトークンの先頭のマジックバイトから判定する。
    /// 未知のマジックや空のトークンは `None` を返す。
    pub fn from_packet(bytes: Vec<u8>) -> Option<Self> {
        let kind = token_kind(&bytes)?;
        Some(Self { bytes, kind })
    }

    /// トークンのバイト列を返す
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// トークンの種別を返す
    pub fn kind(&self) -> AddressValidationTokenKind {
        self.kind
    }

    /// ngtcp2 の `settings.token_type` に渡す値を返す
    pub(crate) fn as_raw_kind(&self) -> ngtcp2_token_type {
        self.kind.as_raw()
    }
}

/// Retry トークンを導出するための秘密 (RFC 9000 Section 8.1.3)
///
/// 秘密を漏らすと誰でも有効な Retry トークンを発行できるため、
/// [`std::fmt::Debug`] では中身を出さない。
#[derive(Clone, PartialEq, Eq)]
pub struct RetrySecret([u8; RETRY_SECRET_LEN]);

impl RetrySecret {
    /// 暗号学的に安全な乱数から秘密を生成する
    pub fn generate() -> Option<Self> {
        let mut bytes = [0u8; RETRY_SECRET_LEN];
        aws_lc_rs::rand::fill(&mut bytes).ok()?;
        Some(Self(bytes))
    }

    /// 既知のバイト列から秘密を作る
    ///
    /// 複数のサーバープロセスで同じトークンを検証できるようにする場合に使う。
    pub fn from_bytes(bytes: [u8; RETRY_SECRET_LEN]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for RetrySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 秘密は表示しない
        f.write_str("RetrySecret(<redacted>)")
    }
}

/// 受理可能な新規接続の Initial パケット
///
/// [`accept_initial`] が返す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedInitial {
    /// パケットのバージョンフィールド
    pub version: u32,
    /// クライアントが選んだ DCID
    ///
    /// トークンが無い場合は Original Destination Connection ID そのもの
    /// (RFC 9000 Section 7.3)。トークンがある場合は Retry の SCID なので、
    /// Original Destination Connection ID は [`verify_retry_token`] で
    /// トークンから取り出すこと。
    pub dcid: ConnectionId,
    /// クライアントの SCID
    pub scid: ConnectionId,
    /// パケットに載っていたトークン。無ければ空
    pub token: Vec<u8>,
}

/// 新規接続の Initial パケットを受理できるか判定する
///
/// ngtcp2 の `ngtcp2_accept` を使う。以下を満たすパケットだけを受理する:
///
/// - Long header かつ Initial (0-RTT はバッファリングせずに破棄する)
/// - サポートしているバージョン
/// - データグラムが 1200 バイト以上 (RFC 9000 Section 14.1)
/// - トークンが無い場合は DCID が 8 バイト以上 (RFC 9000 Section 7.2)
///
/// 受理できない場合は `None` を返す。
pub fn accept_initial(data: &[u8]) -> Option<AcceptedInitial> {
    let mut hd: ngtcp2_pkt_hd =
        // SAFETY: ngtcp2_pkt_hd は値とポインタの集合で、
        // すべてのビットパターンが有効な POD
        unsafe { std::mem::zeroed() };

    // SAFETY: hd は書き込み可能な領域。data は呼び出し中のみ有効で、
    // ngtcp2 は解析中だけ参照する。ただし hd.dcid / hd.scid / hd.token は
    // data の中を指すため、hd の生存中にコピーして返す。
    let rv = unsafe { ngtcp2_accept(&mut hd, data.as_ptr(), data.len()) };
    if rv != 0 {
        return None;
    }

    // SAFETY: 受理できたパケットでは dcid / scid は data 内の有効な領域
    let (dcid_bytes, scid_bytes, token) = unsafe {
        (
            std::slice::from_raw_parts(hd.dcid.data.as_ptr(), hd.dcid.datalen),
            std::slice::from_raw_parts(hd.scid.data.as_ptr(), hd.scid.datalen),
            if hd.token.is_null() || hd.tokenlen == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(hd.token, hd.tokenlen).to_vec()
            },
        )
    };

    Some(AcceptedInitial {
        version: hd.version,
        dcid: ConnectionId::new(dcid_bytes)?,
        scid: ConnectionId::new(scid_bytes)?,
        token,
    })
}

/// トークンの種別を判定する
///
/// ngtcp2 が生成したトークンは先頭にマジックバイトを持つ。
/// 未知のマジックや空のトークンは `None` を返す。
pub fn token_kind(token: &[u8]) -> Option<AddressValidationTokenKind> {
    let magic = *token.first()?;
    if magic == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2 as u8 {
        Some(AddressValidationTokenKind::Retry)
    } else if magic == NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR as u8 {
        Some(AddressValidationTokenKind::NewToken)
    } else {
        None
    }
}

/// Retry トークンを生成する (RFC 9000 Section 8.1.3)
///
/// * `client_addr` - Retry を送る相手のアドレス。トークンに束縛されるため、
///   別のアドレスから再送された場合は検証に失敗する
/// * `retry_scid` - Retry パケットの SCID として選ぶコネクション ID
/// * `original_dcid` - クライアントが最初の Initial で使った DCID
/// * `ts` - 現在時刻 (ナノ秒)。トークンの有効期限の基準になる
///
/// # Errors
///
/// トークンの生成に失敗した場合にエラーを返す。
pub fn generate_retry_token(
    secret: &RetrySecret,
    version: QuicVersion,
    client_addr: SocketAddr,
    retry_scid: &ConnectionId,
    original_dcid: &ConnectionId,
    ts: u64,
) -> Result<AddressValidationToken> {
    let (addr, addr_len) = sockaddr_to_raw(&client_addr);
    let retry_scid_raw = cid_to_raw(retry_scid);
    let odcid_raw = cid_to_raw(original_dcid);

    let mut token = [0u8; MAX_RETRY_TOKEN_LEN];

    // SAFETY: token は MAX_RETRY_TOKEN_LEN バイト以上の書き込み可能な領域
    // (ngtcp2_crypto_generate_retry_token2 の要求)。addr / CID は呼び出し中のみ
    // 参照される。
    let rv = unsafe {
        ngtcp2_crypto_generate_retry_token2(
            token.as_mut_ptr(),
            secret.0.as_ptr(),
            secret.0.len(),
            version.as_u32(),
            &addr as *const _ as *const ngtcp2_sockaddr,
            addr_len as ngtcp2_socklen,
            &retry_scid_raw,
            &odcid_raw,
            ts,
        )
    };

    if rv < 0 {
        return Err(Error::Internal(
            "ngtcp2_crypto_generate_retry_token2 failed".to_string(),
        ));
    }

    Ok(AddressValidationToken {
        bytes: token[..rv as usize].to_vec(),
        kind: AddressValidationTokenKind::Retry,
    })
}

/// Retry トークンを検証して Original Destination Connection ID を取り出す
/// (RFC 9000 Section 8.1.3)
///
/// * `client_addr` - パケットの送信元アドレス。トークンに束縛された
///   アドレスと一致しなければならない
/// * `retry_dcid` - パケットの DCID。Retry パケットの SCID と一致しなければならない
/// * `timeout` - トークンの有効期間
/// * `ts` - 現在時刻 (ナノ秒)
///
/// # Errors
///
/// トークンが壊れている、アドレスが一致しない、有効期限が切れている場合は
/// [`Error::InvalidArgument`] を返す。
pub fn verify_retry_token(
    secret: &RetrySecret,
    token: &[u8],
    version: QuicVersion,
    client_addr: SocketAddr,
    retry_dcid: &ConnectionId,
    timeout: Duration,
    ts: u64,
) -> Result<ConnectionId> {
    let (addr, addr_len) = sockaddr_to_raw(&client_addr);
    let dcid_raw = cid_to_raw(retry_dcid);
    let mut odcid_raw = cid_to_raw(retry_dcid);

    // SAFETY: odcid_raw は書き込み可能な領域。addr / CID / token は
    // 呼び出し中のみ参照される。
    let rv = unsafe {
        ngtcp2_crypto_verify_retry_token2(
            &mut odcid_raw,
            token.as_ptr(),
            token.len(),
            secret.0.as_ptr(),
            secret.0.len(),
            version.as_u32(),
            &addr as *const _ as *const ngtcp2_sockaddr,
            addr_len as ngtcp2_socklen,
            &dcid_raw,
            timeout.as_nanos() as u64,
            ts,
        )
    };

    if rv != 0 {
        // ngtcp2_crypto のエラーコードは ngtcp2 本体とは別の範囲のため、
        // ngtcp2_strerror ではなく自前のメッセージを使う
        let reason = if rv == NGTCP2_CRYPTO_ERR_UNREADABLE_TOKEN {
            "retry token is badly formatted or fails integrity check"
        } else if rv == NGTCP2_CRYPTO_ERR_VERIFY_TOKEN {
            "retry token does not prove the client address or has expired"
        } else {
            "retry token verification failed"
        };
        return Err(Error::InvalidArgument(reason.to_string()));
    }

    // SAFETY: 検証に成功した場合、odcid_raw には取り出した CID が入る
    let odcid_bytes =
        unsafe { std::slice::from_raw_parts(odcid_raw.data.as_ptr(), odcid_raw.datalen) };
    ConnectionId::new(odcid_bytes)
        .ok_or_else(|| Error::InvalidArgument("retry token contains an invalid cid".to_string()))
}

/// NEW_TOKEN フレームで配布するトークンを生成する (RFC 9000 Section 8.1.3)
///
/// Retry のトークンと違い、クライアントが最初に選んだ DCID は埋め込まない。
/// 次の接続で新しい DCID を使うため (RFC 9000 Section 7.3)。
///
/// * `client_addr` - トークンを配布する相手のアドレス。トークンに束縛される
/// * `ts` - 現在時刻 (ナノ秒)。トークンの有効期限の基準になる
///
/// # Errors
///
/// トークンの生成に失敗した場合にエラーを返す。
pub fn generate_new_token(
    secret: &RetrySecret,
    client_addr: SocketAddr,
    ts: u64,
) -> Result<AddressValidationToken> {
    let (addr, addr_len) = sockaddr_to_raw(&client_addr);

    let mut token = [0u8; MAX_NEW_TOKEN_LEN];

    // SAFETY: token は MAX_NEW_TOKEN_LEN バイト以上の書き込み可能な領域
    // (ngtcp2_crypto_generate_regular_token の要求)。addr は呼び出し中のみ
    // 参照される。
    let rv = unsafe {
        ngtcp2_crypto_generate_regular_token(
            token.as_mut_ptr(),
            secret.0.as_ptr(),
            secret.0.len(),
            &addr as *const _ as *const ngtcp2_sockaddr,
            addr_len as ngtcp2_socklen,
            ts,
        )
    };

    if rv < 0 {
        return Err(Error::Internal(
            "ngtcp2_crypto_generate_regular_token failed".to_string(),
        ));
    }

    Ok(AddressValidationToken {
        bytes: token[..rv as usize].to_vec(),
        kind: AddressValidationTokenKind::NewToken,
    })
}

/// NEW_TOKEN で配布したトークンを検証する (RFC 9000 Section 8.1.3)
///
/// * `client_addr` - パケットの送信元アドレス。トークンに束縛された
///   アドレスと一致しなければならない
/// * `timeout` - トークンの有効期間
/// * `ts` - 現在時刻 (ナノ秒)
///
/// # Errors
///
/// トークンが壊れている、アドレスが一致しない、有効期限が切れている場合は
/// [`Error::InvalidArgument`] を返す。
pub fn verify_new_token(
    secret: &RetrySecret,
    token: &[u8],
    client_addr: SocketAddr,
    timeout: Duration,
    ts: u64,
) -> Result<()> {
    let (addr, addr_len) = sockaddr_to_raw(&client_addr);

    // SAFETY: token / addr は呼び出し中のみ参照される。
    let rv = unsafe {
        ngtcp2_crypto_verify_regular_token(
            token.as_ptr(),
            token.len(),
            secret.0.as_ptr(),
            secret.0.len(),
            &addr as *const _ as *const ngtcp2_sockaddr,
            addr_len as ngtcp2_socklen,
            timeout.as_nanos() as u64,
            ts,
        )
    };

    if rv != 0 {
        return Err(Error::InvalidArgument(
            "new token does not prove the client address or has expired".to_string(),
        ));
    }

    Ok(())
}

/// Retry パケットを書き出す (RFC 9000 Section 17.2.5)
///
/// * `client_scid` - クライアントの Initial の SCID。Retry の DCID になる
/// * `retry_scid` - サーバーが選んだ SCID
/// * `original_dcid` - クライアントが最初の Initial で使った DCID。
///   パケットの完全性保護に含められる
///
/// 戻り値は書き込んだバイト数。
///
/// # Errors
///
/// バッファが足りない場合、またはパケットの生成に失敗した場合にエラーを返す。
pub fn write_retry_packet(
    buf: &mut [u8],
    version: QuicVersion,
    client_scid: &ConnectionId,
    retry_scid: &ConnectionId,
    original_dcid: &ConnectionId,
    token: &[u8],
) -> Result<usize> {
    let client_scid_raw = cid_to_raw(client_scid);
    let retry_scid_raw = cid_to_raw(retry_scid);
    let odcid_raw = cid_to_raw(original_dcid);

    // SAFETY: buf は書き込み可能な領域。CID と token は呼び出し中のみ参照され、
    // ngtcp2 は内容を buf に複製する。
    let rv = unsafe {
        ngtcp2_crypto_write_retry(
            buf.as_mut_ptr(),
            buf.len(),
            version.as_u32(),
            &client_scid_raw,
            &retry_scid_raw,
            &odcid_raw,
            token.as_ptr(),
            token.len(),
        )
    };

    if rv < 0 {
        return Err(Error::Internal(
            "ngtcp2_crypto_write_retry failed".to_string(),
        ));
    }

    Ok(rv as usize)
}

/// 接続状態を持たない CONNECTION_CLOSE パケットを書き出す
/// (RFC 9000 Section 10.2.3)
///
/// トークンが不正な Initial に対する応答のように、接続を作らずに
/// 1 パケットだけでエラーを伝えたい場合に使う。
///
/// ngtcp2 はこのパケットを 1200 バイトにパディングしない。接続を終了させる
/// だけの応答に経路 MTU の確認は不要で、引き金になった Initial
/// (1200 バイト以上) より必ず小さくなるため増幅攻撃にも使われない
/// (RFC 9000 Section 8.1)。
///
/// * `client_scid` - クライアントの Initial の SCID。DCID になる
/// * `server_scid` - サーバーの SCID
///
/// 戻り値は書き込んだバイト数。
///
/// # Errors
///
/// バッファが足りない場合、またはパケットの生成に失敗した場合にエラーを返す。
pub fn write_stateless_connection_close(
    buf: &mut [u8],
    version: QuicVersion,
    client_scid: &ConnectionId,
    server_scid: &ConnectionId,
    error_code: u64,
    reason: &[u8],
) -> Result<usize> {
    let client_scid_raw = cid_to_raw(client_scid);
    let server_scid_raw = cid_to_raw(server_scid);
    // 理由文字列は長すぎる場合に切り詰める (ngtcp2 は可変長で受け付けるが、
    // 呼び出し側が無制限のデータを持たないよう上限を設ける)
    let reason = &reason[..reason.len().min(MAX_CLOSE_REASON_LEN)];

    // SAFETY: buf は書き込み可能な領域。CID と reason は呼び出し中のみ参照される。
    let rv = unsafe {
        ngtcp2_crypto_write_connection_close(
            buf.as_mut_ptr(),
            buf.len(),
            version.as_u32(),
            &client_scid_raw,
            &server_scid_raw,
            error_code,
            reason.as_ptr(),
            reason.len(),
        )
    };

    if rv < 0 {
        return Err(Error::Internal(
            "ngtcp2_crypto_write_connection_close failed".to_string(),
        ));
    }

    Ok(rv as usize)
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

/// QUIC のトランスポートエラーコード `INVALID_TOKEN` (RFC 9000 Section 20.1)
///
/// トークンが不正な Initial に対して CONNECTION_CLOSE で通知する。
pub const TRANSPORT_ERROR_INVALID_TOKEN: u64 = 0x0b;

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用の秘密
    fn secret() -> RetrySecret {
        RetrySecret::from_bytes([0x77; RETRY_SECRET_LEN])
    }

    /// テスト用のクライアントアドレス
    fn client_addr() -> SocketAddr {
        "127.0.0.1:50000".parse().expect("リテラルアドレスは有効")
    }

    /// NEW_TOKEN のトークンを検証できること (RFC 9000 Section 8.1.3)
    #[test]
    fn test_new_token_roundtrip() {
        let secret = secret();
        let ts = 1_000_000_000;

        let token =
            generate_new_token(&secret, client_addr(), ts).expect("トークンを生成できること");

        assert!(
            token.as_bytes().len() <= MAX_NEW_TOKEN_LEN,
            "トークンが最大長を超えないこと"
        );
        assert_eq!(
            token.kind(),
            AddressValidationTokenKind::NewToken,
            "種別が NEW_TOKEN であること"
        );
        assert_eq!(
            token_kind(token.as_bytes()),
            Some(AddressValidationTokenKind::NewToken),
            "マジックバイトから種別を判定できること"
        );

        verify_new_token(
            &secret,
            token.as_bytes(),
            client_addr(),
            Duration::from_secs(10),
            ts + 1,
        )
        .expect("同じ秘密とアドレスで検証できること");

        // 期限切れのトークンは検証できない
        assert!(
            verify_new_token(
                &secret,
                token.as_bytes(),
                client_addr(),
                Duration::from_secs(10),
                ts + 11_000_000_000,
            )
            .is_err(),
            "有効期間を過ぎたトークンは検証に失敗すること"
        );

        // 別の秘密では検証できない
        let other = RetrySecret::from_bytes([0x78; RETRY_SECRET_LEN]);
        assert!(
            verify_new_token(
                &other,
                token.as_bytes(),
                client_addr(),
                Duration::from_secs(10),
                ts + 1,
            )
            .is_err(),
            "別の秘密では検証に失敗すること"
        );
    }

    /// NEW_TOKEN のトークンが IP アドレスに束縛されること
    ///
    /// ポートは含まれない (アドレス付け替えで正当に変わることがあるため)。
    #[test]
    fn test_new_token_is_bound_to_address() {
        let secret = secret();
        let ts = 1_000_000_000;
        let token =
            generate_new_token(&secret, client_addr(), ts).expect("トークンを生成できること");

        // 同じ IP アドレスならポートが変わっても検証できる
        let other_port: SocketAddr = "127.0.0.1:50001".parse().expect("リテラルアドレスは有効");
        verify_new_token(
            &secret,
            token.as_bytes(),
            other_port,
            Duration::from_secs(10),
            ts + 1,
        )
        .expect("同じ IP アドレスなら検証できること");

        // 別の IP アドレスでは検証できない
        let other_addr: SocketAddr = "127.0.0.2:50000".parse().expect("リテラルアドレスは有効");
        assert!(
            verify_new_token(
                &secret,
                token.as_bytes(),
                other_addr,
                Duration::from_secs(10),
                ts + 1,
            )
            .is_err(),
            "別の IP アドレスでは検証に失敗すること"
        );
    }

    /// Debug 出力に秘密が含まれないこと
    #[test]
    fn test_debug_redacts_secret() {
        let debug = format!("{:?}", secret());
        assert_eq!(debug, "RetrySecret(<redacted>)", "秘密を表示しないこと");
    }

    /// 生成したトークンを検証して Original DCID を取り出せること
    #[test]
    fn test_retry_token_roundtrip() {
        let secret = secret();
        let retry_scid = ConnectionId::new(&[0xaa; 16]).expect("CID を作れること");
        let odcid = ConnectionId::new(&[0xbb; 16]).expect("CID を作れること");
        let ts = 1_000_000_000;

        let token = generate_retry_token(
            &secret,
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            &odcid,
            ts,
        )
        .expect("トークンを生成できること");

        assert!(
            token.as_bytes().len() <= MAX_RETRY_TOKEN_LEN,
            "トークンが最大長を超えないこと"
        );
        assert_eq!(token.kind(), AddressValidationTokenKind::Retry, "種別");
        assert_eq!(
            token_kind(token.as_bytes()),
            Some(AddressValidationTokenKind::Retry),
            "マジックバイトから種別を判定できること"
        );

        // 検証すると Retry の SCID を DCID に持つ Initial から
        // 最初の DCID を取り出せること
        let verified = verify_retry_token(
            &secret,
            token.as_bytes(),
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            Duration::from_secs(10),
            ts + 1,
        )
        .expect("トークンを検証できること");
        assert_eq!(verified, odcid, "Original DCID が取り出せること");
    }

    /// 乱数から生成した秘密でもトークンを生成・検証できること
    #[test]
    fn test_retry_secret_generate() {
        let first = RetrySecret::generate().expect("秘密を生成できること");
        let second = RetrySecret::generate().expect("秘密を生成できること");
        assert_ne!(first, second, "生成のたびに異なる秘密になること");

        let retry_scid = ConnectionId::new(&[0xcc; 16]).expect("CID を作れること");
        let odcid = ConnectionId::new(&[0xdd; 16]).expect("CID を作れること");
        let ts = 2_000_000_000;

        let token = generate_retry_token(
            &first,
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            &odcid,
            ts,
        )
        .expect("トークンを生成できること");

        assert_eq!(
            verify_retry_token(
                &first,
                token.as_bytes(),
                QuicVersion::V1,
                client_addr(),
                &retry_scid,
                Duration::from_secs(10),
                ts + 1,
            )
            .expect("生成した秘密でトークンを検証できること"),
            odcid,
            "生成した秘密でも Original DCID を取り出せること"
        );

        assert!(
            verify_retry_token(
                &second,
                token.as_bytes(),
                QuicVersion::V1,
                client_addr(),
                &retry_scid,
                Duration::from_secs(10),
                ts + 1,
            )
            .is_err(),
            "別の秘密では検証に失敗すること"
        );
    }

    /// 別のアドレスから再送されたトークンは検証に失敗すること
    ///
    /// これがアドレス検証の実体 (RFC 9000 Section 8.1.2)。
    #[test]
    fn test_retry_token_is_bound_to_address() {
        let secret = secret();
        let retry_scid = ConnectionId::new(&[0xaa; 16]).expect("CID を作れること");
        let odcid = ConnectionId::new(&[0xbb; 16]).expect("CID を作れること");
        let ts = 1_000_000_000;

        let token = generate_retry_token(
            &secret,
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            &odcid,
            ts,
        )
        .expect("トークンを生成できること");

        let other_addr: SocketAddr = "127.0.0.1:50001".parse().expect("リテラルアドレスは有効");
        let err = verify_retry_token(
            &secret,
            token.as_bytes(),
            QuicVersion::V1,
            other_addr,
            &retry_scid,
            Duration::from_secs(10),
            ts + 1,
        )
        .expect_err("別のアドレスでは検証に失敗すること");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "InvalidArgument が返ること: {err:?}"
        );
    }

    /// 有効期限が切れたトークンは検証に失敗すること
    #[test]
    fn test_retry_token_expires() {
        let secret = secret();
        let retry_scid = ConnectionId::new(&[0xaa; 16]).expect("CID を作れること");
        let odcid = ConnectionId::new(&[0xbb; 16]).expect("CID を作れること");
        let ts = 1_000_000_000;

        let token = generate_retry_token(
            &secret,
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            &odcid,
            ts,
        )
        .expect("トークンを生成できること");

        // 有効期間 10 秒に対して 1 時間後の時刻で検証する
        let err = verify_retry_token(
            &secret,
            token.as_bytes(),
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            Duration::from_secs(10),
            ts + Duration::from_secs(3600).as_nanos() as u64,
        )
        .expect_err("期限切れのトークンは検証に失敗すること");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "InvalidArgument が返ること: {err:?}"
        );
    }

    /// 別の秘密で検証すると失敗すること
    #[test]
    fn test_retry_token_requires_same_secret() {
        let secret = secret();
        let other = RetrySecret::from_bytes([0x88; RETRY_SECRET_LEN]);
        let retry_scid = ConnectionId::new(&[0xaa; 16]).expect("CID を作れること");
        let odcid = ConnectionId::new(&[0xbb; 16]).expect("CID を作れること");
        let ts = 1_000_000_000;

        let token = generate_retry_token(
            &secret,
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            &odcid,
            ts,
        )
        .expect("トークンを生成できること");

        assert!(
            verify_retry_token(
                &other,
                token.as_bytes(),
                QuicVersion::V1,
                client_addr(),
                &retry_scid,
                Duration::from_secs(10),
                ts + 1,
            )
            .is_err(),
            "別の秘密では検証に失敗すること"
        );
    }

    /// 壊れたトークンは検証に失敗すること
    #[test]
    fn test_verify_rejects_garbage_token() {
        let err = verify_retry_token(
            &secret(),
            &[0u8; 8],
            QuicVersion::V1,
            client_addr(),
            &ConnectionId::new(&[0xaa; 16]).expect("CID を作れること"),
            Duration::from_secs(10),
            0,
        )
        .expect_err("壊れたトークンは拒否されること");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "InvalidArgument が返ること: {err:?}"
        );
    }

    /// Retry パケットのヘッダーが RFC 9000 Section 17.2.5 の形式であること
    #[test]
    fn test_write_retry_packet_format() {
        let secret = secret();
        let client_scid = ConnectionId::new(&[0x11; 16]).expect("CID を作れること");
        let retry_scid = ConnectionId::new(&[0x22; 16]).expect("CID を作れること");
        let odcid = ConnectionId::new(&[0x33; 16]).expect("CID を作れること");
        let token = generate_retry_token(
            &secret,
            QuicVersion::V1,
            client_addr(),
            &retry_scid,
            &odcid,
            0,
        )
        .expect("トークンを生成できること");

        let mut buf = [0u8; 1200];
        let written = write_retry_packet(
            &mut buf,
            QuicVersion::V1,
            &client_scid,
            &retry_scid,
            &odcid,
            token.as_bytes(),
        )
        .expect("Retry パケットを書き出せること");

        // Long header + Retry の種別ビット (v1 では 0x3 → 先頭バイト 0xF0)
        assert_ne!(buf[0] & 0x80, 0, "Long header form bit が立っていること");
        assert_eq!(
            &buf[1..5],
            &QuicVersion::V1.as_u32().to_be_bytes(),
            "バージョンフィールド"
        );

        // DCID にはクライアントの SCID が入ること
        let dcid_len = buf[5] as usize;
        assert_eq!(dcid_len, client_scid.len(), "DCID 長");
        assert_eq!(
            &buf[6..6 + dcid_len],
            client_scid.as_bytes(),
            "DCID はクライアントの SCID であること"
        );

        // SCID にはサーバーが選んだ CID が入ること
        let scid_offset = 6 + dcid_len;
        let scid_len = buf[scid_offset] as usize;
        assert_eq!(scid_len, retry_scid.len(), "SCID 長");
        assert_eq!(
            &buf[scid_offset + 1..scid_offset + 1 + scid_len],
            retry_scid.as_bytes(),
            "SCID はサーバーが選んだ CID であること"
        );

        assert!(
            written > scid_offset + 1 + scid_len,
            "トークンと整合性タグを含むこと: {written}"
        );
    }

    /// 状態を持たない CONNECTION_CLOSE を書き出せること
    #[test]
    fn test_write_stateless_connection_close() {
        let client_scid = ConnectionId::new(&[0x11; 16]).expect("CID を作れること");
        let server_scid = ConnectionId::new(&[0x22; 16]).expect("CID を作れること");

        let mut buf = [0u8; 1200];
        let written = write_stateless_connection_close(
            &mut buf,
            QuicVersion::V1,
            &client_scid,
            &server_scid,
            TRANSPORT_ERROR_INVALID_TOKEN,
            b"invalid address validation token",
        )
        .expect("CONNECTION_CLOSE を書き出せること");

        assert!(written > 0, "パケットが生成されること");
        // 接続状態を持たない応答なので、引き金になった Initial (1200 バイト以上)
        // より小さくなり増幅攻撃に使われないこと (RFC 9000 Section 8.1)
        assert!(
            written < 1200,
            "応答が引き金になったパケットより小さいこと: {written}"
        );
        assert_ne!(buf[0] & 0x80, 0, "Long header form bit が立っていること");
    }

    /// トークンの種別を判定できること
    #[test]
    fn test_token_kind() {
        assert_eq!(
            token_kind(&[NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2 as u8, 1, 2]),
            Some(AddressValidationTokenKind::Retry),
            "Retry のマジックバイト"
        );
        assert_eq!(
            token_kind(&[NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR as u8, 1, 2]),
            Some(AddressValidationTokenKind::NewToken),
            "NEW_TOKEN のマジックバイト"
        );
        assert_eq!(token_kind(&[0x00, 1, 2]), None, "未知のマジックバイト");
        assert_eq!(token_kind(&[]), None, "空のトークン");
    }
}
