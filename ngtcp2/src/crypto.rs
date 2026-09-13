//! TLS コンテキスト管理
//!
//! ngtcp2_crypto_boringssl と aws-lc を統合して、QUIC 接続用の
//! TLS コンテキストを管理する。
//!
//! # 設計
//!
//! - [`TlsContext`]: `SSL_CTX` のラッパー。サーバー / クライアント共通の設定を保持する
//! - [`TlsSession`]: `SSL` のラッパー。個々の接続で使用する
//!
//! `ngtcp2_crypto_boringssl_configure_*_context()` を使用することで、
//! ngtcp2 が必要とする TLS コールバックが自動的に設定される。
//!
//! 0-RTT (early data) は TLS 1.3 のセッション再開で送る (RFC 9001 Section 4.6)。
//! クライアントは [`TlsSession::set_session`] で前回のセッションを設定し、
//! [`TlsSession::take_session_ticket`] で次回用のセッションを取り出す。
//! サーバーは [`TlsContext::set_accept_early_data`] を有効にした場合にだけ
//! 0-RTT を受け入れる。

use std::ffi::{CString, c_void};
use std::path::Path;
use std::sync::Mutex;

// aws-lc の生ポインタ型は shiguredo_ngtcp2_sys が再公開しているものを使用する。
// 直接 aws-lc-sys に依存すると、同一プロセスに 2 つの aws-lc がリンクされる恐れがある。
use shiguredo_ngtcp2_sys::aws_lc_sys;

use aws_lc_sys::{
    SSL, SSL_CTX, SSL_CTX_free, SSL_CTX_new, SSL_CTX_sess_set_new_cb, SSL_CTX_set_alpn_protos,
    SSL_CTX_set_early_data_enabled, SSL_CTX_set_session_cache_mode, SSL_CTX_use_PrivateKey_file,
    SSL_CTX_use_certificate_chain_file, SSL_FILETYPE_PEM, SSL_SESS_CACHE_CLIENT,
    SSL_SESS_CACHE_NO_INTERNAL, SSL_SESSION, SSL_SESSION_early_data_capable, SSL_SESSION_free,
    SSL_SESSION_from_bytes, SSL_SESSION_to_bytes, SSL_early_data_accepted, SSL_free,
    SSL_get_SSL_CTX, SSL_in_early_data, SSL_new, SSL_set_accept_state, SSL_set_connect_state,
    SSL_set_early_data_enabled, SSL_set_ex_data, SSL_set_quic_early_data_context, SSL_set_session,
    SSL_set_tlsext_host_name, TLS_method,
};
use shiguredo_ngtcp2_sys::{
    ngtcp2_crypto_boringssl_configure_client_context,
    ngtcp2_crypto_boringssl_configure_server_context,
};

use crate::error::{Error, Result};

/// `SSL` にセッションチケットのスロットを紐付ける ex_data のインデックス
///
/// ngtcp2_crypto が `SSL_set_app_data` (= ex_data 0) を conn_ref の保存に
/// 使うため、衝突しない 1 を使う。
const SESSION_TICKET_EX_DATA_INDEX: i32 = 1;

/// C コールバックが受け取ったセッションチケットを保持するスロット
///
/// `SSL_CTX_sess_set_new_cb` は `SSL_CTX` 単位で登録するため、コールバックは
/// 渡された `SSL` から接続を特定しなければならない。`SSL` ごとにこのスロットを
/// `Box` で確保して `SSL_set_ex_data` で紐付け、TLS 1.3 の NewSessionTicket を
/// 受け取る。
struct SessionTicketSlot {
    /// 受け取ったセッションチケット (aws-lc のシリアライズ形式)
    ///
    /// コールバックは C から呼ばれるため Rust の借用規則では表現できない。
    /// ハンドシェイクは接続ごとに 1 スレッドからしか駆動されないため競合は
    /// 起きないが、`TlsSession` を `Send` にするために `Mutex` で保護する。
    ticket: Mutex<Option<Vec<u8>>>,
}

impl SessionTicketSlot {
    /// 空のスロットを作成する
    fn new() -> Self {
        Self {
            ticket: Mutex::new(None),
        }
    }

    /// チケットを書き込む
    fn store(&self, ticket: Vec<u8>) {
        if let Ok(mut slot) = self.ticket.lock() {
            // TLS 1.3 では複数のチケットが届く。最後に届いたものを保持する
            *slot = Some(ticket);
        }
    }

    /// 保持しているチケットを取り出す
    ///
    /// 一度取り出したチケットは再度返らない。
    fn take(&self) -> Option<Vec<u8>> {
        self.ticket.lock().ok().and_then(|mut slot| slot.take())
    }
}

/// `SSL_SESSION` をバイト列に変換する
///
/// # Safety
///
/// `session` は有効な `SSL_SESSION` を指していること。
unsafe fn session_to_bytes(session: *const SSL_SESSION) -> Option<Vec<u8>> {
    let mut data: *mut u8 = std::ptr::null_mut();
    let mut len: usize = 0;

    // SAFETY: session は有効。data は aws-lc が OPENSSL_malloc で確保するため
    // 呼び出し側が OPENSSL_free で解放する。
    let rv = unsafe { SSL_SESSION_to_bytes(session, &mut data, &mut len) };
    if rv != 1 || data.is_null() {
        // エラーが残ると後続の無関係な呼び出しのデバッグを妨げるためクリアする
        unsafe { aws_lc_sys::ERR_clear_error() };
        return None;
    }

    // SAFETY: data は len バイトの有効な領域
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    // SAFETY: data は SSL_SESSION_to_bytes が確保した領域
    unsafe { aws_lc_sys::OPENSSL_free(data as *mut c_void) };

    Some(bytes)
}

/// 新しいセッションチケットを受け取ったときに呼ばれるコールバック
///
/// TLS 1.3 の NewSessionTicket はハンドシェイク完了後に届く。
/// `SSL_CTX_sess_set_new_cb` に登録したこの関数でバイト列に複製して保持する。
/// 0 を返してセッションの所有権を受け取らない (aws-lc が解放する)。
unsafe extern "C" fn new_session_callback(ssl: *mut SSL, session: *mut SSL_SESSION) -> i32 {
    if ssl.is_null() || session.is_null() {
        return 0;
    }

    // SAFETY: ssl は aws-lc が呼び出し中だけ有効にする SSL。ex_data には
    // TlsContext::create_session で設定した SessionTicketSlot のポインタが入る。
    let slot = unsafe { aws_lc_sys::SSL_get_ex_data(ssl, SESSION_TICKET_EX_DATA_INDEX) };
    // SAFETY: slot は TlsSession が Box で保持しており、SSL の生存中は有効
    let Some(slot) = (unsafe { (slot as *const SessionTicketSlot).as_ref() }) else {
        return 0;
    };

    // SAFETY: session は aws-lc が呼び出し中だけ有効にする SSL_SESSION
    if let Some(bytes) = unsafe { session_to_bytes(session) } {
        slot.store(bytes);
    }

    0
}

/// TLS コンテキスト
///
/// `SSL_CTX` をラップし、QUIC 接続に必要な設定を提供する。
/// サーバーまたはクライアント用に作成し、複数の [`TlsSession`] を生成できる。
pub struct TlsContext {
    ctx: *mut SSL_CTX,
    is_server: bool,
    /// サーバー証明書を検証するかどうか (クライアントコンテキストのみ)
    ///
    /// [`TlsContext::add_ca_cert_pem`] の有効性判定に使用する。
    verify_peer: bool,
    /// ALPN コールバックで使用するデータ (サーバー用)
    ///
    /// コールバックに渡したポインタを保持し、Drop で解放する。
    alpn_data: Option<*mut Vec<u8>>,
    /// 0-RTT (early data) の受け入れが有効かどうか (サーバー用)
    ///
    /// [`TlsContext::set_accept_early_data`] で設定する。作成する
    /// [`TlsSession`] が early data を受け入れるかどうかを決める。
    accept_early_data: bool,
}

// SAFETY: SSL_CTX は aws-lc がスレッドセーフに扱う。TlsContext 自身は
// 不変の設定を保持するだけで、可変状態を持たない。
unsafe impl Send for TlsContext {}
unsafe impl Sync for TlsContext {}

impl TlsContext {
    /// クライアント用 TLS コンテキストを作成する
    ///
    /// 証明書チェーンの検証を有効にする。
    ///
    /// # Arguments
    ///
    /// * `alpn` - ALPN プロトコルリスト (例: `&[b"hq-interop"]`)
    pub fn new_client(alpn: &[&[u8]]) -> Result<Self> {
        Self::new_client_with_options(alpn, true)
    }

    /// クライアント用 TLS コンテキストを作成する (オプション付き)
    ///
    /// # Arguments
    ///
    /// * `alpn` - ALPN プロトコルリスト (例: `&[b"hq-interop"]`)
    /// * `verify_peer` - サーバー証明書を検証するかどうか
    pub fn new_client_with_options(alpn: &[&[u8]], verify_peer: bool) -> Result<Self> {
        // SAFETY: aws-lc の SSL_CTX 生成と設定を行う。生成に失敗した場合は
        // 即座に解放し、成功した場合は Self が所有権を持つ。
        unsafe {
            let method = TLS_method();
            if method.is_null() {
                return Err(Error::Internal("TLS_method failed".to_string()));
            }

            let ctx = SSL_CTX_new(method);
            if ctx.is_null() {
                return Err(Error::Internal("SSL_CTX_new failed".to_string()));
            }

            // ngtcp2 用の設定を適用する。
            // aws_lc_sys::SSL_CTX と ngtcp2 が期待する SSL_CTX は同じ実体へのポインタ。
            let rv = ngtcp2_crypto_boringssl_configure_client_context(
                ctx as *mut shiguredo_ngtcp2_sys::SSL_CTX,
            );
            if rv != 0 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(
                    "ngtcp2_crypto_boringssl_configure_client_context failed".to_string(),
                ));
            }

            // 証明書検証の設定
            if !verify_peer {
                // 証明書検証を無効にする (テスト用の自己署名証明書で使用する)
                aws_lc_sys::SSL_CTX_set_verify(ctx, aws_lc_sys::SSL_VERIFY_NONE, None);
            } else {
                // 証明書チェーン検証を有効にする
                // (RFC 9001 Section 4.4: クライアントはサーバー証明書を検証しなければならない MUST)
                // BoringSSL のデフォルトは SSL_VERIFY_NONE のため明示的に設定する
                aws_lc_sys::SSL_CTX_set_verify(ctx, aws_lc_sys::SSL_VERIFY_PEER, None);
                // デフォルトのトラストストア (SSL_CERT_FILE / SSL_CERT_DIR /
                // システムの CA パス) を読み込む。戻り値は無視し、トラストストアが
                // 空でも接続作成は成功させる (検証失敗はハンドシェイク時に発生する)
                aws_lc_sys::SSL_CTX_set_default_verify_paths(ctx);
            }

            // ALPN を設定する
            let alpn_wire = Self::encode_alpn(alpn);
            let rv = SSL_CTX_set_alpn_protos(ctx, alpn_wire.as_ptr(), alpn_wire.len());
            if rv != 0 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(
                    "SSL_CTX_set_alpn_protos failed".to_string(),
                ));
            }

            // セッションチケットを受け取れるようにする (RFC 8446 Section 4.6.1)。
            //
            // TLS 1.3 の NewSessionTicket はハンドシェイク完了後に届く。
            // aws-lc は SSL_SESS_CACHE_CLIENT が設定されていて new_session_cb が
            // 登録されている場合にだけコールバックを呼ぶ
            // (tls13_process_new_session_ticket の実装による)。
            // セッションはアプリケーションが保存するため内部キャッシュは使わない。
            SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
            SSL_CTX_sess_set_new_cb(ctx, Some(new_session_callback));

            Ok(Self {
                ctx,
                is_server: false,
                verify_peer,
                alpn_data: None,
                accept_early_data: false,
            })
        }
    }

    /// サーバー用 TLS コンテキストを作成する
    ///
    /// # Arguments
    ///
    /// * `cert_path` - 証明書ファイルのパス (PEM 形式)
    /// * `key_path` - 秘密鍵ファイルのパス (PEM 形式)
    /// * `alpn` - ALPN プロトコルリスト (例: `&[b"hq-interop"]`)
    pub fn new_server(cert_path: &Path, key_path: &Path, alpn: &[&[u8]]) -> Result<Self> {
        // SAFETY: aws-lc の SSL_CTX 生成と設定を行う。生成に失敗した場合は
        // 即座に解放し、成功した場合は Self が所有権を持つ。
        unsafe {
            let method = TLS_method();
            if method.is_null() {
                return Err(Error::Internal("TLS_method failed".to_string()));
            }

            let ctx = SSL_CTX_new(method);
            if ctx.is_null() {
                return Err(Error::Internal("SSL_CTX_new failed".to_string()));
            }

            // ngtcp2 用の設定を適用する
            let rv = ngtcp2_crypto_boringssl_configure_server_context(
                ctx as *mut shiguredo_ngtcp2_sys::SSL_CTX,
            );
            if rv != 0 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(
                    "ngtcp2_crypto_boringssl_configure_server_context failed".to_string(),
                ));
            }

            // 証明書を読み込む
            let cert_path_cstr = CString::new(cert_path.to_string_lossy().as_bytes())
                .map_err(|_| Error::InvalidArgument("invalid cert path".to_string()))?;
            let rv = SSL_CTX_use_certificate_chain_file(ctx, cert_path_cstr.as_ptr());
            if rv != 1 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(format!(
                    "SSL_CTX_use_certificate_chain_file failed: {}",
                    cert_path.display()
                )));
            }

            // 秘密鍵を読み込む
            let key_path_cstr = CString::new(key_path.to_string_lossy().as_bytes())
                .map_err(|_| Error::InvalidArgument("invalid key path".to_string()))?;
            let rv = SSL_CTX_use_PrivateKey_file(ctx, key_path_cstr.as_ptr(), SSL_FILETYPE_PEM);
            if rv != 1 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(format!(
                    "SSL_CTX_use_PrivateKey_file failed: {}",
                    key_path.display()
                )));
            }

            // ALPN コールバックを設定する (サーバー用)
            let alpn_wire = Self::encode_alpn(alpn);
            let alpn_data = Box::new(alpn_wire);
            let alpn_ptr = Box::into_raw(alpn_data);

            aws_lc_sys::SSL_CTX_set_alpn_select_cb(
                ctx,
                Some(alpn_select_callback),
                alpn_ptr as *mut c_void,
            );

            Ok(Self {
                ctx,
                is_server: true,
                verify_peer: false,
                alpn_data: Some(alpn_ptr),
                accept_early_data: false,
            })
        }
    }

    /// 0-RTT (early data) の受け入れを設定する (サーバー専用。RFC 9001 Section 4.6)
    ///
    /// 有効にすると、このコンテキストから作成するサーバーセッションが
    /// クライアントの 0-RTT データを受け入れる。既定は無効。
    /// 0-RTT を受け入れるには、接続ごとに
    /// [`TlsSession::set_quic_early_data_context`] で 0-RTT に使う
    /// トランスポートパラメータを設定する必要もある
    /// ([`crate::Connection::server_new`] が設定する)。
    ///
    /// # 0-RTT の危険性
    ///
    /// 0-RTT のデータはリプレイ攻撃に対して脆弱であり (RFC 9001 Section 9.2)、
    /// 本クレートはアンチリプレイの仕組みを提供しない。受け入れるかどうかは
    /// アプリケーションの責任で判断すること。
    ///
    /// # Errors
    ///
    /// クライアントコンテキストの場合はエラーを返す。
    pub fn set_accept_early_data(&mut self, accept: bool) -> Result<()> {
        if !self.is_server {
            return Err(Error::InvalidArgument(
                "cannot accept early data on client context".to_string(),
            ));
        }

        // SAFETY: self.ctx は有効。以降に作成する SSL は SSL_new でこの値を
        // 複製する (aws-lc の ssl_st のコンストラクタによる)。
        unsafe { SSL_CTX_set_early_data_enabled(self.ctx, i32::from(accept)) };
        self.accept_early_data = accept;
        Ok(())
    }

    /// カスタム CA 証明書をトラストストアに追加する
    ///
    /// `verify_peer` が true のクライアントコンテキストでのみ有効。
    /// PEM 形式の CA 証明書をパースし、システムのトラストストアに**追加**する
    /// (置換はしない)。PEM バンドル (連結された複数証明書) を渡した場合は
    /// **先頭の 1 枚のみ**がロードされる。
    ///
    /// # Errors
    ///
    /// サーバーコンテキストの場合、`verify_peer` が false の場合、
    /// PEM のパースに失敗した場合、トラストストアへの追加に失敗した場合はエラーを返す。
    pub fn add_ca_cert_pem(&mut self, ca_cert_pem: &str) -> Result<()> {
        if self.is_server {
            return Err(Error::InvalidArgument(
                "cannot add CA cert on server context".to_string(),
            ));
        }
        if !self.verify_peer {
            return Err(Error::InvalidArgument(
                "cannot add CA cert when verify_peer is false".to_string(),
            ));
        }

        // SAFETY: BIO と X509 の生成・解放は aws-lc の所有権規則に従う。
        // 生成した X509 は X509_STORE_add_cert でストアに複製された後に解放する。
        unsafe {
            // PEM 文字列を BIO メモリでパースして X509 に変換する
            let bio = aws_lc_sys::BIO_new_mem_buf(
                ca_cert_pem.as_ptr() as *const c_void,
                ca_cert_pem.len() as aws_lc_sys::ossl_ssize_t,
            );
            if bio.is_null() {
                return Err(Error::Internal("BIO_new_mem_buf failed".to_string()));
            }
            let x509 = aws_lc_sys::PEM_read_bio_X509(
                bio,
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            );
            aws_lc_sys::BIO_free(bio);
            if x509.is_null() {
                // パース失敗のエラーが aws-lc のエラーキューに残ると後続の
                // 無関係な呼び出しのデバッグを妨げるためクリアする
                aws_lc_sys::ERR_clear_error();
                return Err(Error::InvalidArgument(
                    "invalid CA certificate PEM".to_string(),
                ));
            }

            // トラストストアに追加する
            let store = aws_lc_sys::SSL_CTX_get_cert_store(self.ctx);
            if store.is_null() {
                aws_lc_sys::X509_free(x509);
                return Err(Error::Internal("SSL_CTX_get_cert_store failed".to_string()));
            }
            let rv = aws_lc_sys::X509_STORE_add_cert(store, x509);
            aws_lc_sys::X509_free(x509);
            if rv != 1 {
                aws_lc_sys::ERR_clear_error();
                return Err(Error::Internal("X509_STORE_add_cert failed".to_string()));
            }
            Ok(())
        }
    }

    /// TLS セッションを作成する
    ///
    /// # Errors
    ///
    /// `SSL_new` に失敗した場合にエラーを返す。
    pub fn create_session(&self) -> Result<TlsSession> {
        // SAFETY: SSL_new は ctx の設定を複製した新しい SSL を返す。
        // 生成に失敗した場合は null が返るためエラーにする。
        unsafe {
            let ssl = SSL_new(self.ctx);
            if ssl.is_null() {
                return Err(Error::Internal("SSL_new failed".to_string()));
            }

            if self.is_server {
                SSL_set_accept_state(ssl);
            } else {
                SSL_set_connect_state(ssl);
            }

            // セッションチケットを受け取るスロットを紐付ける (クライアント用)。
            // ポインタが安定するよう Box で確保し、TlsSession が所有する。
            let ticket_slot = if self.is_server {
                None
            } else {
                let mut slot = Box::new(SessionTicketSlot::new());
                let rv = SSL_set_ex_data(
                    ssl,
                    SESSION_TICKET_EX_DATA_INDEX,
                    &mut *slot as *mut SessionTicketSlot as *mut c_void,
                );
                if rv != 1 {
                    SSL_free(ssl);
                    return Err(Error::Internal("SSL_set_ex_data failed".to_string()));
                }
                Some(slot)
            };

            Ok(TlsSession {
                ssl,
                is_server: self.is_server,
                accept_early_data: self.accept_early_data,
                ticket_slot,
            })
        }
    }

    /// ALPN プロトコルリストをワイヤーフォーマットにエンコードする
    ///
    /// ワイヤーフォーマット: `[len1][proto1][len2][proto2]...` (RFC 7301 Section 3.1)
    fn encode_alpn(alpn: &[&[u8]]) -> Vec<u8> {
        let mut wire = Vec::new();
        for proto in alpn {
            wire.push(proto.len() as u8);
            wire.extend_from_slice(proto);
        }
        wire
    }
}

impl Drop for TlsContext {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: self.ctx は SSL_CTX_new で生成した未解放のポインタ。
            // alpn_data も new_server で Box::into_raw したもので未解放。
            unsafe {
                // ALPN コールバックで設定したデータを解放する
                if let Some(alpn_ptr) = self.alpn_data {
                    let _ = Box::from_raw(alpn_ptr);
                }
                SSL_CTX_free(self.ctx);
            }
        }
    }
}

/// TLS セッション
///
/// `SSL` をラップし、個々の QUIC 接続で使用する。
pub struct TlsSession {
    ssl: *mut SSL,
    is_server: bool,
    /// 0-RTT (early data) を受け入れるかどうか (サーバー用)
    ///
    /// [`TlsContext::set_accept_early_data`] の値を引き継ぐ。
    accept_early_data: bool,
    /// 受け取ったセッションチケットのスロット (クライアント用)
    ///
    /// C コールバックにポインタを渡すため、move されてもアドレスが変わらない
    /// `Box` で保持する。
    ticket_slot: Option<Box<SessionTicketSlot>>,
}

// SAFETY: SSL は 1 つの接続にのみ対応付けられ、その接続の所有スレッドから
// 排他的に使用される。ngtcp2 のコールバックは同一スレッドから呼ばれる。
unsafe impl Send for TlsSession {}
unsafe impl Sync for TlsSession {}

impl TlsSession {
    /// SNI (Server Name Indication) とホスト名検証を設定する
    ///
    /// クライアント接続で使用する。接続先のサーバー名を指定する。
    /// `verify_peer` が true の場合はホスト名検証 (証明書の SAN dNSName との照合。
    /// SAN に dNSName が無い証明書では CN にフォールバックする。CN-ID の使用は
    /// RFC 9110 Section 4.3.4 で MUST NOT とされているが、aws-lc の後方互換
    /// 挙動に従い現状は許容する) にも使用される (RFC 9001 Section 4.4)。
    /// `verify_peer` が false の場合は `SSL_VERIFY_NONE` のためホスト名検証は効かない。
    ///
    /// `server_name` は **DNS 名に限定** する。ホスト名検証は IP アドレス SAN を
    /// 照合しないため、IP アドレスを渡すと正しい証明書でも必ず検証失敗する。
    /// 空文字列・ワイルドカード・255 文字超はホスト名検証の誤動作や SNI の
    /// 仕様違反 (RFC 6066 Section 3 は HostName を FQDN に限定) につながるため
    /// 拒否する。
    ///
    /// # Errors
    ///
    /// サーバーセッションの場合、`server_name` が DNS 名として不正な場合、
    /// SNI またはホスト名検証の設定に失敗した場合はエラーを返す。
    pub fn set_server_name(&mut self, server_name: &str) -> Result<()> {
        if self.is_server {
            return Err(Error::InvalidArgument(
                "cannot set server name on server session".to_string(),
            ));
        }

        // ホスト名検証は DNS 名限定。IP アドレス・空文字列・ワイルドカード・
        // 長すぎる名前を拒否する
        if server_name.is_empty() {
            return Err(Error::InvalidArgument(
                "server_name must be a DNS name, not empty".to_string(),
            ));
        }
        if server_name.parse::<std::net::IpAddr>().is_ok() {
            return Err(Error::InvalidArgument(
                "server_name must be a DNS name, not an IP address".to_string(),
            ));
        }
        if server_name.contains('*') {
            return Err(Error::InvalidArgument(
                "server_name must be a DNS name, not a wildcard".to_string(),
            ));
        }
        // DNS 名 (FQDN) の長さ制限は 255 オクテット (RFC 1035 Section 2.3.4)。
        // RFC 6066 Section 3 は HostName を FQDN に限定しており、
        // これを超える文字列は FQDN として無効
        if server_name.len() > 255 {
            return Err(Error::InvalidArgument(
                "server_name exceeds 255 bytes".to_string(),
            ));
        }

        let server_name_cstr = CString::new(server_name)
            .map_err(|_| Error::InvalidArgument("invalid server name".to_string()))?;

        // SAFETY: self.ssl は有効な SSL。server_name_cstr は呼び出し中のみ有効だが、
        // aws-lc は内部で複製するため呼び出し後に解放されて問題ない。
        unsafe {
            let rv = SSL_set_tlsext_host_name(self.ssl, server_name_cstr.as_ptr());
            if rv != 1 {
                return Err(Error::Internal(
                    "SSL_set_tlsext_host_name failed".to_string(),
                ));
            }

            // ホスト名検証を設定する (SSL_VERIFY_NONE のときは効かない)
            // 証明書の dNSName と server_name を照合する
            let rv = aws_lc_sys::SSL_set1_host(self.ssl, server_name_cstr.as_ptr());
            if rv != 1 {
                return Err(Error::Internal("SSL_set1_host failed".to_string()));
            }
        }

        Ok(())
    }

    /// QUIC トランスポートパラメータを設定する
    ///
    /// ngtcp2_conn に接続する前に呼び出す必要がある。
    pub fn set_quic_transport_params(&mut self, params: &[u8]) -> Result<()> {
        // SAFETY: self.ssl は有効な SSL。params は呼び出し中のみ有効だが、
        // aws-lc は内部で複製するため呼び出し後に解放されて問題ない。
        unsafe {
            let rv =
                aws_lc_sys::SSL_set_quic_transport_params(self.ssl, params.as_ptr(), params.len());
            if rv != 1 {
                return Err(Error::Internal(
                    "SSL_set_quic_transport_params failed".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// 交渉された ALPN プロトコルを返す (RFC 7301 Section 3)
    ///
    /// ハンドシェイクで ALPN が確定するまでは `None` を返す。サーバーが
    /// ALPN を選択しなかった場合 (クライアントの提示と一致しない場合) も
    /// `None` になる。
    ///
    /// 戻り値はプロトコル名のバイト列で、ワイヤーフォーマットの長さ
    /// プレフィックスは含まない。
    pub fn selected_alpn_protocol(&self) -> Option<Vec<u8>> {
        let mut data: *const u8 = std::ptr::null();
        let mut len: u32 = 0;

        // SAFETY: self.ssl は有効な SSL。aws-lc は out_data に SSL が所有する
        // 領域へのポインタと out_len にその長さを書き込む。
        unsafe {
            aws_lc_sys::SSL_get0_alpn_selected(self.ssl, &mut data, &mut len);
        }

        if data.is_null() || len == 0 {
            return None;
        }

        // 返されるポインタは SSL の生存期間中だけ有効なため複製する。
        // SAFETY: data は len バイトの有効な領域を指す
        Some(unsafe { std::slice::from_raw_parts(data, len as usize) }.to_vec())
    }

    /// 前回の接続で保存したセッションを設定する (クライアント専用)
    ///
    /// ハンドシェイクを開始する前 (最初の [`crate::Connection::write_pkt`] の前)
    /// に呼び出す必要がある。aws-lc の `SSL_set_session` はハンドシェイク開始後に
    /// 呼ぶとプロセスを異常終了させるため、本メソッドは接続の作成時にだけ使う。
    ///
    /// 戻り値は 0-RTT (early data) を送れる状態になったかどうか。サーバーが
    /// 0-RTT を受け入れない設定でチケットを発行した場合など、セッションが
    /// early data に対応していない場合は false を返す。その場合もセッションは
    /// 設定されるため、通常のハンドシェイクとして再開される。
    ///
    /// # Errors
    ///
    /// サーバーセッションの場合、`session` が空または aws-lc のセッション
    /// 形式として不正な場合に [`Error::InvalidArgument`] を返す。
    pub fn set_session(&mut self, session: &[u8]) -> Result<bool> {
        if self.is_server {
            return Err(Error::InvalidArgument(
                "cannot set session on server session".to_string(),
            ));
        }
        if session.is_empty() {
            return Err(Error::InvalidArgument("session is empty".to_string()));
        }

        // SAFETY: self.ssl は有効。SSL_SESSION_from_bytes は ctx を
        // 証明書のパース方法の決定に使うため、この SSL の SSL_CTX を渡す。
        unsafe {
            let parsed =
                SSL_SESSION_from_bytes(session.as_ptr(), session.len(), SSL_get_SSL_CTX(self.ssl));
            if parsed.is_null() {
                aws_lc_sys::ERR_clear_error();
                return Err(Error::InvalidArgument("invalid TLS session".to_string()));
            }

            // early data の可否はセッションを解放する前に判定する
            let early_data_capable = SSL_SESSION_early_data_capable(parsed) != 0;
            let rv = SSL_set_session(self.ssl, parsed);
            SSL_SESSION_free(parsed);
            if rv != 1 {
                aws_lc_sys::ERR_clear_error();
                return Err(Error::InvalidArgument(
                    "TLS session cannot be set".to_string(),
                ));
            }

            // サーバーが 0-RTT を受理するチケットを発行した場合にだけ
            // early data を有効にする (RFC 9001 Section 4.6.1)。
            //
            // 有効にすると、ngtcp2_crypto が QUIC メソッドの set_write_secret を
            // early data レベルで受け取り、ngtcp2_crypto_derive_and_install_tx_key
            // で 0-RTT の送信鍵を ngtcp2_conn にインストールする
            // (crypto/boringssl/boringssl.c の実装による)。
            if early_data_capable {
                SSL_set_early_data_enabled(self.ssl, 1);
            }

            Ok(early_data_capable)
        }
    }

    /// 受け取ったセッションチケットを取り出す (クライアント専用)
    ///
    /// TLS 1.3 の NewSessionTicket はハンドシェイク完了後に届く
    /// (RFC 8446 Section 4.6.1)。ハンドシェイク完了後にパケットを処理した
    /// あとに呼び出すこと。まだ届いていない場合と、一度取り出した後は
    /// `None` を返す。
    pub fn take_session_ticket(&mut self) -> Option<Vec<u8>> {
        self.ticket_slot.as_ref()?.take()
    }

    /// 0-RTT (early data) を送受信している最中かどうかを返す
    /// (RFC 9001 Section 4.6)
    ///
    /// クライアントでは ClientHello を送ってからハンドシェイクが完了するまでの
    /// 間、サーバーでは 0-RTT データを処理している間 true になる。
    pub fn is_in_early_data(&self) -> bool {
        // SAFETY: self.ssl は有効。値は読み取るだけで変更しない
        unsafe { SSL_in_early_data(self.ssl) != 0 }
    }

    /// 0-RTT (early data) がサーバーに受理されたかどうかを返す
    /// (RFC 9001 Section 4.6.2)
    ///
    /// クライアント専用。ハンドシェイクが完了するまでは、受理されたかどうかは
    /// 確定しない (拒否は [`crate::ConnectionEvent::EarlyDataRejected`] で通知される)。
    pub fn is_early_data_accepted(&self) -> bool {
        // SAFETY: self.ssl は有効。値は読み取るだけで変更しない
        unsafe { SSL_early_data_accepted(self.ssl) != 0 }
    }

    /// 0-RTT (early data) を受け入れる設定かどうかを返す (サーバー用)
    pub(crate) fn accepts_early_data(&self) -> bool {
        self.accept_early_data
    }

    /// 0-RTT を受け入れる条件 (early data context) を設定する (サーバー専用)
    ///
    /// aws-lc は、チケットを発行した接続と 0-RTT を再開した接続でこの値が
    /// 一致する場合にだけ early data を受け入れる (`quic_ticket_compatible`)。
    /// 0-RTT で送れるデータ量はサーバーのトランスポートパラメータで決まるため、
    /// そのうち 0-RTT に影響するものをエンコードした値を設定する。
    /// `original_dcid` や Stateless Reset トークンのように接続ごとに変わる値を
    /// 含めると、常に一致しなくなり 0-RTT が受理されない。
    ///
    /// # Errors
    ///
    /// クライアントセッションの場合、設定に失敗した場合はエラーを返す。
    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<()> {
        if !self.is_server {
            return Err(Error::InvalidArgument(
                "cannot set early data context on client session".to_string(),
            ));
        }

        // SAFETY: self.ssl は有効。context は呼び出し中のみ有効だが、
        // aws-lc は内部に複製するため呼び出し後に解放されて問題ない。
        let rv =
            unsafe { SSL_set_quic_early_data_context(self.ssl, context.as_ptr(), context.len()) };
        if rv != 1 {
            return Err(Error::Internal(
                "SSL_set_quic_early_data_context failed".to_string(),
            ));
        }

        Ok(())
    }

    /// 生の `SSL` ポインタを取得する
    pub(crate) fn as_ptr(&self) -> *mut SSL {
        self.ssl
    }

    /// 生の `SSL` ポインタを `c_void` として取得する (ngtcp2 用)
    pub(crate) fn as_void_ptr(&self) -> *mut c_void {
        self.ssl as *mut c_void
    }
}

impl Drop for TlsSession {
    fn drop(&mut self) {
        if !self.ssl.is_null() {
            // SAFETY: self.ssl は SSL_new で生成した未解放のポインタ
            unsafe {
                SSL_free(self.ssl);
            }
        }
    }
}

/// ALPN 選択コールバック (サーバー用)
///
/// クライアントが提示した ALPN リストから、サーバーがサポートするプロトコルを選択する。
/// 一致するものがない場合は `SSL_TLSEXT_ERR_NOACK` を返し、ハンドシェイクを失敗させる
/// (一致しない ALPN で接続を成立させない)。
unsafe extern "C" fn alpn_select_callback(
    _ssl: *mut SSL,
    out: *mut *const u8,
    outlen: *mut u8,
    client_alpn: *const u8,
    client_alpn_len: u32,
    arg: *mut c_void,
) -> i32 {
    const SSL_TLSEXT_ERR_OK: i32 = 0;
    const SSL_TLSEXT_ERR_NOACK: i32 = 3;

    if arg.is_null() {
        return SSL_TLSEXT_ERR_NOACK;
    }

    // SAFETY: arg は TlsContext::new_server で Box::into_raw した Vec<u8> へのポインタ。
    // TlsContext の生存期間中有効であることが保証されている。
    let server_alpn = unsafe { &*(arg as *const Vec<u8>) };
    // SAFETY: client_alpn と client_alpn_len は aws-lc から渡された有効な領域
    let client_alpn_slice =
        unsafe { std::slice::from_raw_parts(client_alpn, client_alpn_len as usize) };

    // サーバーの ALPN リストをパースする
    let mut server_pos = 0;
    while server_pos < server_alpn.len() {
        let server_proto_len = server_alpn[server_pos] as usize;
        server_pos += 1;
        if server_pos + server_proto_len > server_alpn.len() {
            break;
        }
        let server_proto = &server_alpn[server_pos..server_pos + server_proto_len];
        server_pos += server_proto_len;

        // クライアントの ALPN リストをパースする
        let mut client_pos = 0;
        while client_pos < client_alpn_slice.len() {
            let client_proto_len = client_alpn_slice[client_pos] as usize;
            client_pos += 1;
            if client_pos + client_proto_len > client_alpn_slice.len() {
                break;
            }
            let client_proto = &client_alpn_slice[client_pos..client_pos + client_proto_len];
            client_pos += client_proto_len;

            // マッチした場合はクライアントのリスト内の位置を返す
            if server_proto == client_proto {
                // SAFETY: out と outlen は呼び出し元から渡された有効なポインタ。
                // client_alpn の領域はハンドシェイク中 aws-lc が保持する。
                unsafe {
                    *out = client_alpn.add(client_pos - client_proto_len);
                    *outlen = client_proto_len as u8;
                }
                return SSL_TLSEXT_ERR_OK;
            }
        }
    }

    SSL_TLSEXT_ERR_NOACK
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ALPN がワイヤーフォーマットに正しくエンコードされること
    #[test]
    fn test_encode_alpn() {
        let alpn = TlsContext::encode_alpn(&[b"hq-interop", b"h3"]);
        assert_eq!(
            alpn,
            vec![
                10, b'h', b'q', b'-', b'i', b'n', b't', b'e', b'r', b'o', b'p', 2, b'h', b'3'
            ],
            "ALPN のワイヤーフォーマット (RFC 7301 Section 3.1)"
        );
    }

    /// クライアントコンテキストが作成できること
    #[test]
    fn test_client_context_creation() {
        let ctx = TlsContext::new_client(&[b"hq-interop"]);
        assert!(ctx.is_ok(), "クライアントコンテキストが作成できること");

        let ctx = TlsContext::new_client_with_options(&[b"hq-interop"], false);
        assert!(
            ctx.is_ok(),
            "verify_peer=false のコンテキストが作成できること"
        );
    }

    /// クライアントセッションが作成でき、SSL ポインタが有効であること
    #[test]
    fn test_client_session_creation() {
        let ctx = TlsContext::new_client(&[b"hq-interop"]).expect("test must succeed");
        let session = ctx.create_session().expect("セッションが作成できること");
        assert!(!session.as_ptr().is_null(), "SSL ポインタが有効であること");
        assert!(
            !session.as_void_ptr().is_null(),
            "c_void ポインタが有効であること"
        );
    }

    /// クライアントセッションに SNI を設定できること
    #[test]
    fn test_set_server_name_on_client() {
        let ctx = TlsContext::new_client(&[b"hq-interop"]).expect("test must succeed");
        let mut session = ctx.create_session().expect("test must succeed");
        session
            .set_server_name("localhost")
            .expect("SNI が設定できること");
    }

    /// SNI に DNS 名以外を渡すと拒否されること
    #[test]
    fn test_set_server_name_rejects_invalid_names() {
        let ctx = TlsContext::new_client(&[b"hq-interop"]).expect("test must succeed");
        let mut session = ctx.create_session().expect("test must succeed");

        for name in ["", "127.0.0.1", "::1", "*.example.com"] {
            let err = session
                .set_server_name(name)
                .expect_err("不正な server_name は拒否されること");
            assert!(
                matches!(err, Error::InvalidArgument(_)),
                "server_name={name:?} は InvalidArgument であること: {err:?}"
            );
        }

        // 255 バイトを超える名前は拒否されること
        let long_name = "a".repeat(256);
        let err = session
            .set_server_name(&long_name)
            .expect_err("長すぎる server_name は拒否されること");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "255 バイト超は InvalidArgument であること: {err:?}"
        );
    }

    /// ハンドシェイク前は ALPN が未交渉であること
    ///
    /// ALPN は TLS ハンドシェイクの中で確定するため (RFC 7301 Section 3)、
    /// 作りたてのセッションでは `None` になる。
    #[test]
    fn test_selected_alpn_protocol_is_none_before_handshake() {
        let ctx = TlsContext::new_client(&[b"hq-interop", b"h3"]).expect("test must succeed");
        let session = ctx.create_session().expect("セッションが作成できること");
        assert_eq!(
            session.selected_alpn_protocol(),
            None,
            "ハンドシェイク前は ALPN が未交渉であること"
        );
    }

    /// QUIC トランスポートパラメータを設定できること
    #[test]
    fn test_set_quic_transport_params() {
        let ctx = TlsContext::new_client(&[b"hq-interop"]).expect("test must succeed");
        let mut session = ctx.create_session().expect("test must succeed");
        session
            .set_quic_transport_params(&[1, 2, 3, 4])
            .expect("トランスポートパラメータが設定できること");
    }

    /// 不正な PEM は InvalidArgument で拒否されること
    #[test]
    fn test_add_ca_cert_pem_rejects_invalid_pem() {
        let mut ctx =
            TlsContext::new_client_with_options(&[b"hq-interop"], true).expect("test must succeed");
        let err = ctx
            .add_ca_cert_pem("not a pem")
            .expect_err("不正な PEM は拒否される");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "不正な PEM は InvalidArgument であること: {err:?}"
        );
    }

    /// verify_peer=false のコンテキストでは CA 追加が拒否されること
    #[test]
    fn test_add_ca_cert_pem_rejects_when_verify_peer_false() {
        let mut ctx = TlsContext::new_client_with_options(&[b"hq-interop"], false)
            .expect("test must succeed");
        let err = ctx
            .add_ca_cert_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
            .expect_err("verify_peer=false では拒否される");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "verify_peer=false では CA 追加が拒否されること: {err:?}"
        );
    }

    /// 有効な PEM をトラストストアに追加できること
    #[test]
    fn test_add_ca_cert_pem_accepts_valid_pem() {
        let key = rcgen::KeyPair::generate().expect("test must succeed");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("test must succeed");
        let cert = params.self_signed(&key).expect("test must succeed");

        let mut ctx =
            TlsContext::new_client_with_options(&[b"hq-interop"], true).expect("test must succeed");
        ctx.add_ca_cert_pem(&cert.pem())
            .expect("有効な PEM が追加できること");
    }

    /// サーバーコンテキストでは CA 追加が拒否されること
    #[test]
    fn test_add_ca_cert_pem_rejects_on_server_context() {
        let (cert_path, key_path) = crate::tests::generate_test_certs("crypto_ca_server");

        let mut ctx = TlsContext::new_server(&cert_path, &key_path, &[b"hq-interop"])
            .expect("test must succeed");
        let err = ctx
            .add_ca_cert_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
            .expect_err("サーバーコンテキストでは拒否される");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "サーバーコンテキストでは CA 追加が拒否されること: {err:?}"
        );

        crate::tests::remove_test_certs(&cert_path, &key_path);
    }

    /// 不透明な証明書パスではエラーになること
    #[test]
    fn test_new_server_rejects_missing_cert() {
        let cert_path = std::path::Path::new("/nonexistent/cert.pem");
        let key_path = std::path::Path::new("/nonexistent/key.pem");
        let result = TlsContext::new_server(cert_path, key_path, &[b"hq-interop"]);
        assert!(result.is_err(), "存在しない証明書パスはエラーになること");
    }

    /// セッションチケットを受け取るコールバックが NULL でも安全であること
    ///
    /// コールバックは extern "C" であり、aws-lc が NULL を渡しても
    /// パニックしてはいけない。
    #[test]
    fn test_new_session_callback_rejects_null() {
        // SAFETY: NULL を渡すこと自体は安全。中身を参照しないことを確認する
        let rv = unsafe { new_session_callback(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(rv, 0, "NULL のときは 0 を返すこと");
    }

    /// 作りたてのセッションは early data の状態ではないこと
    #[test]
    fn test_early_data_state_before_handshake() {
        let ctx = TlsContext::new_client(&[b"hq-interop"]).expect("test must succeed");
        let mut session = ctx.create_session().expect("test must succeed");

        assert!(
            !session.is_in_early_data(),
            "セッションを設定していなければ 0-RTT を送らないこと"
        );
        assert!(
            !session.is_early_data_accepted(),
            "ハンドシェイク前は受理が確定しないこと"
        );
        assert!(
            session.take_session_ticket().is_none(),
            "ハンドシェイク前はチケットが無いこと"
        );
    }

    /// 不正なセッションは InvalidArgument で拒否されること
    #[test]
    fn test_set_session_rejects_invalid_bytes() {
        let ctx = TlsContext::new_client(&[b"hq-interop"]).expect("test must succeed");
        let mut session = ctx.create_session().expect("test must succeed");

        for bytes in [b"not a session".as_slice(), &[0x30, 0x00]] {
            let err = session
                .set_session(bytes)
                .expect_err("不正なセッションは拒否されること");
            assert!(
                matches!(err, Error::InvalidArgument(_)),
                "不正なセッションは InvalidArgument であること: {err:?}"
            );
        }

        // 空のセッションも拒否されること
        let err = session
            .set_session(&[])
            .expect_err("空のセッションは拒否されること");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "空のセッションは InvalidArgument であること: {err:?}"
        );
    }

    /// サーバーセッションにはセッションを設定できないこと
    #[test]
    fn test_set_session_rejects_on_server_session() {
        let (cert_path, key_path) = crate::tests::generate_test_certs("crypto_set_session");
        let ctx = TlsContext::new_server(&cert_path, &key_path, &[b"hq-interop"])
            .expect("test must succeed");
        let mut session = ctx.create_session().expect("test must succeed");

        let err = session
            .set_session(&[0x30, 0x00])
            .expect_err("サーバーセッションでは拒否されること");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "サーバーセッションでは InvalidArgument であること: {err:?}"
        );

        crate::tests::remove_test_certs(&cert_path, &key_path);
    }

    /// クライアントコンテキストでは 0-RTT の受け入れを設定できないこと
    #[test]
    fn test_set_accept_early_data_rejects_on_client_context() {
        let mut ctx = TlsContext::new_client(&[b"hq-interop"]).expect("test must succeed");
        let err = ctx
            .set_accept_early_data(true)
            .expect_err("クライアントコンテキストでは拒否されること");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "クライアントコンテキストでは InvalidArgument であること: {err:?}"
        );
    }

    /// サーバーコンテキストで 0-RTT の受け入れを設定できること
    #[test]
    fn test_set_accept_early_data_on_server_context() {
        let (cert_path, key_path) = crate::tests::generate_test_certs("crypto_accept_early");
        let mut ctx = TlsContext::new_server(&cert_path, &key_path, &[b"hq-interop"])
            .expect("test must succeed");

        // 既定では受け入れない
        let session = ctx.create_session().expect("test must succeed");
        assert!(
            !session.accepts_early_data(),
            "既定では 0-RTT を受け入れないこと"
        );

        ctx.set_accept_early_data(true)
            .expect("0-RTT の受け入れを設定できること");
        let session = ctx.create_session().expect("test must succeed");
        assert!(
            session.accepts_early_data(),
            "設定後は 0-RTT を受け入れること"
        );

        // 無効に戻せること
        ctx.set_accept_early_data(false)
            .expect("0-RTT の受け入れを無効にできること");
        let session = ctx.create_session().expect("test must succeed");
        assert!(
            !session.accepts_early_data(),
            "無効にすると 0-RTT を受け入れないこと"
        );

        crate::tests::remove_test_certs(&cert_path, &key_path);
    }

    /// サーバーセッションに early data context を設定できること
    #[test]
    fn test_set_quic_early_data_context_on_server_session() {
        let (cert_path, key_path) = crate::tests::generate_test_certs("crypto_early_ctx");
        let ctx = TlsContext::new_server(&cert_path, &key_path, &[b"hq-interop"])
            .expect("test must succeed");
        let mut session = ctx.create_session().expect("test must succeed");

        session
            .set_quic_early_data_context(&[1, 2, 3])
            .expect("early data context を設定できること");

        crate::tests::remove_test_certs(&cert_path, &key_path);
    }

    /// クライアントセッションには early data context を設定できないこと
    #[test]
    fn test_set_quic_early_data_context_rejects_on_client_session() {
        let ctx = TlsContext::new_client(&[b"hq-interop"]).expect("test must succeed");
        let mut session = ctx.create_session().expect("test must succeed");

        let err = session
            .set_quic_early_data_context(&[1, 2, 3])
            .expect_err("クライアントセッションでは拒否されること");
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "クライアントセッションでは InvalidArgument であること: {err:?}"
        );
    }
}
