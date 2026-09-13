//! QUIC サーバーの非同期実装

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use shiguredo_ngtcp2::{
    AcceptedInitial, AddressValidationToken, AddressValidationTokenKind, ConnStats, Connection,
    ConnectionErrorKind, ConnectionId, Error, PacketInfo, PacketVersion, PathInfo, QuicVersion,
    RemoteTransportParams, Result, RetrySecret, Settings, StatelessResetSecret, StreamId,
    TRANSPORT_ERROR_INVALID_TOKEN, TlsContext, TransportParams, accept_initial,
    decode_packet_version, generate_new_token, generate_retry_token, verify_new_token,
    verify_retry_token, write_retry_packet, write_stateless_connection_close,
    write_stateless_reset, write_version_negotiation,
};

use crate::qlog::{QlogWriter, file_name};
use crate::socket::{ServerSockets, timestamp};
use crate::streams::{
    OutgoingPacket, PendingStreams, close_packets, write_control_packets, write_packets,
};
use crate::{ConnectionEvent, DatagramConfig};

/// Retry トークンの既定の有効期間
///
/// クライアントが Retry を受け取ってから新しい Initial を送るまでの時間。
/// RFC 9000 Section 8.1.3 はトークンを短い期間だけ有効にすることを求めており、
/// 遅延の大きい経路でも再接続が間に合う 10 秒を既定にする。
const DEFAULT_RETRY_TOKEN_TIMEOUT: Duration = Duration::from_secs(10);

/// サーバーが発行する SCID の既定の長さ (バイト)
///
/// Short header パケットは DCID 長を運ばないため (RFC 9000 Section 17.3)、
/// サーバーは発行した CID の長さの集合で照合する。
const DEFAULT_SCID_LEN: usize = 16;

/// 長さ 0 のコネクション ID を使う場合の、接続ごとの内部キーの長さ (バイト)
///
/// このキーはパケットには載らず、サーバーが接続を識別するためにだけ使う。
const INTERNAL_KEY_LEN: usize = 16;

/// サーバーがパケットに載せる SCID を作る
///
/// 長さ 0 を指定した場合は長さ 0 のコネクション ID を返す。この場合
/// サーバーはコネクション ID でパケットを識別できないため、ピアの
/// アドレスで振り分ける (RFC 9000 Section 5.1)。
fn generate_scid(scid_len: usize) -> Option<ConnectionId> {
    if scid_len == 0 {
        Some(ConnectionId::empty())
    } else {
        ConnectionId::random(scid_len)
    }
}

/// 受信バッファのサイズ (バイト)
const RECV_BUFFER_SIZE: usize = 65535;

/// 送信バッファのサイズ (バイト)
const SEND_BUFFER_SIZE: usize = 65535;

/// Stateless Reset の送信を制限するバースト上限 (個)
///
/// 未知の DCID を持つパケットは認証されていないため、無制限に応答すると
/// 反射型の増幅攻撃に使える。RFC 9000 Section 10.3.3 のレート制限要件に従い、
/// バケット方式で上限を設ける。
const STATELESS_RESET_BURST: u64 = 100;

/// Stateless Reset の送信を制限する補充レート (個 / 秒)
const STATELESS_RESET_RATE: u64 = 33;

/// 1 秒のナノ秒数
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// 引き渡し済みのコネクション ID を覚えておく上限
///
/// [`Server::accept`] が接続を [`AcceptedConnection`] に引き渡すと、
/// ルーティングテーブルからは削除される。その CID を持つパケットは
/// 「接続状態を失った」ように見えるが、実際には同じプロセス内で生きているため
/// Stateless Reset を返してはいけない。直近の引き渡し分だけを覚えて除外する。
///
/// 上限は `MAX_CONNECTIONS` x 1 接続あたりの CID 数程度の余裕を持たせた値。
/// 超過時は古いものから忘れるため、古い接続は Stateless Reset の対象に
/// 戻りうる (その場合でもピアはトークンを検証するため誤動作はしない)。
const MAX_TAKEN_CIDS: usize = 8192;

/// サーバーが同時に保持する接続数の上限
///
/// 未認証の Initial で接続状態を無制限に作らせないための上限。
/// 超過した接続は破棄する (RFC 9000 Section 11.1 は不正な Initial の破棄を認めている)。
const MAX_CONNECTIONS: usize = 1024;

/// サーバーの設定
#[derive(Clone)]
pub struct ServerConfig {
    /// ALPN プロトコルリスト (RFC 7301)
    ///
    /// クライアントの提示するリストと一致しない場合はハンドシェイクが失敗する。
    pub alpn_protocols: Vec<Vec<u8>>,
    /// トランスポートパラメータ (RFC 9000 Section 18)
    pub transport_params: TransportParams,
    /// DATAGRAM の設定 (RFC 9221)
    pub datagram: DatagramConfig,
    /// サーバーが能動的に発行する SCID の長さ (バイト)
    pub scid_len: usize,
    /// サポートする QUIC バージョン (RFC 9000 Section 6)
    ///
    /// この一覧にないバージョンの Long header パケットには Version Negotiation
    /// パケットを返す。空にするとどのクライアントとも接続できないため、
    /// [`Server::bind`] が拒否する。
    pub quic_versions: Vec<QuicVersion>,
    /// 接続設定 (輻輳制御アルゴリズム、初期 RTT、keep-alive など)
    ///
    /// [`Settings::initial_ts`] は接続の作成時に実際の時刻で上書きされるため、
    /// 設定しておく必要はない。
    ///
    /// `Settings::stateless_reset_secret` は [`Server::bind`] が
    /// `ServerConfig::stateless_reset_secret` の値で上書きするため、
    /// ここに設定する必要はない。
    pub settings: Settings,
    /// Retry によるアドレス検証に使う秘密 (RFC 9000 Section 8.1.2)
    ///
    /// 設定すると、トークンを持たない Initial に対して Retry パケットを返し、
    /// 再接続時にトークンを検証してから接続状態を作る。設定しない場合
    /// (既定) は Retry を送らず、最初の Initial で接続を作る。
    ///
    /// [`Server::bind`] が `None` のときに乱数から生成することはない。
    /// アドレス検証は明示的に有効化する機能であり、有効にすると
    /// すべての接続に 1 RTT が加わるため。
    pub retry_secret: Option<RetrySecret>,
    /// Retry トークンの有効期間
    ///
    /// Retry を送ってからクライアントが再接続するまでの許容時間。
    /// 既定は 10 秒。短すぎると遅延の大きいクライアントが検証に失敗する。
    pub retry_token_timeout: Duration,
    /// Stateless Reset トークンを導出するための秘密 (RFC 9000 Section 10.3.1)
    ///
    /// `None` の場合は [`Server::bind`] が乱数から生成する。プロセスの再起動を
    /// またいでもピアが保持するトークンと一致させたい場合は、永続化した値を
    /// [`ServerConfig::with_stateless_reset_secret`] で渡すこと。
    pub stateless_reset_secret: Option<StatelessResetSecret>,
    /// qlog の出力先ディレクトリ
    ///
    /// 指定すると接続ごとに `<ディレクトリ>/<SCID>.sqlog` を作り、qlog を
    /// 書き出す。`None` の場合は出力しない。
    pub qlog_dir: Option<std::path::PathBuf>,
    /// 優先アドレス (RFC 9000 Section 9.6)
    ///
    /// 指定すると、そのアドレスで 2 つ目のソケットを待ち受ける。接続を
    /// 確立したクライアントは、通知された優先アドレスへ移る。
    pub preferred_address: Option<SocketAddr>,
    /// NEW_TOKEN フレームでアドレス検証トークンを配布するかどうか
    /// (RFC 9000 Section 8.1.3)
    ///
    /// 有効にすると、アドレスを検証できた接続に対してトークンを配布する。
    /// クライアントは次の接続の Initial にトークンを載せることで、Retry を
    /// 省略できる。トークンの生成には [`ServerConfig::with_retry`] の秘密を
    /// 使うため、Retry を有効にしていない場合は配布しない。
    pub new_token: bool,
    /// 0-RTT (early data) を受け入れるかどうか (RFC 9001 Section 4.6)
    ///
    /// 既定は false。true にすると、クライアントが前回の接続で得たチケットを
    /// 使って送った 0-RTT データを受け入れる。
    ///
    /// 0-RTT のデータはリプレイ攻撃に対して脆弱であり (RFC 9001 Section 9.2)、
    /// 本クレートはアンチリプレイの仕組みを提供しない。有効にする場合は
    /// アプリケーション側で対策すること。
    pub early_data: bool,
}

impl ServerConfig {
    /// ALPN を指定して設定を作成する
    ///
    /// - `transport_params`: [`TransportParams::new()`]
    /// - `datagram`: [`DatagramConfig::default()`]
    /// - `scid_len`: 16
    /// - `quic_versions`: QUIC v1 と QUIC v2
    /// - `settings`: [`Settings::new`]`(0)`
    pub fn new(alpn_protocols: &[&[u8]]) -> Self {
        Self {
            alpn_protocols: alpn_protocols.iter().map(|p| p.to_vec()).collect(),
            transport_params: TransportParams::new(),
            datagram: DatagramConfig::default(),
            scid_len: DEFAULT_SCID_LEN,
            quic_versions: vec![QuicVersion::V1, QuicVersion::V2],
            // initial_ts と address_validation_token は接続の作成時に上書きされる
            settings: Settings::new(0),
            retry_secret: None,
            retry_token_timeout: DEFAULT_RETRY_TOKEN_TIMEOUT,
            stateless_reset_secret: None,
            qlog_dir: None,
            preferred_address: None,
            new_token: false,
            early_data: false,
        }
    }

    /// 0-RTT (early data) の受け入れを有効にする (RFC 9001 Section 4.6)
    ///
    /// 有効にすると、クライアントが前回の接続で得たチケットを使って送った
    /// 0-RTT データを受け入れる。既定では無効。
    ///
    /// 0-RTT のデータはリプレイ攻撃に対して脆弱であり (RFC 9001 Section 9.2)、
    /// 同じデータが複数回届きうる。本クレートはアンチリプレイの仕組みを
    /// 提供しないため、有効にする場合はアプリケーション側で対策すること。
    /// 対策できない場合は有効にしないこと。
    pub fn with_early_data(mut self, early_data: bool) -> Self {
        self.early_data = early_data;
        self
    }

    /// Retry によるアドレス検証を有効にする (RFC 9000 Section 8.1.2)
    ///
    /// 有効にすると、トークンを持たない Initial には接続状態を作らずに
    /// Retry パケットを返す。偽造した送信元アドレスを使った増幅攻撃を防げるが、
    /// すべての接続に 1 RTT が加わる。
    pub fn with_retry(mut self, secret: RetrySecret) -> Self {
        self.retry_secret = Some(secret);
        self
    }

    /// 互換バージョン交渉で提示するバージョンを設定する (RFC 9368)
    ///
    /// 優先順に並べる。クライアントが提示したバージョンのうちこの一覧に
    /// 含まれるものがある場合、Version Negotiation パケットを返さずに
    /// そのバージョンで接続を確立する。 [`ServerConfig::with_quic_versions`] に
    /// 含まれるバージョンだけを指定すること。
    pub fn with_preferred_versions(mut self, versions: &[QuicVersion]) -> Self {
        self.settings.preferred_versions = versions.to_vec();
        // 相手に通知する利用可能なバージョンも同じ一覧にする
        self.settings.available_versions = versions.to_vec();
        self
    }

    /// 優先アドレスを設定する (RFC 9000 Section 9.6)
    ///
    /// 指定したアドレスで 2 つ目のソケットを待ち受ける。クライアントには
    /// 実際に bind できたアドレスを通知するため、ポートに 0 を指定すると
    /// OS が割り当てたポートが通知される (RFC 9000 Section 18.2)。
    ///
    /// クライアントはハンドシェイクの確認後、このアドレスへ自分から移る。
    /// アドレス検証を有効にした接続 (Retry) では、優先アドレスで受け取った
    /// Initial にも同じアドレスから応答する (RFC 9000 Section 9.6.1)。
    pub fn with_preferred_address(mut self, addr: SocketAddr) -> Self {
        self.preferred_address = Some(addr);
        self
    }

    /// qlog の出力先ディレクトリを設定する
    ///
    /// 接続ごとに `<ディレクトリ>/<SCID>.sqlog` を作り、qlog (JSON Text
    /// Sequence、RFC 7464) を書き出す。ディレクトリが無い場合は作る。
    /// ファイルを開けない場合は qlog を無効にして接続は続ける。
    pub fn with_qlog_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.qlog_dir = Some(dir.into());
        self
    }

    /// NEW_TOKEN フレームでのトークンの配布を有効にする
    /// (RFC 9000 Section 8.1.3)
    ///
    /// アドレスを検証できた接続に対してトークンを配布し、クライアントが次の
    /// 接続で Retry を省略できるようにする。トークンの生成と検証には
    /// [`ServerConfig::with_retry`] の秘密を使う。
    pub fn with_new_token(mut self, new_token: bool) -> Self {
        self.new_token = new_token;
        self
    }

    /// Retry トークンの有効期間を設定する
    pub fn with_retry_token_timeout(mut self, timeout: Duration) -> Self {
        self.retry_token_timeout = timeout;
        self
    }

    /// Stateless Reset トークンを導出するための秘密を設定する
    /// (RFC 9000 Section 10.3.1)
    ///
    /// 設定しない場合は [`Server::bind`] が乱数から生成する。
    pub fn with_stateless_reset_secret(mut self, secret: StatelessResetSecret) -> Self {
        self.stateless_reset_secret = Some(secret);
        self
    }

    /// 接続設定を設定する
    ///
    /// [`Settings::initial_ts`] は接続の作成時に実際の時刻で上書きされる。
    pub fn with_settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    /// サポートする QUIC バージョンを設定する (RFC 9000 Section 6)
    ///
    /// 先頭ほど優先される。この一覧にないバージョンの Long header パケットには
    /// Version Negotiation パケットを返す。空の一覧は [`Server::bind`] が拒否する。
    pub fn with_quic_versions(mut self, quic_versions: &[QuicVersion]) -> Self {
        self.quic_versions = quic_versions.to_vec();
        self
    }

    /// トランスポートパラメータを設定する
    pub fn with_transport_params(mut self, params: TransportParams) -> Self {
        self.transport_params = params;
        self
    }

    /// DATAGRAM の設定を指定する
    ///
    /// DATAGRAM を有効にする場合は `transport_params` にも
    /// `with_datagram` を設定すること。
    pub fn with_datagram(mut self, datagram: DatagramConfig) -> Self {
        self.datagram = datagram;
        self
    }

    /// サーバーが発行する SCID の長さを設定する (既定は 16 バイト)
    ///
    /// 0 を指定すると、サーバーは長さ 0 のコネクション ID を使う
    /// (RFC 9000 Section 5.1)。この場合、パケットにコネクション ID が
    /// 載らないため、サーバーはピアのアドレスでパケットを接続へ振り分ける。
    ///
    /// 長さ 0 のコネクション ID を使う構成では次が使えない。
    ///
    /// - 接続のマイグレーション (ピアのアドレスが変わると接続を識別できない)
    /// - 優先アドレス ([`ServerConfig::with_preferred_address`])
    /// - Stateless Reset (トークンを配布するコネクション ID が無い)
    ///
    /// また 1 つのアドレスにつき 1 接続だけを識別できるため、同じアドレスを
    /// 複数の接続で共有することはできない。
    pub fn with_scid_len(mut self, scid_len: usize) -> Self {
        self.scid_len = scid_len;
        self
    }

    /// DATAGRAM を反映したトランスポートパラメータを返す
    fn effective_transport_params(&self) -> TransportParams {
        let params = self.transport_params.clone();
        if self.datagram.is_enabled() {
            params.with_datagram(self.datagram.max_datagram_frame_size)
        } else {
            params.with_datagram(0)
        }
    }

    /// ALPN プロトコルリストを `&[&[u8]]` に変換する
    fn alpn_refs(&self) -> Vec<&[u8]> {
        self.alpn_protocols.iter().map(|p| p.as_slice()).collect()
    }
}

/// Version Negotiation が必要なパケットかどうかを判定する (RFC 9000 Section 6)
///
/// `data` が Long header で、`supported_versions` に含まれないバージョンを
/// 使っている場合に Version Negotiation パケットを書くための情報を返す。
///
/// サポートしているバージョンに対して Version Negotiation を送ってはいけない
/// ため (RFC 9000 Section 6)、`supported_versions` に含まれるバージョンは
/// `None` になる。
fn version_negotiation_info(
    data: &[u8],
    supported_versions: &[QuicVersion],
) -> Option<PacketVersion> {
    let info = decode_packet_version(data)?;
    if QuicVersion::from_u32(info.version)
        .is_some_and(|version| supported_versions.contains(&version))
    {
        return None;
    }
    Some(info)
}

/// サポートするバージョンの新規接続 Initial をパースする
///
/// パケットの受理判定は ngtcp2 の `ngtcp2_accept` ([`accept_initial`]) に任せる。
/// 以下を満たすパケットだけを受理する:
///
/// - Long header かつ Initial。Handshake は SHOULD ignore、0-RTT の
///   バッファリングは MAY だが、本実装ではバッファリングを行わず破棄する。
///   状態を持たないパケットでサーバーの接続状態を消費させないため。
/// - サポートしているバージョン
/// - データグラムが 1200 バイト以上 (RFC 9000 Section 14.1 の MUST discard)
/// - トークンが無い場合は DCID が 8 バイト以上 (RFC 9000 Section 7.2 の MUST)
/// - CID 長が 20 以下 (RFC 9000 Section 17.2 の MUST drop)
/// - ゼロ長 CID でないこと (本クレートはゼロ長のコネクション ID を
///   サポートしない)
///
/// 戻り値は `(バージョン, パケットの情報)`。
fn accept_initial_packet(
    data: &[u8],
    supported_versions: &[QuicVersion],
) -> Option<(QuicVersion, AcceptedInitial)> {
    let accepted = accept_initial(data)?;
    let version = QuicVersion::from_u32(accepted.version)?;
    if !supported_versions.contains(&version) {
        return None;
    }
    Some((version, accepted))
}

/// 到着パケットの DCID から接続キーを解決する (RFC 9000 Section 5.2)
///
/// - Long header: DCID 長はヘッダーに含まれるため、そのまま照合する
/// - Short header: DCID 長はヘッダーに含まれないため (RFC 9000 Section 17.3)、
///   サーバーが発行した CID の長さの集合で照合する
///
/// DCID がルーティングテーブルに無い場合は `None` を返す。呼び出し側は
/// `None` の場合に Long header なら新規接続、Short header なら破棄を判断する
/// (Short header の破棄は RFC 9000 Section 5.2.2 の MUST drop に従う)。
/// Stateless Reset (RFC 9000 Section 10.3) は実装しないため、
/// 未知 DCID のパケットには応答せず黙って破棄する。
fn resolve_dcid(
    cid_map: &HashMap<ConnectionId, ConnectionId>,
    short_cid_lengths: &BTreeSet<usize>,
    data: &[u8],
) -> Option<ConnectionId> {
    if data.is_empty() {
        return None;
    }

    if data[0] & 0x80 != 0 {
        // Long header (RFC 9000 Section 17.2)
        if data.len() < 6 {
            return None;
        }
        let dcid_len = data[5] as usize;
        if data.len() < 6 + dcid_len {
            return None;
        }
        let dcid = ConnectionId::new(&data[6..6 + dcid_len])?;
        return cid_map.get(&dcid).cloned();
    }

    // Short header (RFC 9000 Section 17.3)
    //
    // DCID 長を運ばないため、発行済み CID の長いものから順に照合する。
    // パケットの先頭が別長の CID と偶然 prefix 一致した場合の誤ルーティングを
    // 減らすため、長いものから優先する。
    for len in short_cid_lengths.iter().rev() {
        let len = *len;
        if data.len() < 1 + len {
            continue;
        }
        if let Some(dcid) = ConnectionId::new(&data[1..1 + len])
            && let Some(key) = cid_map.get(&dcid)
        {
            return Some(key.clone());
        }
    }

    None
}

/// Stateless Reset の送信レート制限 (RFC 9000 Section 10.3.3)
///
/// 未知の DCID を持つパケットは認証されていないため、無制限に応答すると
/// 反射型の増幅攻撃に使える。トークンバケット方式で送信数を制限する。
/// タイマーを持たず、呼び出し時に渡されたタイムスタンプから補充量を計算する。
struct StatelessResetLimiter {
    /// 送信できる残りの個数
    bucket: u64,
    /// 前回補充した時刻 (ナノ秒)
    last_refill_ts: u64,
}

impl StatelessResetLimiter {
    /// バケットを満たした状態で作成する
    fn new() -> Self {
        Self {
            bucket: STATELESS_RESET_BURST,
            last_refill_ts: 0,
        }
    }

    /// 送信許可を 1 つ取り出す
    ///
    /// バケットが空のときは false を返し、呼び出し側は Stateless Reset を送らない。
    fn try_acquire(&mut self, ts: u64) -> bool {
        self.refill(ts);
        if self.bucket == 0 {
            return false;
        }
        self.bucket -= 1;
        true
    }

    /// 経過時間に応じてバケットを補充する
    fn refill(&mut self, ts: u64) {
        let elapsed = ts.saturating_sub(self.last_refill_ts);
        let refill = elapsed
            .saturating_mul(STATELESS_RESET_RATE)
            .saturating_div(NANOS_PER_SEC);
        if refill == 0 {
            return;
        }

        self.bucket = self
            .bucket
            .saturating_add(refill)
            .min(STATELESS_RESET_BURST);
        // 端数を切り捨てないよう、補充に使った時間分だけ基準時刻を進める
        let consumed = refill
            .saturating_mul(NANOS_PER_SEC)
            .saturating_div(STATELESS_RESET_RATE);
        self.last_refill_ts = self.last_refill_ts.saturating_add(consumed);
    }
}

/// サーバー側の接続
struct ServerConnection {
    conn: Connection,
    remote_addr: SocketAddr,
    // TLS コンテキスト (SSL_CTX はサーバーと共有する)
    //
    // この接続が作った TlsSession (SSL) は SSL_CTX へのポインタを保持するため、
    // 接続より先に SSL_CTX が解放されないよう Arc で生存期間を保証する。
    _tls_ctx: Arc<TlsContext>,
    // 送信待ちのストリームデータ
    pending: PendingStreams,
    // 未処理のイベント
    events: Vec<ConnectionEvent>,
    // アドレスを検証済みかどうか (RFC 9000 Section 8.1.3)
    //
    // クライアントが有効なアドレス検証トークンを提示した場合に true になる。
    // NEW_TOKEN の配布はアドレスを検証できた接続にだけ行う。
    address_validated: bool,
    // NEW_TOKEN の配布に使う秘密。配布しない場合は None
    new_token_secret: Option<RetrySecret>,
    // NEW_TOKEN を配布済みかどうか
    new_token_submitted: bool,
    // 0-RTT (early data) で届いたアプリケーションデータを受信したか
    //
    // サーバーは 0-RTT のデータをハンドシェイクの完了前に受け取るが、
    // `Server::accept` はハンドシェイクの完了を待つため、接続を取り出した
    // 時点では `Connection::is_in_early_data` は false になっている。
    // データを受け取った時点で判定した結果をここに記録する。
    early_data_received: bool,
    // CONNECTION_CLOSE を送受信済みか
    closed: bool,
    // 受信バッファ
    recv_buf: Vec<u8>,
    // 優先アドレスのソケット用の受信バッファ
    // 送信バッファ
    //
    // Box<[u8]> を使う。Vec<u8> は Send だが、async ブロック内で &mut Vec<u8> を
    // 跨いで保持すると future が Send にならず tokio::spawn できないため。
    send_buf: Box<[u8]>,
    // DATAGRAM の設定
    datagram: DatagramConfig,
    // qlog の出力先
    qlog: QlogWriter,
}

/// ハンドシェイクが完了した接続のハンドル
///
/// [`Server::accept`] が返す。以降この接続のパケットは `Server` ではなく
/// このハンドルが受信する。
pub struct AcceptedConnection {
    sockets: Arc<ServerSockets>,
    local_addr: SocketAddr,
    connection_id: ConnectionId,
    inner: ServerConnection,
    // 優先アドレスのソケット用の受信バッファ
    alt_recv_buf: Vec<u8>,
}

impl AcceptedConnection {
    /// サーバーがこの接続に割り当てたコネクション ID を返す
    ///
    /// 長さ 0 のコネクション ID を使う構成
    /// ([`ServerConfig::with_scid_len`]) では、パケットに載らない内部の
    /// 識別子を返す。
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id.clone()
    }

    /// クライアントのアドレスを返す
    pub fn remote_addr(&self) -> SocketAddr {
        self.inner.remote_addr
    }

    /// 交渉された ALPN プロトコルを返す (RFC 7301 Section 3)
    ///
    /// [`ServerConfig::alpn_protocols`] に複数のプロトコルを登録している場合に、
    /// クライアントがどれを選んだかを判別するために使う。
    /// 戻り値はプロトコル名のバイト列で、長さプレフィックスは含まない。
    pub fn selected_alpn_protocol(&self) -> Option<Vec<u8>> {
        self.inner.conn.selected_alpn_protocol()
    }

    /// 0-RTT (early data) で届いたアプリケーションデータを受信したかどうかを返す
    /// (RFC 9001 Section 4.6)
    ///
    /// サーバーが 0-RTT のデータを受け取るのはハンドシェイクの完了前だが、
    /// [`Server::accept`] はハンドシェイクの完了を待つ。そのため接続を
    /// 取り出した時点では `shiguredo_ngtcp2::Connection::is_in_early_data` は
    /// 既に false になっており、後から 0-RTT だったかどうかを判定できない。
    /// このメソッドはデータを受け取った時点で記録した結果を返す。
    ///
    /// 0-RTT が無効な接続 ([`ServerConfig::with_early_data`] が false) では
    /// 常に false になる。
    pub fn received_early_data(&self) -> bool {
        self.inner.early_data_received
    }

    /// この接続で使用されている QUIC バージョンを返す (RFC 9000 Section 6)
    ///
    /// クライアントの Initial に含まれていたバージョン。
    /// [`ServerConfig::quic_versions`] に含まれないバージョンの接続は
    /// 作られないため、通常は `None` にならない。
    pub fn negotiated_version(&self) -> Option<QuicVersion> {
        self.inner.conn.negotiated_version()
    }

    /// ローカルアドレスを返す
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 接続の統計情報を返す
    ///
    /// RTT、輻輳ウィンドウ、送受信量、パケット喪失などのスナップショット。
    /// 診断やメトリクスの収集に使う。
    pub fn stats(&self) -> ConnStats {
        self.inner.conn.stats()
    }

    /// 輻輳ウィンドウの残りを返す (RFC 9002 Section 7)
    ///
    /// 0 の場合は輻輳制御で送信を止めなければならず、ACK を待つ必要がある。
    pub fn cwnd_left(&self) -> u64 {
        self.inner.conn.get_cwnd_left()
    }

    /// ストリームで送信可能な残りのデータ量を返す (RFC 9000 Section 4.1)
    ///
    /// 存在しないストリーム ID を渡した場合は 0 を返す。
    pub fn max_stream_data_left(&self, stream_id: StreamId) -> u64 {
        self.inner.conn.get_max_stream_data_left(stream_id)
    }

    /// 接続全体で送信可能な残りのデータ量を返す (RFC 9000 Section 4.1)
    ///
    /// ピアの `initial_max_data` と MAX_DATA から決まる接続レベルの
    /// フロー制御ウィンドウの残り。0 の場合は MAX_DATA を待つ必要がある。
    pub fn max_data_left(&self) -> u64 {
        self.inner.conn.get_max_data_left()
    }

    /// 開ける残りの双方向ストリーム数を返す (RFC 9000 Section 4.2)
    ///
    /// 0 の場合は [`AcceptedConnection::open_bidi_stream`] がエラーになり、
    /// ピアの MAX_STREAMS ([`ConnectionEvent::MaxStreamsBidi`]) を待つ必要がある。
    pub fn streams_bidi_left(&self) -> u64 {
        self.inner.conn.get_streams_bidi_left()
    }

    /// 開ける残りの単方向ストリーム数を返す (RFC 9000 Section 4.2)
    ///
    /// 0 の場合は [`AcceptedConnection::open_uni_stream`] がエラーになり、
    /// ピアの MAX_STREAMS ([`ConnectionEvent::MaxStreamsUni`]) を待つ必要がある。
    pub fn streams_uni_left(&self) -> u64 {
        self.inner.conn.get_streams_uni_left()
    }

    /// ピアが通知したトランスポートパラメータを返す (RFC 9000 Section 18)
    ///
    /// ハンドシェイクが完了した接続では常に `Some` になる。
    /// 各フィールドの向きについては [`RemoteTransportParams`] の
    /// ドキュメントを参照。
    pub fn remote_transport_params(&self) -> Option<RemoteTransportParams> {
        self.inner.conn.remote_transport_params()
    }

    /// ピアが通知した `max_datagram_frame_size` を返す (RFC 9221 Section 3)
    ///
    /// ピアが DATAGRAM をサポートしていない場合は 0 を返す。
    pub fn remote_max_datagram_frame_size(&self) -> u64 {
        self.remote_transport_params()
            .map_or(0, |params| params.max_datagram_frame_size)
    }

    /// ローカルがピアに通知した `max_datagram_frame_size` を返す (RFC 9221 Section 3)
    ///
    /// [`crate::DatagramConfig`] を無効にしている場合は 0 になる。
    pub fn local_max_datagram_frame_size(&self) -> u64 {
        if self.inner.datagram.is_enabled() {
            self.inner.datagram.max_datagram_frame_size
        } else {
            0
        }
    }

    /// ピアが DATAGRAM を受信できるかどうかを返す
    pub fn can_send_datagram(&self) -> bool {
        self.inner.datagram.is_enabled() && self.inner.conn.can_send_datagram()
    }

    /// ピアが RESET_STREAM_AT を受理するかどうかを返す
    /// (draft-ietf-quic-reliable-stream-reset)
    ///
    /// ピアが `reset_stream_at` を通知していない場合、またはトランスポート
    /// パラメータがまだ届いていない場合は false。true の場合、
    /// [`AcceptedConnection::reset_stream_reliable`] が送信中のデータの配信を
    /// 保証する。
    pub fn supports_reset_stream_at(&self) -> bool {
        self.inner.conn.supports_reset_stream_at()
    }

    /// 接続が closing / draining 期間に入っているかを返す
    pub fn is_closed(&self) -> bool {
        self.inner.closed
            || self.inner.conn.is_in_closing_period()
            || self.inner.conn.is_in_draining_period()
    }

    /// 送信待ちのデータが残っているかどうかを返す
    ///
    /// [`AcceptedConnection::write_stream`] で積んだデータのうち、フロー制御や
    /// 輻輳制御でまだ送れていないものが残っている場合に true を返す。
    pub fn has_pending_data(&self) -> bool {
        !self.inner.pending.is_empty()
    }

    /// 双方向ストリームを開く (RFC 9000 Section 2.1)
    ///
    /// # Errors
    ///
    /// ピアが許可した双方向ストリーム数の上限に達している場合にエラーを返す。
    pub fn open_bidi_stream(&mut self) -> Result<StreamId> {
        self.inner.conn.open_bidi_stream()
    }

    /// 単方向ストリームを開く (RFC 9000 Section 2.1)
    ///
    /// # Errors
    ///
    /// ピアが許可した単方向ストリーム数の上限に達している場合にエラーを返す。
    pub fn open_uni_stream(&mut self) -> Result<StreamId> {
        self.inner.conn.open_uni_stream()
    }

    /// ストリームにデータを書き込む
    ///
    /// `fin` が true の場合、このデータの後ろで送信側を終端する
    /// (RFC 9000 Section 19.8)。
    ///
    /// この呼び出しはデータを送信待ちに積むだけで、パケットは送らない。
    /// 送信するには [`AcceptedConnection::flush`] を呼ぶか、送信と受信を
    /// 交互に行う [`AcceptedConnection::recv_event`] を呼ぶ。
    /// 送信と受信を交互に行わないとピアの ACK や MAX_STREAM_DATA を
    /// 受け取れず、輻輳ウィンドウとフロー制御ウィンドウが伸びないため、
    /// 大きなデータを送る場合は `recv_event` を併用すること。
    ///
    /// 送りきれなかったデータは内部に保持し、次の `flush` / `recv_event` で
    /// 再送を試みる。戻り値は常に `data.len()`。
    ///
    /// # Errors
    ///
    /// 接続が閉じている場合にエラーを返す。
    pub fn write_stream(&mut self, stream_id: StreamId, data: &[u8], fin: bool) -> Result<usize> {
        if self.is_closed() {
            return Err(Error::ConnectionClosed);
        }
        self.inner.pending.push(stream_id, data, fin);
        Ok(data.len())
    }

    /// 未処理のイベントを 1 つ取り出す (ノンブロッキング)
    pub fn poll_event(&mut self) -> Option<ConnectionEvent> {
        pop_event(&mut self.inner.events)
    }

    /// 送信待ちのデータを送信する
    ///
    /// # Errors
    ///
    /// ngtcp2 が回復不能なエラーを返した場合にエラーを返す。ソケットの送信
    /// エラーは接続エラーではないためログのみ出す。
    pub async fn flush(&mut self) -> Result<()> {
        let ts = timestamp();
        let packets = flush_to_packets(&mut self.inner, ts)?;
        self.sockets.send_packets(&packets).await;
        Ok(())
    }

    /// イベントを 1 つ待つ
    ///
    /// # Errors
    ///
    /// - [`Error::ConnectionClosed`][]: 接続が既に閉じている
    /// - 接続が回復不能なエラーで終了した場合はそのエラー
    pub async fn recv_event(&mut self) -> Result<ConnectionEvent> {
        if let Some(event) = self.poll_event() {
            return Ok(event);
        }
        if self.is_closed() {
            // 終了イベントをまだ配信していれば先に返す。
            // 例えば Stateless Reset は受信した直後に draining へ移行するため、
            // ここでイベントを積まないと ConnectionClosed が配信されない。
            push_connection_closed(&mut self.inner);
            if let Some(event) = self.poll_event() {
                return Ok(event);
            }
            return Err(Error::ConnectionClosed);
        }

        loop {
            if let Some(event) = self.poll_event() {
                return Ok(event);
            }

            // 接続の終了を送信より先に判定する。
            //
            // draining 状態では ngtcp2_conn_write_pkt が NGTCP2_ERR_DRAINING を
            // 返すため、先に flush すると終了イベントを通知できない。
            if self.inner.conn.is_in_closing_period() || self.inner.conn.is_in_draining_period() {
                push_connection_closed(&mut self.inner);
                if let Some(event) = self.poll_event() {
                    return Ok(event);
                }
                return Err(Error::ConnectionClosed);
            }

            self.flush().await?;
            // 送信側でもコールバックが発生する (MAX_STREAMS の送信など)
            drain_events(&mut self.inner);

            if let Some(event) = self.poll_event() {
                return Ok(event);
            }

            let now = timestamp();
            let expiry = self.inner.conn.get_expiry();
            let timer_duration = if expiry > now {
                Duration::from_nanos(expiry - now)
            } else {
                Duration::from_millis(1)
            };

            tokio::select! {
                result = self.sockets.recv_from(&mut self.inner.recv_buf, &mut self.alt_recv_buf) => {
                    match result {
                        Ok((data, from, local, ecn)) => {
                            // 送信元アドレスが変わっていても破棄しない。ngtcp2 が
                            // 経路の変更を検出して経路検証を始める
                            // (RFC 9000 Section 9.3)。接続に関係のないパケットは
                            // ngtcp2 が復号に失敗して破棄する。
                            let ts = timestamp();
                            handle_datagram(&mut self.inner, local, from, &data, ts, ecn)?;
                        }
                        Err(e) => {
                            return Err(Error::Internal(format!("recv error: {e}")));
                        }
                    }
                }
                _ = tokio::time::sleep(timer_duration) => {
                    let ts = timestamp();
                    let expiry_result = self.inner.conn.handle_expiry(ts);
                    // タイマー処理でもコールバックが発生する (再送タイムアウトによる
                    // ストリームクローズなど)
                    drain_events(&mut self.inner);
                    if let Err(e) = expiry_result {
                        match e.classify_connection_error() {
                            ConnectionErrorKind::Ignore | ConnectionErrorKind::Terminal => {}
                            _ => {
                                push_connection_closed(&mut self.inner);
                                if let Some(event) = self.poll_event() {
                                    return Ok(event);
                                }
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }
    }

    /// ストリームのフロー制御クレジットを進める (RFC 9000 Section 19.9)
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn extend_max_stream_offset(&mut self, stream_id: StreamId, consumed: u64) -> Result<()> {
        self.inner
            .conn
            .extend_max_stream_offset(stream_id, consumed)?;
        self.inner.conn.extend_max_offset(consumed);
        Ok(())
    }

    /// ピアが開ける双方向ストリーム数の上限を `n` 増やす (RFC 9000 Section 19.11)
    ///
    /// MAX_STREAMS フレームを送る。ngtcp2 は上限を自動では増やさないため、
    /// ピアのストリームを処理し終えたら呼ぶこと。呼ばない限りピアは
    /// `initial_max_streams_bidi` の上限に達した後に新しいストリームを開けず、
    /// [`AcceptedConnection::open_bidi_stream`] もエラーになる。
    ///
    /// 次の [`AcceptedConnection::flush`] / [`AcceptedConnection::recv_event`] で
    /// 送信される。
    pub fn extend_max_streams_bidi(&mut self, n: usize) {
        self.inner.conn.extend_max_streams_bidi(n);
    }

    /// ピアが開ける単方向ストリーム数の上限を `n` 増やす (RFC 9000 Section 19.11)
    ///
    /// [`AcceptedConnection::extend_max_streams_bidi`] の単方向版。
    pub fn extend_max_streams_uni(&mut self, n: usize) {
        self.inner.conn.extend_max_streams_uni(n);
    }

    /// ストリームの送信側をエラーコード付きで中断する (RFC 9000 Section 19.4)
    ///
    /// RESET_STREAM を送り、まだ送っていないデータを破棄する。ピア側には
    /// [`ConnectionEvent::StreamReset`] が届く。
    ///
    /// 送信側を**正常に**終端する (FIN を送る) 場合は
    /// [`AcceptedConnection::write_stream`] に `fin = true` を渡すこと。
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn reset_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        self.inner.pending.remove(stream_id);
        self.inner.conn.shutdown_stream_write(stream_id, error_code)
    }

    /// ストリームの送信側を中断しつつ、送信済みのデータの配信を保証する
    /// (draft-ietf-quic-reliable-stream-reset)
    ///
    /// [`AcceptedConnection::reset_stream`] との違いは、まだ ACK をもらっていない
    /// 送信中のデータを破棄せず、リセットの時点までに送ったデータを届けてから
    /// 送信側を閉じるところにある。ピアは RESET_STREAM ではなく RESET_STREAM_AT を
    /// 受け取り、リセットより前に送られたデータを欠落なく受け取れる。
    ///
    /// この保証が働くのはピアが `reset_stream_at` を通知している場合だけである
    /// ([`AcceptedConnection::supports_reset_stream_at`] で確認できる)。通知して
    /// いないピアに対しては RESET_STREAM が送られ、未送信のデータは破棄される
    /// ([`AcceptedConnection::reset_stream`] と同じ挙動)。
    ///
    /// [`AcceptedConnection::write_stream`] で送信待ちに積んだまま送っていない
    /// データは保証の対象外であり、[`AcceptedConnection::reset_stream`] と同様に
    /// 破棄される。保証の対象に含める場合は、事前に
    /// [`AcceptedConnection::flush`] を呼んで送信しておくこと。送信待ちが残って
    /// いるかどうかは [`AcceptedConnection::has_pending_data`] で確認できる。
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn reset_stream_reliable(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        self.inner.pending.remove(stream_id);
        self.inner
            .conn
            .shutdown_stream_write_reliable(stream_id, error_code)
    }

    /// ストリームの受信側をエラーコード付きで中断する (RFC 9000 Section 19.5)
    ///
    /// STOP_SENDING を送り、ピアからの以降のデータを受け取らない。ピア側には
    /// [`ConnectionEvent::StreamStopSending`] が届き、ngtcp2 が自動的に
    /// RESET_STREAM を送り返す。
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn stop_sending(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        self.inner.conn.shutdown_stream_read(stream_id, error_code)
    }

    /// ストリームの送受信両方向をエラーコード付きで中断する
    /// (RFC 9000 Section 19.4 / 19.5)
    ///
    /// RESET_STREAM と STOP_SENDING を送る。
    ///
    /// # Errors
    ///
    /// ストリームが存在しない場合にエラーを返す。
    pub fn close_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        self.inner.pending.remove(stream_id);
        self.inner.conn.shutdown_stream(stream_id, error_code)
    }

    /// DATAGRAM を送信する (RFC 9221)
    ///
    /// # Errors
    ///
    /// ピアが DATAGRAM をサポートしていない場合、`data` が設定された上限を
    /// 超える場合はエラーを返す。
    pub async fn send_datagram(&mut self, data: &[u8]) -> Result<()> {
        send_datagram_impl(&mut self.inner, data, &self.sockets).await
    }

    /// 鍵の更新を開始する (RFC 9001 Section 4.6.3)
    ///
    /// 次の [`AcceptedConnection::flush`] / [`AcceptedConnection::recv_event`] で
    /// 新しい 1-RTT 鍵に切り替わる。長期間生きる接続では前方秘匿性を保つために
    /// 定期的な更新が推奨される (RFC 9001 Section 6)。
    ///
    /// # Errors
    ///
    /// すでに鍵の更新が進行中の場合にエラーを返す。
    pub fn initiate_key_update(&mut self) -> Result<()> {
        self.inner.conn.initiate_key_update(timestamp())
    }

    /// CONNECTION_CLOSE を送信して接続を閉じる (RFC 9000 Section 10.2)
    ///
    /// ピアの応答を待たない点は [`crate::ClientConnection::close`] と同じ。
    ///
    /// # Errors
    ///
    /// ngtcp2 が CONNECTION_CLOSE を生成できない場合にエラーを返す。
    pub async fn close(&mut self, error_code: u64, reason: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Ok(());
        }
        let ts = timestamp();
        let written = self.inner.conn.write_connection_close_app(
            &mut self.inner.send_buf,
            error_code,
            reason,
            ts,
        )?;
        if written > 0 {
            // ngtcp2 が複数のパケットを連結して返す場合があるため、
            // パケットごとに送る
            let packets = close_packets(
                &self.inner.send_buf[..written],
                self.local_addr,
                self.inner.remote_addr,
                0,
            );
            self.sockets.send_packets(&packets).await;
        }
        self.inner.closed = true;
        Ok(())
    }
}

/// QUIC サーバー
pub struct Server {
    sockets: Arc<ServerSockets>,
    local_addr: SocketAddr,
    // TLS コンテキスト (接続ごとに TlsSession を作るため共有する)
    tls_ctx: Arc<TlsContext>,
    config: ServerConfig,
    // 接続マップ (サーバー SCID -> 接続)
    connections: HashMap<ConnectionId, ServerConnection>,
    // DCID -> 接続キーのルーティングマップ (RFC 9000 Section 5.2)
    //
    // 1 つの接続は複数の CID を持つ (クライアント初回 Initial の DCID、
    // サーバーが発行した SCID、NEW_CONNECTION_ID で発行した CID)。
    // 到着パケットは DCID で接続に振り分ける。
    cid_map: HashMap<ConnectionId, ConnectionId>,
    // Short header パケットの DCID 照合に使う長さの集合
    short_cid_lengths: BTreeSet<usize>,
    // ピアのアドレス -> 接続キーのルーティングマップ
    //
    // サーバーが長さ 0 のコネクション ID を使う場合、パケットは
    // コネクション ID では識別できないため、ピアのアドレスで振り分ける
    // (RFC 9000 Section 5.1)。他の構成では空のまま。
    addr_map: HashMap<SocketAddr, ConnectionId>,
    // Stateless Reset トークンを導出するための秘密 (RFC 9000 Section 10.3.1)
    stateless_reset_secret: Option<StatelessResetSecret>,
    // Stateless Reset の送信レート制限 (RFC 9000 Section 10.3.3)
    stateless_reset_limiter: StatelessResetLimiter,
    // accept で引き渡し済みの CID (Stateless Reset の抑止に使う)
    taken_cids: HashSet<ConnectionId>,
    // taken_cids の挿入順。上限を超えたときに古いものから忘れる
    taken_cid_order: VecDeque<ConnectionId>,
    // 受信バッファ
    recv_buf: Vec<u8>,
    // 優先アドレスのソケット用の受信バッファ
    alt_recv_buf: Vec<u8>,
    // 送信バッファ
    //
    // Box<[u8]> を使う。Vec<u8> は Send だが、async ブロック内で &mut Vec<u8> を
    // 跨いで保持すると future が Send にならず tokio::spawn できないため。
    send_buf: Box<[u8]>,
}

impl Server {
    /// 指定アドレスにバインドする
    ///
    /// `config` を省略した場合は ALPN を `hq-interop` にした既定設定を使う。
    ///
    /// # Errors
    ///
    /// ソケットのバインドに失敗した場合、証明書または秘密鍵の読み込みに
    /// 失敗した場合にエラーを返す。
    pub async fn bind(
        addr: SocketAddr,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        config: Option<ServerConfig>,
    ) -> Result<Self> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        let config = config.unwrap_or_else(|| ServerConfig::new(&[b"hq-interop"]));
        // バージョンが 1 つも無いとどのクライアントとも接続できないため、
        // 設定ミスとしてバインド時に検出する
        if config.quic_versions.is_empty() {
            return Err(Error::InvalidArgument(
                "quic_versions must not be empty".to_string(),
            ));
        }
        let alpn = config.alpn_refs();
        let mut tls_ctx = TlsContext::new_server(cert_path, key_path, &alpn)?;
        // 0-RTT を受け入れる場合、以降に作るセッションで early data を有効にする
        if config.early_data {
            tls_ctx.set_accept_early_data(true)?;
        }

        let preferred = config.preferred_address.is_some();
        let sockets = ServerSockets::bind(addr, config.preferred_address)
            .await
            .map_err(|e| Error::Internal(format!("failed to bind socket: {e}")))?;
        let local_addr = sockets.local_addr();
        let sockets = Arc::new(sockets);

        // サーバーが発行する CID の長さを登録する。長さ 0 の CID は
        // パケットの識別に使えないため登録しない (RFC 9000 Section 5.1)
        let mut short_cid_lengths = BTreeSet::new();
        if config.scid_len > 0 {
            short_cid_lengths.insert(config.scid_len);
        }

        // Stateless Reset トークンの導出に使う秘密。
        // 設定されていなければこのサーバーの寿命の間だけ有効な秘密を生成する。
        let stateless_reset_secret = config
            .stateless_reset_secret
            .clone()
            .or_else(StatelessResetSecret::generate);

        Ok(Self {
            sockets,
            local_addr,
            tls_ctx: Arc::new(tls_ctx),
            config,
            connections: HashMap::new(),
            cid_map: HashMap::new(),
            short_cid_lengths,
            addr_map: HashMap::new(),
            stateless_reset_secret,
            stateless_reset_limiter: StatelessResetLimiter::new(),
            taken_cids: HashSet::new(),
            taken_cid_order: VecDeque::new(),
            recv_buf: vec![0u8; RECV_BUFFER_SIZE],
            alt_recv_buf: if preferred {
                vec![0u8; RECV_BUFFER_SIZE]
            } else {
                Vec::new()
            },
            send_buf: vec![0u8; SEND_BUFFER_SIZE].into_boxed_slice(),
        })
    }

    /// ローカルアドレスを返す
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 優先アドレスを返す (RFC 9000 Section 9.6)
    ///
    /// [`ServerConfig::with_preferred_address`] を設定していない場合は `None`。
    pub fn preferred_addr(&self) -> Option<SocketAddr> {
        self.sockets.preferred_addr()
    }

    /// 現在保持している接続のコネクション ID 一覧を返す
    ///
    /// [`Server::accept`] で取り出した接続は含まれない。長さ 0 の
    /// コネクション ID を使う構成 ([`ServerConfig::with_scid_len`]) では、
    /// パケットに載らない内部の識別子を返す。
    pub fn connection_ids(&self) -> Vec<ConnectionId> {
        self.connections.keys().cloned().collect()
    }

    /// 接続を 1 つ受け入れる
    ///
    /// ハンドシェイクが完了した接続を返すまで待つ。不正なパケットは破棄し、
    /// サーバーは停止しない。ハンドシェイク中に閉じた接続も破棄する。
    ///
    /// # Errors
    ///
    /// ソケットの受信に失敗した場合にエラーを返す。個々の不正パケットは
    /// エラーにならない。
    pub async fn accept(&mut self) -> Result<Option<AcceptedConnection>> {
        loop {
            self.remove_closed_connections();

            // 既にハンドシェイクが完了している接続があれば返す
            if let Some(conn_id) = self
                .connections
                .iter()
                .find(|(_, c)| c.conn.is_handshake_completed())
                .map(|(id, _)| id.clone())
            {
                return Ok(Some(self.take_connection(&conn_id)));
            }

            // ngtcp2 のタイマーを待ち時間に変換する
            let now = timestamp();
            let next_expiry = self
                .connections
                .values()
                .map(|c| c.conn.get_expiry())
                .min()
                .unwrap_or_else(|| now + Duration::from_secs(1).as_nanos() as u64);
            let timer_duration = if next_expiry > now {
                Duration::from_nanos(next_expiry - now)
            } else {
                Duration::from_millis(1)
            };

            tokio::select! {
                result = self.sockets.recv_from(&mut self.recv_buf, &mut self.alt_recv_buf) => {
                    match result {
                        Ok((data, from, local_addr, ecn)) => {
                            let ts = timestamp();
                            self.handle_datagram(&data, from, local_addr, ts, ecn).await;
                        }
                        Err(e) => {
                            return Err(Error::Internal(format!("recv error: {e}")));
                        }
                    }
                }
                _ = tokio::time::sleep(timer_duration) => {
                    self.handle_timers();
                }
            }
        }
    }

    /// 受信したデータグラムを処理する
    async fn handle_datagram(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        local_addr: SocketAddr,
        ts: u64,
        ecn: u8,
    ) {
        // 既存接続へのパケットか判定する (RFC 9000 Section 5.2)
        //
        // コネクション ID で解決できない場合はピアのアドレスで解決する。
        // サーバーが長さ 0 のコネクション ID を使う場合、パケットには
        // コネクション ID が載らないため、これが唯一の手がかりになる
        // (RFC 9000 Section 5.1)。
        let conn_key = resolve_dcid(&self.cid_map, &self.short_cid_lengths, data)
            .or_else(|| self.addr_map.get(&from).cloned());

        match conn_key {
            Some(key) => {
                self.handle_existing_connection(&key, data, from, local_addr, ts, ecn)
                    .await
            }
            None if data.first().is_some_and(|first| first & 0x80 != 0) => {
                // Long header の未知 DCID は新規接続として扱う。
                // Initial 以外の Long header は parse_new_connection_packet が破棄する
                self.handle_new_connection(data, from, local_addr, ts, ecn)
                    .await;
            }
            None => {
                // Short header の未知 DCID には Stateless Reset を返す
                // (RFC 9000 Section 10.3)。接続状態を持たない応答なので、
                // サイズと送信レートの制限 (RFC 9000 Section 10.3.3) に従う。
                self.send_stateless_reset(data, from, local_addr, ts).await;
            }
        }
    }

    /// 既存接続のパケットを処理する
    async fn handle_existing_connection(
        &mut self,
        conn_key: &ConnectionId,
        data: &[u8],
        from: SocketAddr,
        local_addr: SocketAddr,
        ts: u64,
        ecn: u8,
    ) {
        let (result, packets, issued_cids, retired_cids) = {
            let Some(conn) = self.connections.get_mut(conn_key) else {
                return;
            };

            // 送信元アドレスが変わっていても破棄しない。ngtcp2 が経路の変更を
            // 検出して経路検証 (PATH_CHALLENGE) を始める (RFC 9000 Section 9.3)。
            // 検証が終わるまでは古い経路が使われるため、送信先はパケットごとに
            // 異なる (write_pkt が返す経路に従う)。
            let result = read_packet(conn, local_addr, from, data, ts, ecn);
            let packets = flush_to_packets(conn, ts).unwrap_or_default();
            // CID は読み込みと書き出しの両方で発行・終了されるため、
            // 書き出した後にまとめて取り出す
            let issued_cids = conn.conn.poll_issued_cids();
            let retired_cids = conn.conn.poll_retired_cids();

            (result, packets, issued_cids, retired_cids)
        };

        // NEW_CONNECTION_ID で発行した CID をルーティングテーブルへ登録する
        // (RFC 9000 Section 5.1.1)。ピアは発行された CID をすぐに使うため、
        // ここで登録しないと次のパケットを接続に振り分けられない。
        for cid in issued_cids {
            self.short_cid_lengths.insert(cid.len());
            self.cid_map.insert(cid, conn_key.clone());
        }

        // RETIRE_CONNECTION_ID でピアが使用を終了した CID を取り除く
        // (RFC 9000 Section 5.1.2)
        self.remove_retired_cids(&retired_cids, conn_key);

        self.sockets.send_packets(&packets).await;

        // エラーを分類して接続単位で処理する (サーバー全体は停止させない)
        if let Err(e) = result {
            self.handle_conn_error(conn_key, e, from, local_addr).await;
        }
    }

    /// 接続単位のエラーを処理する
    async fn handle_conn_error(
        &mut self,
        conn_key: &ConnectionId,
        err: Error,
        from: SocketAddr,
        local_addr: SocketAddr,
    ) {
        match err.classify_connection_error() {
            ConnectionErrorKind::Ignore => {
                // パケットの破棄指示やストリーム単位のシグナル。何もしない
            }
            ConnectionErrorKind::SilentDrop | ConnectionErrorKind::Internal => {
                // 接続を黙って破棄する。closing / draining にならないため
                // 明示的に除去する (除去しないとタイマーが 1ms でビジーループする)
                self.remove_connection(conn_key);
            }
            ConnectionErrorKind::Terminal => {
                // closing / draining 状態に移行済み。remove_closed_connections が除去する
            }
            ConnectionErrorKind::TransportClose | ConnectionErrorKind::ApplicationClose => {
                eprintln!("[shiguredo_ngtcp2_tokio] closing connection: {err}");
                let ts = timestamp();

                let packets = {
                    let Some(conn) = self.connections.get_mut(conn_key) else {
                        return;
                    };

                    // エラー種別に応じた CONNECTION_CLOSE を書き出す
                    // (RFC 9000 Section 11.1)
                    let result = if matches!(
                        err.classify_connection_error(),
                        ConnectionErrorKind::ApplicationClose
                    ) {
                        conn.conn
                            .write_connection_close_app(&mut self.send_buf, 0, b"", ts)
                    } else {
                        let code = match &err {
                            Error::Ngtcp2(_, code) => {
                                shiguredo_ngtcp2::infer_quic_transport_error_code(*code)
                            }
                            _ => 0,
                        };
                        conn.conn
                            .write_connection_close(&mut self.send_buf, code, b"", ts)
                    };

                    match result {
                        // ngtcp2 が複数のパケットを連結して返す場合があるため、
                        // パケットごとに送る
                        Ok(written) if written > 0 => {
                            close_packets(&self.send_buf[..written], local_addr, from, 0)
                        }
                        _ => Vec::new(),
                    }
                };

                if packets.is_empty() {
                    // CONNECTION_CLOSE を書き込めない場合は黙って破棄する
                    // (anti-amplification 制限で NOBUF になる場合がある)
                    self.remove_connection(conn_key);
                } else {
                    self.sockets.send_packets(&packets).await;
                }
            }
        }
    }

    /// 新規接続の Initial を処理する
    ///
    /// Initial の AEAD は強力な認証を提供しないため、不正な Initial で
    /// エラーが返ってもサーバーは継続する (RFC 9000 Section 11.1)。
    /// 復号に成功した上での致命的なエラーは、状態を保持せずに
    /// CONNECTION_CLOSE を送って破棄する (RFC 9000 Section 10.2.3)。
    async fn handle_new_connection(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        local_addr: SocketAddr,
        ts: u64,
        ecn: u8,
    ) {
        // サポート外のバージョンには Version Negotiation を返す
        // (RFC 9000 Section 6)。接続状態は作らない。
        if let Some(negotiation) = version_negotiation_info(data, &self.config.quic_versions) {
            self.send_version_negotiation(&negotiation, from, local_addr)
                .await;
            return;
        }

        let Some((version, accepted)) = accept_initial_packet(data, &self.config.quic_versions)
        else {
            return;
        };

        // アドレス検証 (RFC 9000 Section 8.1.2)。
        // 検証に使う Original DCID とトークンはここで確定する。
        // 秘密は send_retry で &mut self を使うため先に複製する。
        let retry_secret = self.config.retry_secret.clone();
        let mut original_dcid = accepted.dcid.clone();
        let mut address_validation_token = None;
        // Retry を送ったかどうか。Retry の SCID を再利用するかと、
        // retry_source_connection_id を通知するかに使う
        let mut retried = false;
        if let Some(secret) = &retry_secret {
            match AddressValidationToken::from_packet(accepted.token.clone()) {
                // トークンが無いなら Retry を返して接続状態を作らない
                None => {
                    self.send_retry(&accepted, version, secret, from, local_addr, ts)
                        .await;
                    return;
                }
                Some(token) => {
                    let result = match token.kind() {
                        // Retry のトークンには最初の DCID が埋め込まれている。
                        // パケットの DCID は Retry の SCID なので使えない
                        // (RFC 9000 Section 7.3)。
                        AddressValidationTokenKind::Retry => verify_retry_token(
                            secret,
                            token.as_bytes(),
                            version,
                            from,
                            &accepted.dcid,
                            self.config.retry_token_timeout,
                            ts,
                        )
                        .map(|odcid| {
                            original_dcid = odcid;
                            retried = true;
                        }),
                        // NEW_TOKEN のトークンには DCID が埋め込まれていない。
                        // クライアントは新しい DCID を選ぶため、Initial の DCID を
                        // Original Destination Connection ID として扱う
                        // (RFC 9000 Section 7.3)。
                        AddressValidationTokenKind::NewToken => verify_new_token(
                            secret,
                            token.as_bytes(),
                            from,
                            self.config.retry_token_timeout,
                            ts,
                        ),
                    };

                    match result {
                        Ok(()) => address_validation_token = Some(token),
                        Err(e) => {
                            // 不正なトークンには接続状態を作らずに
                            // INVALID_TOKEN を返す (RFC 9000 Section 8.1.3)
                            eprintln!(
                                "[shiguredo_ngtcp2_tokio] rejected address validation token: {e}"
                            );
                            self.send_invalid_token_close(&accepted, version, from, local_addr)
                                .await;
                            return;
                        }
                    }
                }
            }
        }

        // 接続数の上限を超えたら破棄する
        if self.connections.len() >= MAX_CONNECTIONS {
            return;
        }

        // 同じ Original DCID の Initial 再送は既存接続として扱う
        if self.cid_map.contains_key(&original_dcid) {
            return;
        }

        // Retry を送った場合は、Retry の SCID を接続の SCID として使い回す。
        //
        // クライアントは 2 通目の Initial の DCID に Retry の SCID を使うため、
        // サーバーの SCID を同じ値にすれば、クライアントが最初から使う DCID を
        // そのままルーティングキーにできる。RFC 9000 Section 7.3 が求めるのは
        // Retry の SCID を retry_source_connection_id として通知することだけで、
        // 以後の Initial の SCID を一致させることまでは求めていない
        // (ngtcp2 の example server は別の CID を生成する)。
        let server_scid = if retried {
            accepted.dcid.clone()
        } else {
            let Some(scid) = generate_scid(self.config.scid_len) else {
                eprintln!("[shiguredo_ngtcp2_tokio] failed to generate scid");
                return;
            };
            scid
        };

        // ルーティングのキー。長さ 0 のコネクション ID を使う場合、SCID は
        // パケットの識別に使えないため、接続ごとの内部キーを別に作って
        // ピアのアドレスから引けるようにする (RFC 9000 Section 5.1)。
        let conn_key = if server_scid.is_empty() {
            match ConnectionId::random(INTERNAL_KEY_LEN) {
                Some(key) => key,
                None => {
                    eprintln!("[shiguredo_ngtcp2_tokio] failed to generate connection key");
                    return;
                }
            }
        } else {
            server_scid.clone()
        };

        let tls_session = match self.tls_ctx.create_session() {
            Ok(session) => session,
            Err(e) => {
                eprintln!("[shiguredo_ngtcp2_tokio] failed to create TLS session: {e}");
                return;
            }
        };

        // - dcid: クライアントの SCID (サーバーがクライアントへ送るパケットの DCID)
        // - scid: サーバーの SCID
        let mut params = self
            .config
            .effective_transport_params()
            .with_original_dcid(&original_dcid);

        // Retry を送った場合は、Retry の SCID を通知しなければならない
        // (RFC 9000 Section 7.3)。クライアントは受け取った Retry の SCID と
        // 一致することを検証するため、無いとハンドシェイクが
        // TRANSPORT_PARAMETER_ERROR で失敗する。
        //
        // Retry を送っていない場合は通知してはならない。クライアントは Retry を
        // 受け取っていない接続でこのパラメータが届くと接続を終了する。
        if retried {
            params = params.with_retry_scid(&server_scid);
        }

        // 最初の SCID に対応する Stateless Reset トークンを
        // トランスポートパラメータで配布する (RFC 9000 Section 18.2)。
        // これがないとピアは最初の DCID に対する Stateless Reset を受理できない。
        if !server_scid.is_empty()
            && let Some(secret) = &self.stateless_reset_secret
            && let Some(token) = secret.token(&server_scid)
        {
            params = params.with_stateless_reset_token(&token);
        }

        // 優先アドレスを通知する (RFC 9000 Section 9.6 / 18.2)
        //
        // 優先アドレス用の CID もサーバーが発行する CID なので、Stateless Reset
        // トークンを導出して一緒に通知する。トークンが導出できない場合は
        // 通知しない (RFC 9000 Section 18.2 はトークンを必須としている)。
        // 通知するのは実際に bind できたアドレス。設定でポート 0 を指定した
        // 場合、config の値はそのままでは通知できない
        let mut preferred_addr_cid = None;
        if !server_scid.is_empty()
            && let Some(preferred_addr) = self.sockets.preferred_addr()
            && let Some(secret) = &self.stateless_reset_secret
            && let Some(cid) = ConnectionId::random(self.config.scid_len)
            && let Some(token) = secret.token(&cid)
        {
            params = params.with_preferred_address(&cid, preferred_addr, &token);
            preferred_addr_cid = Some(cid);
        }

        // NEW_TOKEN の配布に使う秘密。Retry と同じ秘密を使うため、
        // Retry が無効な場合は配布しない
        let address_validated = address_validation_token.is_some();
        let new_token_secret = if self.config.new_token {
            retry_secret.clone()
        } else {
            None
        };

        // qlog の出力先が指定されていれば有効にする
        let qlog = match &self.config.qlog_dir {
            Some(dir) => QlogWriter::new(dir, &file_name("server-", &server_scid)),
            None => QlogWriter::disabled(),
        };

        // 接続を作成する時刻とトークン、Stateless Reset の秘密を設定する
        let mut settings = self.config.settings.clone();
        settings.initial_ts = ts;
        settings.qlog = self.config.qlog_dir.is_some();
        settings.address_validation_token = address_validation_token;
        settings.stateless_reset_secret = self.stateless_reset_secret.clone();

        let conn = match Connection::server_new(
            &accepted.scid,
            &server_scid,
            // パケットを受け取ったソケットのアドレスを経路にする。優先アドレスで
            // 受けた Initial への応答は、同じアドレスから送る必要がある
            // (RFC 9000 Section 9.6.1)
            local_addr,
            from,
            version,
            tls_session,
            &params,
            &settings,
        ) {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("[shiguredo_ngtcp2_tokio] failed to create connection: {e}");
                return;
            }
        };

        let mut server_conn = ServerConnection {
            conn,
            remote_addr: from,
            _tls_ctx: Arc::clone(&self.tls_ctx),
            pending: PendingStreams::new(),
            events: Vec::new(),
            address_validated,
            new_token_secret,
            new_token_submitted: false,
            early_data_received: false,
            closed: false,
            datagram: self.config.datagram,
            qlog,
            recv_buf: vec![0u8; RECV_BUFFER_SIZE],
            send_buf: vec![0u8; SEND_BUFFER_SIZE].into_boxed_slice(),
        };

        // 受信した Initial を処理する
        let result = read_packet(&mut server_conn, local_addr, from, data, ts, ecn);

        // ngtcp2 が Retry を要求した場合は接続を破棄して Retry を返す
        // (ngtcp2 の `ngtcp2_conn_read_pkt` の契約)。トークンを検証できた場合でも
        // クライアントの Initial が 1 パケットに収まっていない場合などに発生する。
        if let Err(e) = &result
            && e.is_retry_required()
            && let Some(secret) = &retry_secret
        {
            self.send_retry(&accepted, version, secret, from, local_addr, ts)
                .await;
            return;
        }

        // ルーティングテーブルへの登録
        //
        // - server_scid: サーバーが以後使う SCID。クライアントの 2 通目以降の
        //   パケットの DCID になる
        // - original_dcid: クライアントが最初の Initial で使った DCID。
        //   クライアントは Initial を再送するとき同じ DCID を使うため
        if !server_scid.is_empty() {
            self.short_cid_lengths.insert(server_scid.len());
        }
        if server_scid != conn_key {
            // 長さ 0 のコネクション ID では、ピアのアドレスから接続を引く
            self.addr_map.insert(from, conn_key.clone());
        } else {
            self.cid_map.insert(server_scid.clone(), conn_key.clone());
        }
        self.cid_map.insert(original_dcid.clone(), conn_key.clone());

        // 優先アドレス用の CID もルーティングテーブルに登録する。クライアントは
        // 優先アドレスへ移った後、この CID を Destination Connection ID に使う
        // (RFC 9000 Section 9.6.1)。
        if let Some(cid) = &preferred_addr_cid {
            self.short_cid_lengths.insert(cid.len());
            self.cid_map.insert(cid.clone(), conn_key.clone());
        }

        // ハンドシェイクの応答を書き出す
        //
        // CID の登録より先に書き出すが、書き出した直後に登録するため、
        // ピアが新しい CID を使って送ってきたパケットは次の受信で振り分けられる。
        let packets = flush_to_packets(&mut server_conn, ts).unwrap_or_default();

        self.connections.insert(conn_key.clone(), server_conn);

        // ngtcp2 が生成した CID も登録する。
        //
        // サーバーは Initial の処理中 (get_new_connection_id コールバック) と
        // NEW_CONNECTION_ID の書き出し中に CID を発行する。クライアント
        // (例: s2n-quic) は以後その CID を DCID として使うため、登録しないと
        // パケットを接続に振り分けられず、未知の DCID として Stateless Reset を
        // 返してハンドシェイクを止めてしまう (RFC 9000 Section 5.1.1)。
        if let Some(server_conn) = self.connections.get_mut(&conn_key) {
            Self::register_issued_cids(
                server_conn,
                &mut self.cid_map,
                &mut self.short_cid_lengths,
                &conn_key,
            );
        }

        if !packets.is_empty() {
            self.sockets.send_packets(&packets).await;
        }

        // 復号に成功しても致命エラーになった Initial は接続を破棄する
        if let Err(e) = result {
            self.handle_conn_error(&conn_key, e, from, local_addr).await;
        }
    }

    /// Retry パケットを送る (RFC 9000 Section 8.1.2 / 17.2.5)
    ///
    /// 接続状態を作らずに 1 パケットだけ返すため、偽造した送信元アドレスを
    /// 使った増幅攻撃のコストを攻撃側に負わせられる。
    ///
    /// Retry の生成にはトークンの暗号計算が必要だが、ngtcp2 の example server と
    /// 同様にレート制限は行わない。ハンドシェイク自体も同等のコストを
    /// 持つため、Retry だけを制限しても攻撃は防げない。
    async fn send_retry(
        &mut self,
        accepted: &AcceptedInitial,
        version: QuicVersion,
        secret: &RetrySecret,
        to: SocketAddr,
        local: SocketAddr,
        ts: u64,
    ) {
        let Some(retry_scid) = generate_scid(self.config.scid_len) else {
            eprintln!("[shiguredo_ngtcp2_tokio] failed to generate retry scid");
            return;
        };

        let token = match generate_retry_token(secret, version, to, &retry_scid, &accepted.dcid, ts)
        {
            Ok(token) => token,
            Err(e) => {
                eprintln!("[shiguredo_ngtcp2_tokio] failed to generate retry token: {e}");
                return;
            }
        };

        let written = match write_retry_packet(
            &mut self.send_buf,
            version,
            &accepted.scid,
            &retry_scid,
            &accepted.dcid,
            token.as_bytes(),
        ) {
            Ok(written) if written > 0 => written,
            Ok(_) => return,
            Err(e) => {
                eprintln!("[shiguredo_ngtcp2_tokio] failed to write retry packet: {e}");
                return;
            }
        };

        let packet = OutgoingPacket {
            data: self.send_buf[..written].to_vec(),
            local,
            remote: to,
            ecn: 0,
        };
        self.sockets.send_packets(&[packet]).await;
    }

    /// 不正なトークンを持つ Initial に INVALID_TOKEN の CONNECTION_CLOSE を返す
    /// (RFC 9000 Section 8.1.3 / 10.2.3)
    ///
    /// 接続状態は作らない。応答は引き金になった Initial (1200 バイト以上) より
    /// 小さいため増幅攻撃に使われない (RFC 9000 Section 8.1)。
    async fn send_invalid_token_close(
        &mut self,
        accepted: &AcceptedInitial,
        version: QuicVersion,
        to: SocketAddr,
        local: SocketAddr,
    ) {
        let Some(server_scid) = generate_scid(self.config.scid_len) else {
            return;
        };

        let written = match write_stateless_connection_close(
            &mut self.send_buf,
            version,
            &accepted.scid,
            &server_scid,
            TRANSPORT_ERROR_INVALID_TOKEN,
            b"invalid address validation token",
        ) {
            Ok(written) if written > 0 => written,
            Ok(_) => return,
            Err(e) => {
                eprintln!("[shiguredo_ngtcp2_tokio] failed to write connection close: {e}");
                return;
            }
        };

        let packet = OutgoingPacket {
            data: self.send_buf[..written].to_vec(),
            local,
            remote: to,
            ecn: 0,
        };
        self.sockets.send_packets(&[packet]).await;
    }

    /// Version Negotiation パケットを送る (RFC 9000 Section 6)
    ///
    /// 受信したデータグラムは 1200 バイト以上
    /// ([`version_negotiation_info`] が [`decode_packet_version`] 経由で保証する) で、
    /// 送る Version Negotiation パケットはそれより十分小さいため、
    /// 反射型攻撃への増幅率は 1 を下回る (RFC 9000 Section 8.1 の 3 倍制限を満たす)。
    async fn send_version_negotiation(
        &mut self,
        info: &PacketVersion,
        to: SocketAddr,
        local: SocketAddr,
    ) {
        let result = write_version_negotiation(
            &mut self.send_buf,
            &info.scid,
            &info.dcid,
            &self.config.quic_versions,
        );

        let packet = match result {
            Ok(written) if written > 0 => self.send_buf[..written].to_vec(),
            Ok(_) => return,
            Err(e) => {
                eprintln!("[shiguredo_ngtcp2_tokio] failed to write version negotiation: {e}");
                return;
            }
        };

        let packet = OutgoingPacket {
            data: packet,
            local,
            remote: to,
            ecn: 0,
        };
        self.sockets.send_packets(&[packet]).await;
    }

    /// 未知の DCID を持つ Short header パケットに Stateless Reset を返す
    /// (RFC 9000 Section 10.3)
    ///
    /// Short header は DCID 長を運ばないため (RFC 9000 Section 17.3)、
    /// 発行した CID の長いものから順に試す。トークンが一致しなければ
    /// ピアは Stateless Reset を無視するため、長さを外しても害はない。
    ///
    /// 送信は [`StatelessResetLimiter`] で制限する (RFC 9000 Section 10.3.3)。
    async fn send_stateless_reset(
        &mut self,
        data: &[u8],
        to: SocketAddr,
        local: SocketAddr,
        ts: u64,
    ) {
        if !self.stateless_reset_limiter.try_acquire(ts) {
            return;
        }
        let Some(secret) = &self.stateless_reset_secret else {
            return;
        };

        for len in self.short_cid_lengths.iter().rev() {
            let len = *len;
            if data.len() < 1 + len {
                continue;
            }
            let Some(dcid) = ConnectionId::new(&data[1..1 + len]) else {
                continue;
            };
            // accept で引き渡した接続の CID なら接続は生きているため送らない
            if self.is_taken_cid(&dcid) {
                return;
            }
            let Some(token) = secret.token(&dcid) else {
                continue;
            };

            match write_stateless_reset(&mut self.send_buf, &token, data.len()) {
                Ok(written) if written > 0 => {
                    let pkt = OutgoingPacket {
                        data: self.send_buf[..written].to_vec(),
                        local,
                        remote: to,
                        ecn: 0,
                    };
                    self.sockets.send_packets(&[pkt]).await;
                }
                Ok(_) => {
                    // 元のパケットが短すぎて Stateless Reset を作れない
                    // (RFC 9000 Section 10.3.3)。それ以上短い CID でも同じため打ち切る。
                }
                Err(e) => {
                    eprintln!("[shiguredo_ngtcp2_tokio] failed to write stateless reset: {e}");
                }
            }
            return;
        }
    }

    /// 全接続のタイマーを処理する
    fn handle_timers(&mut self) {
        let ts = timestamp();
        let keys: Vec<ConnectionId> = self.connections.keys().cloned().collect();
        for key in keys {
            let Some(conn) = self.connections.get_mut(&key) else {
                continue;
            };
            if conn.conn.get_expiry() > ts {
                continue;
            }
            let result = conn.conn.handle_expiry(ts);
            // タイマー処理で発生したイベント (ストリームクローズなど) は
            // accept 後にハンドルへ引き渡されるため、ここで取り込んでおく
            drain_events(conn);
            // 期限処理でも NEW_CONNECTION_ID の再送で CID が発行されうる
            Self::register_issued_cids(conn, &mut self.cid_map, &mut self.short_cid_lengths, &key);
            let retired = conn.conn.poll_retired_cids();
            self.remove_retired_cids(&retired, &key);
            if let Err(e) = result {
                match e.classify_connection_error() {
                    ConnectionErrorKind::Ignore | ConnectionErrorKind::Terminal => {}
                    _ => {
                        eprintln!("[shiguredo_ngtcp2_tokio] connection error: {e}");
                        self.remove_connection(&key);
                    }
                }
            }
        }
    }

    /// ピアが使用を終了した CID をルーティングテーブルから取り除く
    /// (RFC 9000 Section 5.1.2)
    ///
    /// 取り除いた CID は「引き渡し済み」として記録する。遅れて届いた
    /// パケットに Stateless Reset を返すと、まだ接続が生きているピアの
    /// 接続を切ってしまうため (RFC 9000 Section 10.3)。
    fn remove_retired_cids(&mut self, cids: &[ConnectionId], conn_key: &ConnectionId) {
        for cid in cids {
            if self.cid_map.get(cid) == Some(conn_key) {
                self.cid_map.remove(cid);
            }
            self.remember_taken_cid(cid.clone());
        }
    }

    /// ngtcp2 が発行した CID をルーティングテーブルへ登録する
    ///
    /// ngtcp2 は `get_new_connection_id` コールバックで CID を発行する。発行は
    /// ハンドシェイクの処理中 (パケットの読み込み) だけでなく、パケットの
    /// 書き出し中 (NEW_CONNECTION_ID の送信) と期限処理中にも起きる。
    ///
    /// ピアは発行された CID をすぐに DCID として使い始めるため、読み書きの
    /// たびに登録しないとパケットを接続に振り分けられず、未知の DCID として
    /// Stateless Reset を返して生きている接続を止めてしまう。
    ///
    /// `Server` のフィールドを分けて借りるため、メソッドではなく関数にしている
    /// (`self.connections` から借用した接続を渡しながら `self.cid_map` を
    /// 更新する必要があるため)。
    fn register_issued_cids(
        conn: &mut ServerConnection,
        cid_map: &mut HashMap<ConnectionId, ConnectionId>,
        short_cid_lengths: &mut BTreeSet<usize>,
        conn_key: &ConnectionId,
    ) {
        for cid in conn.conn.poll_issued_cids() {
            short_cid_lengths.insert(cid.len());
            cid_map.insert(cid, conn_key.clone());
        }
    }

    /// ハンドシェイクが完了した接続をマップから取り出してハンドルを返す
    fn take_connection(&mut self, conn_key: &ConnectionId) -> AcceptedConnection {
        let conn = self
            .connections
            .remove(conn_key)
            .expect("connection was checked to exist");

        // ルーティングテーブルから該当接続のエントリを除去し、
        // 使っていた CID を引き渡し済みとして記録する。
        // 記録しないと、以降この CID を持つパケットを「接続状態を失った」と
        // 誤認して Stateless Reset を返し、生きている接続を止めてしまう。
        let taken: Vec<ConnectionId> = self
            .cid_map
            .iter()
            .filter(|(_, key)| *key == conn_key)
            .map(|(cid, _)| cid.clone())
            .collect();
        for cid in taken {
            self.remember_taken_cid(cid);
        }
        self.cid_map.retain(|_, key| key != conn_key);
        self.addr_map.retain(|_, key| key != conn_key);

        AcceptedConnection {
            sockets: Arc::clone(&self.sockets),
            local_addr: self.local_addr,
            connection_id: conn_key.clone(),
            inner: conn,
            alt_recv_buf: if self.sockets.preferred_addr().is_some() {
                vec![0u8; RECV_BUFFER_SIZE]
            } else {
                Vec::new()
            },
        }
    }

    /// closing / draining 期間に入った接続を除去する
    ///
    /// CONNECTION_CLOSE の再送 (RFC 9000 Section 11.1 の SHOULD) と
    /// draining 期間の維持 (RFC 9000 Section 10.2) は行わない。
    /// 終了状態の接続を保持し続けるコストを避けるための意図的な逸脱で、
    /// 除去後に届くパケットは未知 DCID として破棄される (RFC 9000 Section 5.2.2)。
    fn remove_closed_connections(&mut self) {
        let closed: Vec<ConnectionId> = self
            .connections
            .iter()
            .filter(|(_, conn)| {
                conn.conn.is_in_closing_period() || conn.conn.is_in_draining_period()
            })
            .map(|(key, _)| key.clone())
            .collect();

        for key in closed {
            self.remove_connection(&key);
        }
    }

    /// 引き渡し済みの CID を記録する
    ///
    /// 上限を超えたら最も古いものから忘れる。
    fn remember_taken_cid(&mut self, cid: ConnectionId) {
        if self.taken_cids.insert(cid.clone()) {
            self.taken_cid_order.push_back(cid);
        }
        while self.taken_cid_order.len() > MAX_TAKEN_CIDS {
            // pop_front は len > MAX_TAKEN_CIDS >= 1 の間だけ呼ぶため必ず Some
            let oldest = self
                .taken_cid_order
                .pop_front()
                .expect("taken_cid_order is not empty");
            self.taken_cids.remove(&oldest);
        }
    }

    /// 引き渡し済みの CID かどうかを返す
    fn is_taken_cid(&self, cid: &ConnectionId) -> bool {
        self.taken_cids.contains(cid)
    }

    /// 接続をマップとルーティングテーブルから除去する
    fn remove_connection(&mut self, conn_key: &ConnectionId) {
        self.connections.remove(conn_key);
        self.cid_map.retain(|_, key| key != conn_key);
        self.addr_map.retain(|_, key| key != conn_key);
    }
}

/// 受信したデータグラムを処理してイベントを積む
fn read_packet(
    conn: &mut ServerConnection,
    local_addr: SocketAddr,
    from: SocketAddr,
    data: &[u8],
    ts: u64,
    ecn: u8,
) -> Result<()> {
    // 受信した ECN コードポイントをそのまま渡す。ngtcp2 はこれを使って
    // ECN の検証と ACK_ECN の送信を行う (RFC 9000 Section 13.4.2)
    let info = PacketInfo { ecn };
    let path = PathInfo {
        local: local_addr,
        remote: from,
    };
    let result = conn.conn.read_pkt(&path, &info, data, ts);

    drain_events(conn);

    result
}

/// sans-IO 層で発生したイベントを取り込んで変換する
///
/// ngtcp2 のコールバックは `read_pkt` / `write_pkt` / `handle_expiry` の
/// 内部から同期的に呼ばれる。エラーが返った場合でもコールバックは
/// 呼ばれているため、成否に関わらず取り出す。
fn drain_events(conn: &mut ServerConnection) {
    while let Some(event) = conn.conn.poll_event() {
        // ハンドシェイクが完了したら、アドレスを検証できた接続に対して
        // NEW_TOKEN を配布する (RFC 9000 Section 8.1.3)。次の接続でクライアントが
        // トークンを提示すると、サーバーは Retry を省略できる
        if matches!(event, shiguredo_ngtcp2::ConnectionEvent::HandshakeCompleted) {
            submit_new_token(conn);
        }

        // 0-RTT (early data) で届いたアプリケーションデータを記録する
        // (RFC 9001 Section 4.6)。
        //
        // 0-RTT かどうかはデータを受け取った時点でしか判定できない。
        // `Server::accept` はハンドシェイクの完了を待つため、接続を取り出した
        // 時点では `is_in_early_data` は false になっている。
        if conn.conn.is_in_early_data()
            && matches!(
                event,
                shiguredo_ngtcp2::ConnectionEvent::StreamData { .. }
                    | shiguredo_ngtcp2::ConnectionEvent::Datagram { .. }
            )
        {
            conn.early_data_received = true;
        }

        // 経路の検証に成功したら、以後はその経路 (送信元アドレス) を使う
        if let shiguredo_ngtcp2::ConnectionEvent::PathValidated {
            path,
            success: true,
        } = &event
        {
            conn.remote_addr = path.remote;
        }
        conn.events.push(event.into());
    }
}

/// NEW_TOKEN フレームでアドレス検証トークンを送る (RFC 9000 Section 8.1.3)
///
/// アドレスを検証できた接続にだけ送る。送ったフレームは次の flush で書き出される。
fn submit_new_token(conn: &mut ServerConnection) {
    if conn.new_token_submitted || !conn.address_validated {
        return;
    }
    let Some(secret) = conn.new_token_secret.clone() else {
        return;
    };

    let ts = timestamp();
    let token = match generate_new_token(&secret, conn.remote_addr, ts) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("[shiguredo_ngtcp2_tokio] failed to generate a new token: {e}");
            return;
        }
    };

    match conn.conn.submit_new_token(token.as_bytes()) {
        Ok(()) => conn.new_token_submitted = true,
        Err(e) => {
            eprintln!("[shiguredo_ngtcp2_tokio] failed to submit a new token: {e}");
        }
    }
}

/// 送信待ちデータを書き出して、送信するパケットを返す
///
/// ストリームデータと制御フレームの両方を書き出す。フロー制御でブロックされた
/// ストリームは送信待ちとして保持し、次の呼び出しで再試行する。
fn flush_to_packets(conn: &mut ServerConnection, ts: u64) -> Result<Vec<OutgoingPacket>> {
    let result = write_packets(&mut conn.conn, &mut conn.pending, &mut conn.send_buf, ts);
    // 送信側でもコールバックが発生する (MAX_STREAMS の送信など)
    drain_events(conn);
    conn.qlog.write(&mut conn.conn);
    result
}

/// 受信したデータグラムを処理する
fn handle_datagram(
    conn: &mut ServerConnection,
    local_addr: SocketAddr,
    from: SocketAddr,
    data: &[u8],
    ts: u64,
    ecn: u8,
) -> Result<()> {
    if let Err(e) = read_packet(conn, local_addr, from, data, ts, ecn) {
        match e.classify_connection_error() {
            // パケットの破棄指示は無視する (RFC 9000 Section 5.2.2)
            ConnectionErrorKind::Ignore => {}
            // 接続の終了は次のループで ConnectionClosed として通知する
            ConnectionErrorKind::Terminal
            | ConnectionErrorKind::SilentDrop
            | ConnectionErrorKind::TransportClose
            | ConnectionErrorKind::ApplicationClose => {}
            ConnectionErrorKind::Internal => return Err(e),
        }
    }
    Ok(())
}

/// DATAGRAM を送信する (RFC 9221)
async fn send_datagram_impl(
    conn: &mut ServerConnection,
    data: &[u8],
    sockets: &ServerSockets,
) -> Result<()> {
    if data.len() > conn.datagram.max_tx_datagram_size {
        return Err(Error::InvalidArgument(format!(
            "datagram size {} exceeds max_tx_datagram_size {}",
            data.len(),
            conn.datagram.max_tx_datagram_size
        )));
    }

    let ts = timestamp();
    let (written, accepted, path, info) = conn.conn.write_datagram(&mut conn.send_buf, data, ts)?;
    if !accepted {
        // 輻輳制御などで送れなかった。DATAGRAM は再送しない (RFC 9221 Section 3)
        return Ok(());
    }

    let mut packets = Vec::new();
    if written > 0 {
        packets.push(OutgoingPacket::from_written(
            conn.send_buf[..written].to_vec(),
            path,
            info.ecn,
        )?);
    } else {
        packets.extend(write_control_packets(
            &mut conn.conn,
            &mut conn.send_buf,
            ts,
        )?);
    }

    sockets.send_packets(&packets).await;
    Ok(())
}

/// イベントを 1 つ取り出す
fn pop_event(events: &mut Vec<ConnectionEvent>) -> Option<ConnectionEvent> {
    if events.is_empty() {
        return None;
    }
    Some(events.remove(0))
}

/// 接続終了イベントを積む (一度だけ)
fn push_connection_closed(conn: &mut ServerConnection) {
    if conn.closed {
        return;
    }
    conn.closed = true;

    let err = conn.conn.get_connection_error();
    let kind = if err.has_error {
        if err.is_application {
            ConnectionErrorKind::ApplicationClose
        } else {
            ConnectionErrorKind::TransportClose
        }
    } else {
        ConnectionErrorKind::Terminal
    };

    conn.events.push(ConnectionEvent::ConnectionClosed {
        error_code: err.error_code,
        reason: err.reason,
        kind,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テストでサポート対象とする QUIC バージョン
    fn supported_versions() -> Vec<QuicVersion> {
        vec![QuicVersion::V1, QuicVersion::V2]
    }

    /// Initial パケットを組み立てる
    ///
    /// Long header の種別ビットは QUIC バージョンごとに異なる
    /// (v1 は RFC 9000 Section 17.2、v2 は RFC 9369 Section 3.2) ため、
    /// バージョンから先頭バイトを求める。Token Length と Length は
    /// 可変長整数として正しく書く (RFC 9000 Section 17.2.2)。
    fn make_initial(version: QuicVersion, dcid_len: usize, scid_len: usize) -> Vec<u8> {
        // Initial の種別ビット: v1 は 0x0、v2 は 0x1
        let type_bits = match version {
            QuicVersion::V1 => 0x0u8,
            QuicVersion::V2 => 0x1u8,
        };

        let mut data = Vec::new();
        data.push(0x80 | 0x40 | (type_bits << 4));
        data.extend_from_slice(&version.as_u32().to_be_bytes());
        data.push(dcid_len as u8);
        data.extend_from_slice(&vec![0x11u8; dcid_len]);
        data.push(scid_len as u8);
        data.extend_from_slice(&vec![0x22u8; scid_len]);

        // Token Length = 0
        shiguredo_ngtcp2::varint::encode_to_vec(0, &mut data);
        // Length はパケット番号と暗号化ペイロードの長さ。
        // Length 自体は 2 バイトの可変長整数で書くためその分を引く。
        let rest = shiguredo_ngtcp2::MIN_INITIAL_DATAGRAM_SIZE.saturating_sub(data.len() + 2);
        shiguredo_ngtcp2::varint::encode_to_vec(rest as u64, &mut data);

        // Initial を含むデータグラムは 1200 バイト以上 (RFC 9000 Section 14.1)
        data.resize(shiguredo_ngtcp2::MIN_INITIAL_DATAGRAM_SIZE, 0);
        data
    }

    /// Initial でない Long header は新規接続として扱わないこと
    #[test]
    fn test_accept_initial_rejects_non_initial() {
        // QUIC v1 の Handshake は種別ビット 0x2 (先頭バイト 0xE0)
        let mut data = make_initial(QuicVersion::V1, 8, 4);
        data[0] = 0xe0;
        assert!(
            accept_initial_packet(&data, &supported_versions()).is_none(),
            "Handshake は新規接続として扱わないこと"
        );

        // QUIC v2 で先頭バイト 0xC0 は Retry (種別ビット 0x0)
        let mut data = make_initial(QuicVersion::V2, 8, 4);
        data[0] = 0xc0;
        assert!(
            accept_initial_packet(&data, &supported_versions()).is_none(),
            "QUIC v2 の Retry は新規接続として扱わないこと"
        );
    }

    /// 1200 バイト未満の Initial は破棄されること (RFC 9000 Section 14.1)
    #[test]
    fn test_accept_initial_rejects_short_datagram() {
        let data = make_initial(QuicVersion::V1, 8, 4);
        assert!(
            accept_initial_packet(&data[..100], &supported_versions()).is_none(),
            "1200 バイト未満は破棄すること"
        );
    }

    /// 有効な Initial がパースできること
    #[test]
    fn test_accept_initial_accepts_initial() {
        // DCID 長 8、SCID 長 4
        let data = make_initial(QuicVersion::V1, 8, 4);

        let (version, accepted) = accept_initial_packet(&data, &supported_versions())
            .expect("有効な Initial がパースできること");
        assert_eq!(version, QuicVersion::V1, "QUIC v1");
        assert_eq!(accepted.dcid.len(), 8, "DCID 長");
        assert_eq!(accepted.scid.len(), 4, "SCID 長");
        assert!(accepted.token.is_empty(), "トークンを持たないこと");
    }

    /// QUIC v2 の Initial もパースできること (RFC 9369 Section 3.2)
    ///
    /// v2 の Initial は種別ビットが 0x1 (先頭バイト 0xD0) であり、
    /// v1 の 0-RTT と同じ値になる。バージョンを見て判定しなければならない。
    #[test]
    fn test_accept_initial_accepts_v2() {
        let data = make_initial(QuicVersion::V2, 8, 4);
        assert_eq!(data[0], 0xd0, "QUIC v2 の Initial は先頭バイト 0xD0");

        let (version, _) = accept_initial_packet(&data, &supported_versions())
            .expect("QUIC v2 の Initial がパースできること");
        assert_eq!(version, QuicVersion::V2, "QUIC v2 であること");
    }

    /// サポートしていないバージョンは新規接続として扱わないこと
    #[test]
    fn test_accept_initial_rejects_unsupported_version() {
        let data = make_initial(QuicVersion::V2, 8, 4);

        assert!(
            accept_initial_packet(&data, &[QuicVersion::V1]).is_none(),
            "サポート外のバージョンは新規接続として扱わないこと"
        );
    }

    /// DCID 長が 8 未満の Initial は破棄されること (RFC 9000 Section 7.2)
    #[test]
    fn test_accept_initial_rejects_short_dcid() {
        let data = make_initial(QuicVersion::V1, 4, 4);
        assert!(
            accept_initial_packet(&data, &supported_versions()).is_none(),
            "DCID が 8 バイト未満の Initial は破棄すること"
        );
    }

    /// サポート外のバージョンは Version Negotiation が必要と判定されること
    /// (RFC 9000 Section 6)
    #[test]
    fn test_version_negotiation_info_for_unsupported_version() {
        let mut data = vec![0xc0u8; 1300];
        // 未知のバージョン 0xdeadbeef
        data[1..5].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        data[5] = 8;
        data[14] = 4;
        // 未知のバージョンでは種別を判定できないこと
        let _ = &data;

        let info = version_negotiation_info(&data, &supported_versions())
            .expect("サポート外のバージョンは Version Negotiation が必要なこと");
        assert_eq!(info.version, 0xdead_beef, "クライアントのバージョン");
        assert_eq!(info.dcid.len(), 8, "DCID 長");
        assert_eq!(info.scid.len(), 4, "SCID 長");
    }

    /// サポートするバージョンに Version Negotiation を送ってはいけないこと
    /// (RFC 9000 Section 6)
    #[test]
    fn test_version_negotiation_info_skips_supported_version() {
        let data = make_initial(QuicVersion::V1, 8, 4);

        assert!(
            version_negotiation_info(&data, &supported_versions()).is_none(),
            "サポートするバージョンに Version Negotiation は送らないこと"
        );
    }

    /// 1200 バイト未満のデータグラムには Version Negotiation を送らないこと
    ///
    /// RFC 9000 Section 14.1 の破棄要件に合わせ、ngtcp2 が解析を拒否する。
    #[test]
    fn test_version_negotiation_info_rejects_short_datagram() {
        let mut data = vec![0xc0u8; 100];
        data[1..5].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        data[5] = 8;

        assert!(
            version_negotiation_info(&data, &supported_versions()).is_none(),
            "1200 バイト未満には Version Negotiation を送らないこと"
        );
    }

    /// Short header は Version Negotiation の対象外であること
    #[test]
    fn test_version_negotiation_info_rejects_short_header() {
        let mut data = vec![0x40u8; 1300];
        data[1] = 16;

        assert!(
            version_negotiation_info(&data, &supported_versions()).is_none(),
            "Short header は Version Negotiation の対象外であること"
        );
    }

    /// Short header は DCID を長さの集合で照合すること (RFC 9000 Section 17.3)
    #[test]
    fn test_resolve_dcid_short_header() {
        let cid = ConnectionId::new(&[0xaa; 16]).expect("test must succeed");
        let key = ConnectionId::new(&[0x01]).expect("test must succeed");

        let mut cid_map = HashMap::new();
        cid_map.insert(cid.clone(), key.clone());
        let mut lengths = BTreeSet::new();
        lengths.insert(16);

        // Short header: 先頭バイト + CID 16 バイト
        let mut packet = vec![0x40u8];
        packet.extend_from_slice(&[0xaa; 16]);
        packet.extend_from_slice(&[0u8; 4]);

        assert_eq!(
            resolve_dcid(&cid_map, &lengths, &packet),
            Some(key),
            "Short header の DCID が解決できること"
        );
    }

    /// 未知の DCID は解決できないこと (RFC 9000 Section 5.2.2)
    #[test]
    fn test_resolve_dcid_unknown() {
        let cid_map = HashMap::new();
        let mut lengths = BTreeSet::new();
        lengths.insert(16);

        let mut packet = vec![0x40u8];
        packet.extend_from_slice(&[0xbb; 16]);
        assert!(
            resolve_dcid(&cid_map, &lengths, &packet).is_none(),
            "未知の DCID は解決できないこと"
        );
    }

    /// Stateless Reset の送信がバースト上限で制限されること
    #[test]
    fn test_stateless_reset_limiter_burst() {
        let mut limiter = StatelessResetLimiter::new();

        // 時刻を進めなければ補充されないため、上限までしか許可されない
        let mut allowed = 0;
        for _ in 0..(STATELESS_RESET_BURST * 2) {
            if !limiter.try_acquire(0) {
                break;
            }
            allowed += 1;
        }
        assert_eq!(
            allowed, STATELESS_RESET_BURST,
            "バースト上限まで許可されること"
        );
        assert!(!limiter.try_acquire(0), "上限を超えたら許可されないこと");
    }

    /// 時間が経つと Stateless Reset の送信許可が補充されること
    #[test]
    fn test_stateless_reset_limiter_refills() {
        let mut limiter = StatelessResetLimiter::new();

        // 空にする
        for _ in 0..STATELESS_RESET_BURST {
            assert!(limiter.try_acquire(0), "バースト上限までは許可されること");
        }
        assert!(!limiter.try_acquire(0), "空のときは許可されないこと");

        // 1 秒で STATELESS_RESET_RATE 個ぶん補充されること
        let one_second = NANOS_PER_SEC;
        let mut allowed = 0;
        for _ in 0..(STATELESS_RESET_RATE * 2) {
            if !limiter.try_acquire(one_second) {
                break;
            }
            allowed += 1;
        }
        assert_eq!(
            allowed, STATELESS_RESET_RATE,
            "1 秒で補充される個数だけ許可されること"
        );
    }

    /// 長時間経過してもバケットは上限を超えないこと
    #[test]
    fn test_stateless_reset_limiter_caps_at_burst() {
        let mut limiter = StatelessResetLimiter::new();

        // 空にする
        for _ in 0..STATELESS_RESET_BURST {
            assert!(limiter.try_acquire(0), "バースト上限までは許可されること");
        }

        // 十分に長い時間が経っても上限までしか溜まらないこと
        let long_time = NANOS_PER_SEC * 3600;
        let mut allowed = 0;
        for _ in 0..(STATELESS_RESET_BURST * 2) {
            if !limiter.try_acquire(long_time) {
                break;
            }
            allowed += 1;
        }
        assert_eq!(
            allowed, STATELESS_RESET_BURST,
            "バケットは上限を超えて溜まらないこと"
        );
    }
}
