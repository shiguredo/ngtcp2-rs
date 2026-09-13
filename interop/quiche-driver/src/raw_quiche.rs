//! 生の quiche を直接動かすドライバ
//!
//! tokio-quiche では表現できない 2 つのモードだけをここに置く。
//!
//! - 0-RTT のデータ送信: tokio-quiche のワーカーは `process_writes` を
//!   ハンドシェイク完了後 (`is_established()`) にしか呼ばないため、
//!   クライアントが early data を送れない
//! - マイグレーション: tokio-quiche に経路の検証 / 移行の API が無く、ワーカーが
//!   ソケットを 1 つ所有するためローカルアドレスを変えられない
//!   (tokio-quiche 自身の migration テストもクライアントは生 quiche で書かれている)
//!
//! どちらも quiche の接続を直接駆動し、送信するパケットとその送信元を
//! アプリケーションが決める必要がある。quiche は BoringSSL を静的リンクするため、
//! このモジュールもテストとは別プロセスで動かす。

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// quiche が送受信する 1 データグラムの最大サイズ (バイト)
const MAX_DATAGRAM_SIZE: usize = 1350;

/// quiche 側の待ち時間の上限
const QUICHE_TIMEOUT: Duration = Duration::from_secs(20);

/// ブロッキングソケットの受信待ちの刻み
///
/// この時間だけ待ってパケットが来なければ quiche のタイマーを進める。
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// 相互運用に使う ALPN
const ALPN: &[u8] = b"hq-interop";

/// quiche のクライアント設定を作る
///
/// 証明書検証は有効にしたまま、`ca_cert_path` の証明書をトラストアンカーとして
/// 読み込む。
fn client_config(ca_cert_path: &str) -> Result<quiche::Config, String> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("設定を作成できること");
    config
        .set_application_protos(&[ALPN])
        .expect("ALPN を設定できること");
    config.set_max_idle_timeout(10_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.verify_peer(true);
    config
        .load_verify_locations_from_file(ca_cert_path)
        .map_err(|e| format!("failed to load certificate: {e}"))?;
    // クライアント自身が移るかどうかは設定で決まるため、常に移れるようにする
    config.set_disable_active_migration(false);
    Ok(config)
}

/// エフェメラルポートにバインドした UDP ソケットを作る
fn bind_socket() -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("failed to bind: {e}"))?;
    socket
        .set_read_timeout(Some(POLL_INTERVAL))
        .map_err(|e| format!("failed to set timeout: {e}"))?;
    Ok(socket)
}

/// ランダムな SCID を持つ quiche の接続を作る
fn connect(
    server_addr: SocketAddr,
    local_addr: SocketAddr,
    config: &mut quiche::Config,
) -> Result<quiche::Connection, String> {
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    getrandom::fill(&mut scid).map_err(|e| format!("failed to generate scid: {e}"))?;
    let scid = quiche::ConnectionId::from_ref(&scid);

    quiche::connect(Some("localhost"), &scid, local_addr, server_addr, config)
        .map_err(|e| format!("failed to create connection: {e}"))
}

/// quiche の接続を駆動するための状態
///
/// マイグレーションでは送信元のローカルアドレスが変わるため、ソケットは
/// ローカルアドレスをキーにした map で複数持てるようにする。
struct ClientDriver {
    /// quiche の接続
    conn: quiche::Connection,
    /// ローカルアドレスごとのソケット
    sockets: HashMap<SocketAddr, UdpSocket>,
    /// 送信バッファ
    out: [u8; MAX_DATAGRAM_SIZE],
    /// 受信バッファ
    buf: [u8; 65535],
    /// 待ち時間の上限
    deadline: Instant,
}

impl ClientDriver {
    /// ソケットを持つドライバを作る
    fn new(conn: quiche::Connection, socket: UdpSocket) -> Result<Self, String> {
        let local_addr = socket
            .local_addr()
            .map_err(|e| format!("failed to get local address: {e}"))?;
        let mut sockets = HashMap::new();
        sockets.insert(local_addr, socket);
        Ok(Self {
            conn,
            sockets,
            out: [0u8; MAX_DATAGRAM_SIZE],
            buf: [0u8; 65535],
            deadline: Instant::now() + QUICHE_TIMEOUT,
        })
    }

    /// ソケットを追加する (マイグレーション先のローカルアドレス用)
    fn add_socket(&mut self, socket: UdpSocket) -> Result<SocketAddr, String> {
        let local_addr = socket
            .local_addr()
            .map_err(|e| format!("failed to get local address: {e}"))?;
        self.sockets.insert(local_addr, socket);
        Ok(local_addr)
    }

    /// 送信できるパケットをすべて送る
    ///
    /// パケットは quiche が指定するローカルアドレスのソケットから送る。
    /// マイグレーション後は新しいソケットが使われる。
    fn send_pending(&mut self) -> Result<(), String> {
        loop {
            match self.conn.send(&mut self.out) {
                Ok((written, send_info)) => {
                    let socket = self
                        .sockets
                        .get(&send_info.from)
                        .ok_or_else(|| format!("no socket bound to {}", send_info.from))?;
                    socket
                        .send_to(&self.out[..written], send_info.to)
                        .map_err(|e| format!("failed to send packet: {e}"))?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(e) => return Err(format!("failed to write packet: {e}")),
            }
        }
    }

    /// パケットを 1 度受信する。受信できたかを返す
    fn recv_once(&mut self) -> Result<bool, String> {
        let local_addrs: Vec<SocketAddr> = self.sockets.keys().copied().collect();
        for local_addr in local_addrs {
            let socket = &self.sockets[&local_addr];
            match socket.recv_from(&mut self.buf) {
                Ok((len, from)) => {
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };
                    // 復号できないパケットは quiche が捨てるため、エラーは無視する
                    let _ = self.conn.recv(&mut self.buf[..len], recv_info);
                    return Ok(true);
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => return Err(format!("failed to receive packet: {e}")),
            }
        }
        Ok(false)
    }

    /// 条件が満たされるまでパケットを送受信する
    fn wait_until<F>(&mut self, mut predicate: F, description: &str) -> Result<(), String>
    where
        F: FnMut(&quiche::Connection) -> bool,
    {
        while !predicate(&self.conn) {
            if Instant::now() > self.deadline {
                return Err(format!("timed out while waiting for {description}"));
            }
            // パケットが来ていないときだけタイマーを進める
            if !self.recv_once()? {
                self.conn.on_timeout();
            }
            self.send_pending()?;
        }
        Ok(())
    }

    /// 指定したローカルアドレスの経路の検証が完了するまでパケットを送受信する
    ///
    /// 検証の完了は [`quiche::PathEvent::Validated`] で通知される。
    fn wait_path_validated(&mut self, local_addr: SocketAddr) -> Result<(), String> {
        loop {
            if Instant::now() > self.deadline {
                return Err(format!(
                    "timed out while waiting for the path validation of {local_addr}"
                ));
            }

            while let Some(event) = self.conn.path_event_next() {
                if let quiche::PathEvent::Validated(local, _) = event
                    && local == local_addr
                {
                    return Ok(());
                }
            }

            if !self.recv_once()? {
                self.conn.on_timeout();
            }
            self.send_pending()?;
        }
    }

    /// FIN が届くまでストリームデータを読み続ける
    fn read_echo(&mut self) -> Result<Vec<u8>, String> {
        let mut received = Vec::new();
        let mut fin = false;
        while !fin {
            if Instant::now() > self.deadline {
                return Err("timed out while waiting for the echo".to_string());
            }

            // 受信したストリームデータを取り出す
            for stream_id in self.conn.readable() {
                while let Ok((read, stream_fin)) = self.conn.stream_recv(stream_id, &mut self.buf) {
                    received.extend_from_slice(&self.buf[..read]);
                    if stream_fin {
                        fin = true;
                    }
                }
            }
            if fin {
                break;
            }

            if !self.recv_once()? {
                self.conn.on_timeout();
            }
            self.send_pending()?;
        }
        Ok(received)
    }
}

/// quiche のクライアントで 0-RTT のデータを送り、エコーを受け取る
///
/// 1 回目の接続でセッションチケットを保存し、2 回目の接続でハンドシェイクの
/// 完了を待たずにデータを送る (RFC 9001 Section 4.6)。戻り値は 2 回目の接続で
/// 送ったデータのエコー。
pub fn client_early_data_roundtrip(
    server_addr: SocketAddr,
    ca_cert_path: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let session = fetch_session(server_addr, ca_cert_path)?;

    let mut config = client_config(ca_cert_path)?;
    // 保存したセッション情報で 0-RTT を送れるようにする
    config.enable_early_data();

    let socket = bind_socket()?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("failed to get local address: {e}"))?;
    let conn = connect(server_addr, local_addr, &mut config)?;

    let mut driver = ClientDriver::new(conn, socket)?;
    // セッション情報はパケットを送る前に設定する
    driver
        .conn
        .set_session(&session)
        .map_err(|e| format!("failed to set session: {e}"))?;
    // ハンドシェイクの完了を待たずにデータを積む。ここで積んだデータが
    // 0-RTT のパケットで送られる
    driver
        .conn
        .stream_send(0, payload, true)
        .map_err(|e| format!("failed to send early data: {e}"))?;
    driver.send_pending()?;

    let echoed = driver.read_echo()?;
    if !driver.conn.is_resumed() {
        return Err("the server did not resume the session".to_string());
    }
    Ok(echoed)
}

/// quiche のクライアントで接続し、途中でローカルアドレスを変えてエコーを受け取る
///
/// ハンドシェイクの完了後に新しいローカルアドレスで経路を検証し、検証できたら
/// その経路へ移ってデータを送る (RFC 9000 Section 9)。
pub fn client_migrate_roundtrip(
    server_addr: SocketAddr,
    ca_cert_path: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut config = client_config(ca_cert_path)?;
    let socket = bind_socket()?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("failed to get local address: {e}"))?;
    let conn = connect(server_addr, local_addr, &mut config)?;

    let mut driver = ClientDriver::new(conn, socket)?;
    driver.send_pending()?;
    driver.wait_until(|conn| conn.is_established(), "the handshake")?;

    // マイグレーションにはピアが発行した未使用のコネクション ID が要る
    // (RFC 9000 Section 9.5)。届くまで駆動する
    driver.wait_until(
        |conn| conn.available_dcids() > 0,
        "a spare destination connection id",
    )?;

    // 自分が新しい経路で使うコネクション ID を 1 つ発行してピアに通知する。
    // 通知しないとピアは新しい経路へ応答を送れない
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    getrandom::fill(&mut scid).map_err(|e| format!("failed to generate scid: {e}"))?;
    let mut reset_token = [0u8; 16];
    getrandom::fill(&mut reset_token)
        .map_err(|e| format!("failed to generate reset token: {e}"))?;
    driver
        .conn
        .new_scid(
            &quiche::ConnectionId::from_ref(&scid),
            u128::from_be_bytes(reset_token),
            false,
        )
        .map_err(|e| format!("failed to issue a new scid: {e}"))?;
    driver.send_pending()?;

    // 新しいローカルアドレスのソケットを用意する
    let new_local_addr = driver.add_socket(bind_socket()?)?;
    // 先に新しい経路を検証する (RFC 9000 Section 9.1)。検証が終わるまでは
    // 現在の経路で通信を続ける
    driver
        .conn
        .probe_path(new_local_addr, server_addr)
        .map_err(|e| format!("failed to probe the new path: {e}"))?;
    driver.wait_path_validated(new_local_addr)?;

    // 検証できたので新しい経路へ移る
    driver
        .conn
        .migrate(new_local_addr, server_addr)
        .map_err(|e| format!("failed to migrate: {e}"))?;
    driver.send_pending()?;

    // 移った先の経路でデータを送る
    driver
        .conn
        .stream_send(0, payload, true)
        .map_err(|e| format!("failed to send request: {e}"))?;
    let echoed = driver.read_echo()?;

    // 親 (我々のサーバー) はエコーを返した後もピアが閉じるまで駆動するため、
    // エコーを受け取ったら接続を閉じる
    driver
        .conn
        .close(false, 0, b"")
        .map_err(|e| format!("failed to close the connection: {e}"))?;
    driver.send_pending()?;

    Ok(echoed)
}

/// 1 回目の接続でセッションチケットを取得する
///
/// セッションチケットはハンドシェイクの完了後にサーバーが送る
/// (RFC 8446 Section 4.6.1) ため、届くまでパケットを処理し続ける。
fn fetch_session(server_addr: SocketAddr, ca_cert_path: &str) -> Result<Vec<u8>, String> {
    let mut config = client_config(ca_cert_path)?;
    let socket = bind_socket()?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("failed to get local address: {e}"))?;
    let conn = connect(server_addr, local_addr, &mut config)?;

    let mut driver = ClientDriver::new(conn, socket)?;
    driver.send_pending()?;
    driver.wait_until(
        |conn| conn.is_established() && conn.session().is_some(),
        "the session ticket",
    )?;

    let session = driver
        .conn
        .session()
        .ok_or("the session ticket is not available")?
        .to_vec();

    // 親 (我々のサーバー) が接続の終了を観測できるよう閉じてから戻る
    driver
        .conn
        .close(false, 0, b"")
        .map_err(|e| format!("failed to close the connection: {e}"))?;
    driver.send_pending()?;

    Ok(session)
}
