//! UDP ソケットのラッパーとタイムスタンプ

use std::io;
use std::mem::size_of;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::Interest;
use tokio::net::UdpSocket;

/// ECN のコードポイント (RFC 3168 Section 5)
///
/// IP ヘッダーの ECN フィールドの値であり、ngtcp2 の
/// `ngtcp2_pkt_info.ecn` と同じ表現。
// 全てのコードポイントはテストで送受信を検証するために定義している
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod ecn {
    /// ECN 非対応 (Not-ECT)
    pub(crate) const NOT_ECT: u8 = 0b00;
    /// ECN Capable Transport (1)
    pub(crate) const ECT1: u8 = 0b01;
    /// ECN Capable Transport (0)
    pub(crate) const ECT0: u8 = 0b10;
    /// Congestion Experienced
    pub(crate) const CE: u8 = 0b11;
}

/// ECN フィールドだけを取り出すマスク
const ECN_MASK: u8 = 0b11;

/// 補助データ (ECN) を受け取るバッファのサイズ (バイト)
///
/// TOS / TCLASS の cmsg 1 つ分あれば足りる。
const CONTROL_BUFFER_SIZE: usize = 64;

/// 補助データ (cmsg) 用のバッファ
///
/// `cmsghdr` はプラットフォームごとの境界に整列している必要があるが、
/// `[u8; N]` のアラインメントは 1 なので、そのままでは `CMSG_FIRSTHDR` が
/// 返すポインタを参照外ししたときに misaligned pointer dereference になる
/// (Linux の debug ビルドでは abort する)。アラインメントを明示した型で確保する。
#[repr(C, align(8))]
struct ControlBuffer([u8; CONTROL_BUFFER_SIZE]);

impl ControlBuffer {
    /// ゼロ初期化したバッファを作る
    fn new() -> Self {
        Self([0u8; CONTROL_BUFFER_SIZE])
    }

    /// 先頭への可変ポインタを返す
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    /// 長さを返す
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// UDP ソケットのラッパー
///
/// `tokio::net::UdpSocket` を包み、バインド時のローカルアドレスを保持する。
/// QUIC は 1 つの UDP ソケットで複数の接続を多重化するため、接続ごとに
/// 使い回せるよう `Arc<UdpSocket>` を取り出せるようにしている。
///
/// ECN (RFC 9000 Section 13.4) を扱うため、送受信には `recvmsg` / `sendmsg` を
/// 使い、補助データで ECN コードポイントをやり取りする。準備完了の待ち合わせは
/// tokio の `try_io` に任せる。
pub(crate) struct Socket {
    inner: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl Socket {
    /// 指定アドレスにバインドする
    ///
    /// ECN コードポイントを受信できるようにもする。設定に失敗した場合は
    /// ECN を使わない (接続自体は動かせる) ため、エラーにはしない。
    pub(crate) async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inner = UdpSocket::bind(addr).await?;
        let local_addr = inner.local_addr()?;
        let socket = Self {
            inner: Arc::new(inner),
            local_addr,
        };
        socket.enable_ecn();
        Ok(socket)
    }

    /// 受信したデータグラムの ECN コードポイントを取得できるようにする
    fn enable_ecn(&self) {
        let fd = self.inner.as_raw_fd();
        let enable: libc::c_int = 1;

        // SAFETY: fd は有効なソケット。enable は c_int の有効な領域
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVTOS,
                &enable as *const _ as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
            // IPv6 ソケットでは IPv4 のオプションは失敗するため、両方試す
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                &enable as *const _ as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    /// ローカルアドレスを返す
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// ECN コードポイントを付けて UDP データグラムを送信する
    ///
    /// ngtcp2 が要求した ECN をそのまま設定する (RFC 9000 Section 13.4.1)。
    pub(crate) async fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddr,
        ecn: u8,
    ) -> io::Result<usize> {
        send_to(&self.inner, buf, target, ecn).await
    }

    /// UDP データグラムと ECN コードポイントを受信する
    pub(crate) async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, u8)> {
        recv_from(&self.inner, buf).await
    }
}

/// ECN コードポイントを付けて UDP データグラムを送信する
///
/// サーバーが接続を引き渡した後は `Arc<UdpSocket>` を直接使うため、
/// ソケット単体でも使えるよう関数として公開する。
pub(crate) async fn send_to(
    socket: &UdpSocket,
    buf: &[u8],
    target: SocketAddr,
    ecn: u8,
) -> io::Result<usize> {
    loop {
        socket.writable().await?;
        match socket.try_io(Interest::WRITABLE, || {
            send_to_sync(socket, buf, target, ecn)
        }) {
            Ok(written) => return Ok(written),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

/// UDP データグラムと ECN コードポイントを受信する
pub(crate) async fn recv_from(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, u8)> {
    loop {
        socket.readable().await?;
        match socket.try_io(Interest::READABLE, || recv_from_sync(socket, buf)) {
            Ok(received) => return Ok(received),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

/// `sendmsg` で ECN を付けて送信する
fn send_to_sync(socket: &UdpSocket, buf: &[u8], target: SocketAddr, ecn: u8) -> io::Result<usize> {
    let (mut addr, addr_len) = sockaddr_to_raw(&target);

    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // SAFETY: msghdr は全てのビットパターンが有効な POD
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = addr_len;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1 as _;

    // ECN 非対応 (0) の場合は補助データを付けない
    let mut control = ControlBuffer::new();
    if ecn != ecn::NOT_ECT {
        let (level, ty) = match target {
            SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_TOS),
            SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
        };

        // SAFETY: control は cmsg を 1 つ格納できる大きさがある
        unsafe {
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            // 実際に使う cmsg の長さだけを伝える。バッファ全体を伝えると
            // 後ろのゼロ埋め領域を cmsg として解釈させてしまう
            msg.msg_controllen = libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as _;

            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = level;
            (*cmsg).cmsg_type = ty;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;

            // TOS / TCLASS は int として渡す
            let value = ecn as libc::c_int;
            std::ptr::copy_nonoverlapping(
                &value as *const _ as *const u8,
                libc::CMSG_DATA(cmsg),
                size_of::<libc::c_int>(),
            );
        }
    }

    // SAFETY: fd は有効なソケット。msg の各ポインタはこの呼び出し中有効
    let n = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// `recvmsg` で ECN コードポイントも受信する
fn recv_from_sync(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, u8)> {
    let mut control = ControlBuffer::new();
    let mut addr: libc::sockaddr_storage =
        // SAFETY: sockaddr_storage は全てのビットパターンが有効な POD
        unsafe { std::mem::zeroed() };

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // SAFETY: msghdr は全てのビットパターンが有効な POD
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1 as _;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    // SAFETY: fd は有効なソケット。msg の各ポインタはこの呼び出し中有効
    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let from = sockaddr_from_raw(&addr, msg.msg_namelen)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unsupported address family"))?;

    Ok((n as usize, from, parse_ecn(&msg)))
}

/// 受信した補助データから ECN コードポイントを取り出す
///
/// TOS / TCLASS の cmsg は int (FreeBSD のみ byte) で渡されるため、
/// リトルエンディアンでは先頭バイトの下位 2 ビットが ECN フィールドになる。
fn parse_ecn(msg: &libc::msghdr) -> u8 {
    let mut ecn = ecn::NOT_ECT;

    // SAFETY: msg は recvmsg が書き込んだ有効な msghdr
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ty = (*cmsg).cmsg_type;
            // cmsg の種別は環境によって IP_TOS / IP_RECVTOS のどちらかになる
            // (macOS は IP_RECVTOS)。s2n-quic も両方を受け付けている。
            let is_tos = (level == libc::IPPROTO_IP
                && (ty == libc::IP_TOS || ty == libc::IP_RECVTOS))
                || (level == libc::IPPROTO_IPV6
                    && (ty == libc::IPV6_TCLASS || ty == libc::IPV6_RECVTCLASS));
            if is_tos {
                ecn = *libc::CMSG_DATA(cmsg) & ECN_MASK;
                break;
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }

    ecn
}

/// `sockaddr_storage` を `SocketAddr` に変換する
///
/// 対応していないアドレスファミリの場合は `None` を返す。
fn sockaddr_from_raw(addr: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    match addr.ss_family as libc::c_int {
        libc::AF_INET => {
            if (len as usize) < size_of::<libc::sockaddr_in>() {
                return None;
            }
            // SAFETY: addr は sockaddr_in として有効な領域
            let sin = unsafe { &*(addr as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::new(ip.into(), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            if (len as usize) < size_of::<libc::sockaddr_in6>() {
                return None;
            }
            // SAFETY: addr は sockaddr_in6 として有効な領域
            let sin6 = unsafe { &*(addr as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::new(ip.into(), u16::from_be(sin6.sin6_port)))
        }
        _ => None,
    }
}

/// `SocketAddr` を `sockaddr_storage` に変換する
fn sockaddr_to_raw(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage は全てのビットパターンが有効な POD
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    match addr {
        SocketAddr::V4(v4) => {
            // SAFETY: storage は sockaddr_in を格納できる大きさがあり、
            // sockaddr_in は同じ先頭レイアウトを持つ
            let sin: &mut libc::sockaddr_in =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (storage, size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        SocketAddr::V6(v6) => {
            // SAFETY: storage は sockaddr_in6 を格納できる大きさがあり、
            // sockaddr_in6 は同じ先頭レイアウトを持つ
            let sin6: &mut libc::sockaddr_in6 =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            (storage, size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

/// プロセス起動からの経過時間をナノ秒で返す
///
/// ngtcp2 のタイムスタンプは単調増加であればよいため、プロセス内で共有する
/// 基準時刻からの経過時間を使う。`Instant` は単調増加が保証される。
pub(crate) fn timestamp() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_nanos() as u64
}

/// サーバーが使うソケット
///
/// RFC 9000 Section 9.6 の優先アドレス (preferred_address) を通知する場合、
/// サーバーは優先アドレス用に 2 つ目のソケットを持つ。パケットの送信元
/// アドレスに応じて使うソケットを選ぶ。
pub(crate) struct ServerSockets {
    /// 主アドレスのソケット
    primary: Socket,
    /// 主アドレス
    primary_addr: SocketAddr,
    /// 優先アドレスのソケットとアドレス
    preferred: Option<(SocketAddr, Socket)>,
}

impl ServerSockets {
    /// 主アドレスのソケットを作る
    pub(crate) async fn bind(
        addr: SocketAddr,
        preferred_addr: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let primary = Socket::bind(addr).await?;
        let primary_addr = primary.local_addr();

        let preferred = match preferred_addr {
            Some(addr) => {
                let socket = Socket::bind(addr).await?;
                let bound = socket.local_addr();
                Some((bound, socket))
            }
            None => None,
        };

        Ok(Self {
            primary,
            primary_addr,
            preferred,
        })
    }

    /// 主アドレスを返す
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.primary_addr
    }

    /// 優先アドレスを返す
    pub(crate) fn preferred_addr(&self) -> Option<SocketAddr> {
        self.preferred.as_ref().map(|(addr, _)| *addr)
    }

    /// 受信する。届いたローカルアドレスも返す
    ///
    /// 優先アドレスのソケットがある場合は両方を待つ。`alt_buf` は優先アドレスの
    /// ソケット用の受信バッファ。
    pub(crate) async fn recv_from(
        &self,
        buf: &mut [u8],
        alt_buf: &mut [u8],
    ) -> io::Result<(Vec<u8>, SocketAddr, SocketAddr, u8)> {
        let (len, from, local, ecn) = match &self.preferred {
            Some((addr, socket)) => {
                tokio::select! {
                    result = self.primary.recv_from(buf) => {
                        let (len, from, ecn) = result?;
                        (len, from, self.primary_addr, ecn)
                    }
                    result = socket.recv_from(alt_buf) => {
                        let (len, from, ecn) = result?;
                        (len, from, *addr, ecn)
                    }
                }
            }
            None => {
                let (len, from, ecn) = self.primary.recv_from(buf).await?;
                (len, from, self.primary_addr, ecn)
            }
        };

        // どちらのバッファに届いたかはローカルアドレスで判断できる
        let data = if local == self.primary_addr {
            buf[..len].to_vec()
        } else {
            alt_buf[..len].to_vec()
        };

        Ok((data, from, local, ecn))
    }

    /// 送信元アドレスに応じたソケットで送る
    pub(crate) async fn send_to(
        &self,
        data: &[u8],
        local: SocketAddr,
        remote: SocketAddr,
        ecn: u8,
    ) -> io::Result<()> {
        match &self.preferred {
            Some((addr, socket)) if *addr == local => {
                socket.send_to(data, remote, ecn).await.map(|_| ())
            }
            _ => self.primary.send_to(data, remote, ecn).await.map(|_| ()),
        }
    }

    /// パケットごとに送信元のソケットを選んで送る
    ///
    /// 送信エラーは接続エラーではないためログのみ出す。
    pub(crate) async fn send_packets(&self, packets: &[crate::streams::OutgoingPacket]) {
        for packet in packets {
            if let Err(e) = self
                .send_to(&packet.data, packet.local, packet.remote, packet.ecn)
                .await
            {
                eprintln!("[shiguredo_ngtcp2_tokio] send error: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ECN を付けて送ったデータグラムが ECN 付きで受信できること
    ///
    /// IPv4 ループバックで ECT(0) を送り、受信側が同じコードポイントを
    /// 観測できることを確認する (RFC 9000 Section 13.4.1)。
    #[tokio::test]
    async fn test_ecn_roundtrip_v4() {
        let sender = Socket::bind("127.0.0.1:0".parse().expect("リテラルアドレスは有効"))
            .await
            .expect("送信側のソケットを用意できること");
        let receiver = Socket::bind("127.0.0.1:0".parse().expect("リテラルアドレスは有効"))
            .await
            .expect("受信側のソケットを用意できること");

        let target = receiver.local_addr();
        for (ecn, name) in [
            (ecn::NOT_ECT, "Not-ECT"),
            (ecn::ECT0, "ECT(0)"),
            (ecn::ECT1, "ECT(1)"),
            (ecn::CE, "CE"),
        ] {
            sender
                .send_to(b"ecn", target, ecn)
                .await
                .expect("ECN を付けて送信できること");

            let mut buf = [0u8; 64];
            let (len, from, received) = receiver.recv_from(&mut buf).await.expect("受信できること");
            assert_eq!(&buf[..len], b"ecn", "データが届くこと");
            assert_eq!(from, sender.local_addr(), "送信元アドレスが一致すること");
            assert_eq!(received, ecn, "{name} がそのまま届くこと");
        }
    }

    /// 受信したデータグラムの ECN を接続へ渡せること
    ///
    /// ECN を付けずに送った場合は Not-ECT として観測される。
    #[tokio::test]
    async fn test_ecn_not_set_is_not_ect() {
        let sender = Socket::bind("127.0.0.1:0".parse().expect("リテラルアドレスは有効"))
            .await
            .expect("送信側のソケットを用意できること");
        let receiver = Socket::bind("127.0.0.1:0".parse().expect("リテラルアドレスは有効"))
            .await
            .expect("受信側のソケットを用意できること");

        sender
            .send_to(b"plain", receiver.local_addr(), ecn::NOT_ECT)
            .await
            .expect("送信できること");

        let mut buf = [0u8; 64];
        let (len, _, received) = receiver.recv_from(&mut buf).await.expect("受信できること");
        assert_eq!(&buf[..len], b"plain", "データが届くこと");
        assert_eq!(received, ecn::NOT_ECT, "ECN なしは Not-ECT になること");
    }
}
