//! 送信バッファのポインタ安定性を実パケット交換で検証する
//!
//! ngtcp2 は STREAM フレームの再送のため、アプリケーションが
//! `ngtcp2_conn_writev_stream` に渡したバッファへの生ポインタ
//! (`ngtcp2_vec`) を ACK されるまで保持する。アプリケーションは
//! `*pdatalen` 分の領域をその間、移動も解放もしない契約になっている。
//!
//! このクレートは `InFlightStreamData` でそのバッファを保持する。以前の実装は
//!
//! - `append` の `extend_from_slice` が容量超過で再確保して旧領域を解放する
//! - `ack_until` の `Vec::drain(..start)` が未 ACK のバイト列を移動する
//!
//! ため、ACK が 64 KiB を超えたあとにパケット損失 / PTO の再送が起きると、
//! ngtcp2 が移動前・解放済みの領域を読み、受信側でストリームデータが
//! silent に破損していた。
//!
//! このテストは実際の TLS ハンドシェイクを行った 2 つの [`Connection`] 間で
//! パケットを手動配送し、損失再送後の受信データが元のバイト列と
//! オフセット単位で一致することを確認する。UDP ソケットの代わりに
//! パケットのバイト列をメモリ上のキューで運ぶだけで、プロトコルの状態遷移は
//! すべて [`Connection`] の公開 API で駆動する (モックやスタブは使わない)。

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use shiguredo_ngtcp2::{
    CongestionAlgorithm, Connection, ConnectionEvent, ConnectionId, PacketInfo, PathInfo,
    QuicVersion, Settings, TlsContext, TransportParams, decode_packet_version,
};

/// 接続に使う ALPN
const ALPN: &[u8] = b"hq-interop";

/// パケットを書き出すバッファの大きさ
const PACKET_BUF_SIZE: usize = 65535;

/// 以前の実装が `Vec::drain(..start)` を行った ACK 済みオフセットのしきい値
///
/// 修正後はこの値を超えても未 ACK のバイト列を移動しないことを確認する。
const COMPACT_THRESHOLD: u64 = 64 * 1024;

/// 1 回の `write_stream` で渡すデータの最大量
///
/// 1 パケットに収まる大きさにしておき、パケットとストリームオフセットの
/// 対応をテスト側で確定させる。
const WRITE_CHUNK: usize = 1200;

/// テスト用の自己署名証明書 (一時ディレクトリに書き出し済み)
struct TestCert {
    temp_dir: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl TestCert {
    /// `localhost` 用の自己署名証明書を生成する
    fn generate(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!(
            "ngtcp2_buffer_lifetime_{}_{}_{}",
            label,
            std::process::id(),
            unique_id
        ));
        std::fs::create_dir_all(&temp_dir).expect("一時ディレクトリを作成できること");

        let cert_path = temp_dir.join("cert.pem");
        let key_path = temp_dir.join("key.pem");

        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("証明書パラメータ");
        let key_pair = rcgen::KeyPair::generate().expect("鍵ペアを生成できること");
        let cert = params
            .self_signed(&key_pair)
            .expect("自己署名証明書を生成できること");

        std::fs::write(&cert_path, cert.pem()).expect("証明書を書き込めること");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("秘密鍵を書き込めること");

        Self {
            temp_dir,
            cert_path,
            key_path,
        }
    }
}

impl Drop for TestCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

/// 書き出したクライアントのパケット 1 つ
struct StreamPacket {
    /// パケットのバイト列
    bytes: Vec<u8>,
    /// このパケットが運ぶ STREAM データのストリーム先頭からのオフセット
    offset: u64,
    /// このパケットが運ぶ STREAM データの長さ (0 は STREAM フレームを含まない)
    datalen: usize,
}

impl StreamPacket {
    /// このパケットが運ぶ STREAM データの終端オフセット
    fn end(&self) -> u64 {
        self.offset + self.datalen as u64
    }
}

/// クライアントとサーバーをメモリ上のパケットキューで接続する駆動装置
struct Harness {
    client: Connection,
    server: Connection,
    client_path: PathInfo,
    server_path: PathInfo,
    /// ngtcp2 に渡す単調増加のタイムスタンプ (ナノ秒)
    clock: u64,
    /// クライアントからサーバーへ未配送のパケット
    c2s: Vec<Vec<u8>>,
    /// サーバーからクライアントへ未配送のパケット
    s2c: Vec<Vec<u8>>,
    /// 送信バッファ (再利用する)
    send_buf: Vec<u8>,
    /// SSL_CTX の所有権 (Connection が参照するため保持する)
    _client_tls: Arc<TlsContext>,
    _server_tls: Arc<TlsContext>,
}

impl Harness {
    /// 実 TLS ハンドシェイクを完了させたクライアントとサーバーを作る
    fn new(cert: &TestCert) -> Self {
        let client_addr: SocketAddr = "127.0.0.1:10001".parse().expect("アドレス");
        let server_addr: SocketAddr = "127.0.0.1:10002".parse().expect("アドレス");

        // 初期タイムスタンプは 1 秒から始める (0 を特別扱いする実装を避ける)
        let clock: u64 = 1_000_000_000;

        // 輻輳制御は Reno にする。CUBIC の HyStart++ は RTT の変化で
        // スロースタートを早期終了するため、合成タイムスタンプでは
        // cwnd の伸びが不安定になる。Reno のスロースタートは
        // ACK されたパケット長の分だけ cwnd を増やすので決定的になる。
        let mut client_settings = Settings::new(clock);
        client_settings.initial_ts = clock;
        client_settings.congestion_algorithm = CongestionAlgorithm::Reno;
        // パケットを受けるたびに即 ACK させる (遅延 ACK タイマーを避ける)
        client_settings.ack_threshold = 1;
        // PMTUD を無効にして経路 MTU の探索を止める (決定的にするため)
        client_settings.no_pmtud = true;
        // 初期輻輳ウィンドウを大きくする。ngtcp2 の初期 cwnd は
        // min(10*M, max(2*M, 14720)) で、M は経路の最大 UDP ペイロード長。
        // ペイロードサイズ成形を無効にすると M がこの設定値になるため、
        // 64 KiB 超のデータを一度に in-flight にできる。
        client_settings.no_tx_udp_payload_size_shaping = true;
        client_settings.max_tx_udp_payload_size = 65527;

        let mut server_settings = Settings::new(clock);
        server_settings.initial_ts = clock;
        server_settings.congestion_algorithm = CongestionAlgorithm::Reno;
        server_settings.ack_threshold = 1;
        server_settings.no_pmtud = true;
        server_settings.no_tx_udp_payload_size_shaping = true;
        server_settings.max_tx_udp_payload_size = 65527;

        let client_params = TransportParams::new();
        let server_params = TransportParams::new();

        let client_tls = Arc::new(
            TlsContext::new_client_with_options(&[ALPN], false).expect("TLS コンテキスト"),
        );
        let server_tls = Arc::new(
            TlsContext::new_server(&cert.cert_path, &cert.key_path, &[ALPN])
                .expect("サーバーの TLS コンテキスト"),
        );

        let session = client_tls.create_session().expect("TLS セッション");
        let dcid = ConnectionId::random(16).expect("DCID");
        let scid = ConnectionId::random(16).expect("SCID");

        let mut client = Connection::client_new(
            &dcid,
            &scid,
            client_addr,
            server_addr,
            QuicVersion::V1,
            "localhost",
            session,
            &client_params,
            &client_settings,
        )
        .expect("クライアント接続");

        // クライアントの Initial を書き出してサーバー接続の材料にする
        let mut send_buf = vec![0u8; PACKET_BUF_SIZE];
        let mut c2s = Vec::new();
        loop {
            match client.write_pkt(&mut send_buf, clock) {
                Ok((0, _, _)) => break,
                Ok((n, _, _)) => c2s.push(send_buf[..n].to_vec()),
                Err(err) => panic!("クライアントの write_pkt が失敗した: {err}"),
            }
        }
        assert!(!c2s.is_empty(), "クライアントが Initial を書き出せること");

        let info = decode_packet_version(&c2s[0]).expect("Initial を解析できること");
        let (client_initial_dcid, client_scid) = (info.dcid, info.scid);

        let server_scid = ConnectionId::random(16).expect("サーバーの SCID");
        let server_session = server_tls.create_session().expect("TLS セッション");
        let server_params = server_params.with_original_dcid(&client_initial_dcid);
        let server = Connection::server_new(
            &client_scid,
            &server_scid,
            server_addr,
            client_addr,
            QuicVersion::V1,
            server_session,
            &server_params,
            &server_settings,
        )
        .expect("サーバー接続");

        let mut harness = Self {
            client,
            server,
            client_path: PathInfo {
                local: client_addr,
                remote: server_addr,
            },
            server_path: PathInfo {
                local: server_addr,
                remote: client_addr,
            },
            clock,
            c2s,
            s2c: Vec::new(),
            send_buf,
            _client_tls: Arc::clone(&client_tls),
            _server_tls: Arc::clone(&server_tls),
        };

        // ハンドシェイクを完了させる
        let mut rounds = 0;
        loop {
            harness.deliver_c2s_to_server();
            harness.clock += 1_000;
            harness.flush_server();
            harness.deliver_s2c_to_client();
            harness.clock += 1_000;
            harness.flush_client();
            rounds += 1;
            if harness.client.is_handshake_completed() && harness.server.is_handshake_completed() {
                // 残りの ACK を配送しきる
                for _ in 0..8 {
                    harness.deliver_c2s_to_server();
                    harness.flush_server();
                    harness.deliver_s2c_to_client();
                    harness.flush_client();
                }
                break;
            }
            assert!(rounds < 200, "ハンドシェイクが完了しなかった");
        }

        assert!(
            harness.client.is_handshake_completed() && harness.server.is_handshake_completed(),
            "両側のハンドシェイクが完了していること"
        );

        // イベントを捨てる
        while harness.client.poll_event().is_some() {}
        while harness.server.poll_event().is_some() {}
        harness.c2s.clear();
        harness.s2c.clear();

        harness
    }

    /// クライアントの送信可能なパケットをすべて書き出す
    fn flush_client(&mut self) {
        loop {
            match self.client.write_pkt(&mut self.send_buf, self.clock) {
                Ok((0, _, _)) => break,
                Ok((n, _, _)) => {
                    let pkt = self.send_buf[..n].to_vec();
                    self.c2s.push(pkt);
                }
                Err(err) => panic!("クライアントの write_pkt が失敗した: {err}"),
            }
        }
    }

    /// サーバーの送信可能なパケットをすべて書き出す
    fn flush_server(&mut self) {
        loop {
            match self.server.write_pkt(&mut self.send_buf, self.clock) {
                Ok((0, _, _)) => break,
                Ok((n, _, _)) => {
                    let pkt = self.send_buf[..n].to_vec();
                    self.s2c.push(pkt);
                }
                Err(err) => panic!("サーバーの write_pkt が失敗した: {err}"),
            }
        }
    }

    /// クライアントからサーバーへの未配送パケットをすべて処理させる
    fn deliver_c2s_to_server(&mut self) {
        let packets = std::mem::take(&mut self.c2s);
        for pkt in packets {
            let path = self.server_path;
            self.server
                .read_pkt(&path, &PacketInfo::default(), &pkt, self.clock)
                .expect("サーバーがクライアントのパケットを処理できること");
        }
    }

    /// サーバーからクライアントへの未配送パケットをすべて処理させる
    fn deliver_s2c_to_client(&mut self) {
        let packets = std::mem::take(&mut self.s2c);
        for pkt in packets {
            let path = self.client_path;
            self.client
                .read_pkt(&path, &PacketInfo::default(), &pkt, self.clock)
                .expect("クライアントがサーバーのパケットを処理できること");
        }
    }

    /// サーバーに ACK を書かせてクライアントへ届ける
    fn round_trip_ack(&mut self) {
        self.flush_server();
        self.deliver_s2c_to_client();
    }

    /// タイマーを期限切れまで進めて handle_expiry を呼ぶ
    fn expire_and_handle(&mut self) {
        // 時間しきい値の損失検出を起こすため 1 秒進める
        let now = self.clock + 1_000_000_000;
        self.clock = now;
        let expiry = self.client.get_expiry();
        println!("handle_expiry: expiry={expiry} now={now}");
        assert!(expiry <= now, "タイマーが期限切れになっていること");
        self.client
            .handle_expiry(now)
            .expect("handle_expiry が成功すること");
    }

    /// クライアントが書き出したパケットをすべてサーバーへ配送する
    ///
    /// 損失検出後の再送パケットを配送するために使う。配送したパケット数を返す。
    fn flush_client_to_server(&mut self) -> usize {
        let mut count = 0;
        loop {
            match self.client.write_pkt(&mut self.send_buf, self.clock) {
                Ok((0, _, _)) => break,
                Ok((n, _, _)) => {
                    let pkt = self.send_buf[..n].to_vec();
                    self.server
                        .read_pkt(&self.server_path, &PacketInfo::default(), &pkt, self.clock)
                        .expect("サーバーがパケットを処理できること");
                    count += 1;
                }
                Err(err) => panic!("write_pkt が失敗した: {err}"),
            }
            self.clock += 100;
        }
        count
    }

    /// サーバーのイベントから受信したストリームデータを取り出す
    fn take_stream_data(&mut self, stream_id: i64, received: &mut Vec<u8>) {
        while let Some(event) = self.server.poll_event() {
            match event {
                ConnectionEvent::StreamData {
                    stream_id: sid,
                    data,
                    fin,
                } => {
                    assert_eq!(sid, stream_id, "ストリーム ID が一致すること");
                    assert!(!fin || data.is_empty(), "FIN はデータと同時に来る想定");
                    received.extend_from_slice(&data);
                }
                ConnectionEvent::StreamOpened { .. } => {}
                other => panic!("サーバーが想定外のイベントを受けた: {other:?}"),
            }
        }
    }
}

/// 位置に依存する非一様なバイト列を作る
fn make_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131) ^ (i >> 3)) as u8).collect()
}

/// クライアントから書き出すパケットを管理する送信側
struct Sender {
    stream_id: i64,
    /// `write_stream` が受理した累計バイト数
    written: u64,
    /// 書き出したがサーバーへ配送していないパケット
    pending: VecDeque<StreamPacket>,
    /// ACK された連続オフセット (ストリーム先頭から)
    acked: u64,
    /// クライアントが書き出した全パケット数
    packet_count: usize,
}

impl Sender {
    fn new(stream_id: i64) -> Self {
        Self {
            stream_id,
            written: 0,
            pending: VecDeque::new(),
            acked: 0,
            packet_count: 0,
        }
    }

    /// 輻輳ウィンドウが埋まるまで書き出す
    ///
    /// 最初の呼び出しでは残りデータ全体を渡して `InFlightStreamData` の
    /// `Vec` の容量を確保させる (再確保経路をこのテストから排除するため)。
    fn write_until_blocked(
        &mut self,
        harness: &mut Harness,
        data: &[u8],
        first_slice: Option<usize>,
    ) {
        loop {
            let offset = self.written as usize;
            if offset >= data.len() {
                return;
            }
            // 最初の呼び出しだけ大きなスライスを渡せるようにする。
            // 残りを渡すと `InFlightStreamData` の Vec の容量がその大きさで
            // 確保されるため、以降の追記で再確保が起きなくなる。
            let len = match first_slice {
                Some(len) if offset == 0 => len,
                _ => WRITE_CHUNK.min(data.len() - offset),
            };
            let chunk = &data[offset..offset + len];
            let (n, datalen, _, _) = harness
                .client
                .write_stream(
                    &mut harness.send_buf,
                    self.stream_id,
                    chunk,
                    false,
                    harness.clock,
                )
                .expect("write_stream が失敗した");
            harness.clock += 100;
            if n == 0 {
                // 輻輳ウィンドウが埋まった (データは受理されていない)
                return;
            }
            let d = datalen.unwrap_or(0);
            assert!(
                d <= len,
                "受理されたデータ量が渡した量を超えないこと: {d} > {len}"
            );
            let bytes = harness.send_buf[..n].to_vec();
            self.pending.push_back(StreamPacket {
                bytes,
                offset: self.written,
                datalen: d,
            });
            self.packet_count += 1;
            self.written += d as u64;
        }
    }

    /// `pending` の先頭から、終端が `limit` を超えないパケットだけ配送する
    fn deliver_below(&mut self, harness: &mut Harness, limit: u64) {
        loop {
            let Some(pkt) = self.pending.front() else {
                return;
            };
            // STREAM データを持たないパケットはそのまま配送する
            if pkt.datalen > 0 && pkt.end() >= limit {
                return;
            }
            let pkt = self.pending.pop_front().expect("先頭があること");
            harness
                .server
                .read_pkt(
                    &harness.server_path,
                    &PacketInfo::default(),
                    &pkt.bytes,
                    harness.clock,
                )
                .expect("サーバーがパケットを処理できること");
            if pkt.datalen > 0 {
                self.acked = pkt.end();
            }
        }
    }

    /// `pending` の先頭から `count` 個のパケットを配送する
    fn deliver_n(&mut self, harness: &mut Harness, count: usize) {
        for _ in 0..count {
            if self.deliver_front(harness).is_none() {
                break;
            }
        }
    }

    /// 先頭のパケットを 1 つだけ配送して返す
    fn deliver_front(&mut self, harness: &mut Harness) -> Option<StreamPacket> {
        let pkt = self.pending.pop_front()?;
        harness
            .server
            .read_pkt(
                &harness.server_path,
                &PacketInfo::default(),
                &pkt.bytes,
                harness.clock,
            )
            .expect("サーバーがパケットを処理できること");
        if pkt.datalen > 0 {
            self.acked = pkt.end();
        }
        Some(pkt)
    }
}

/// 64 KiB 超が ACK されたあとに損失が起きても、再送データが破損しないこと
///
/// ACK が 64 KiB を超えると、以前の実装は `InFlightStreamData::ack_until` で
/// `Vec::drain(..start)` を行い、未 ACK のバイト列をメモリ上で移動していた。
/// ngtcp2 は再送のためにアプリが渡したバッファへのポインタを保持しているため、
/// 移動後に損失 / PTO で再送すると移動前のアドレスから別のデータを読んでいた
/// (silent data corruption)。修正後は未 ACK のバイト列を移動しないため、
/// 再送データが元のバイト列と一致する。
///
/// このテストは修正前の実装では失敗していた (再送データが drain 量だけ
/// 後ろにずれた内容になっていた)。
#[test]
fn test_drain_path_retransmission_keeps_stream_data_intact() {
    let cert = TestCert::generate("drain");
    let mut harness = Harness::new(&cert);

    let stream_id = harness
        .client
        .open_bidi_stream()
        .expect("双方向ストリームを開けること");
    println!("ストリーム ID: {stream_id}");

    // 320 KiB の非一様データ
    let data = make_data(320 * 1024);
    println!("送信データ長: {} バイト", data.len());

    let mut sender = Sender::new(stream_id);
    let mut received: Vec<u8> = Vec::new();

    // スロースタートで cwnd を 64 KiB 以上まで育てながら、
    // ACK の終端が 64 KiB しきい値に近づくまで小刻みに配送する
    for round in 0..200 {
        // round 0 だけデータ全体を渡して Vec の容量を確保させる
        // (以降の追記で再確保が起きないようにするため)
        let first_slice = (round == 0).then_some(data.len());
        sender.write_until_blocked(&mut harness, &data, first_slice);
        sender.deliver_below(&mut harness, COMPACT_THRESHOLD);
        harness.round_trip_ack();

        // 受信済みデータを回収する
        harness.take_stream_data(stream_id, &mut received);

        if round == 0 || round % 20 == 0 {
            println!(
                "round={round} written={} acked={} pending={} received={}",
                sender.written,
                sender.acked,
                sender.pending.len(),
                received.len()
            );
        }

        // 交差判定: 先頭パケットの終端がしきい値以上で、かつ
        // 書き出し済みデータが drain 後の 2 倍オフセットより十分大きい
        if let Some(pkt) = sender.pending.front()
            && pkt.datalen > 0
            && pkt.end() >= COMPACT_THRESHOLD
        {
            let acked_after = pkt.end();
            let margin = sender.written as i128 - 2 * acked_after as i128;
            println!(
                "交差候補: 次のパケット offset={} datalen={} acked_after={} written={} margin={margin}",
                pkt.offset, pkt.datalen, acked_after, sender.written
            );
            if margin > 4096 {
                // この 1 パケットを配送すると ACK がしきい値を超える
                let delivered = sender
                    .deliver_front(&mut harness)
                    .expect("交差パケットがあること");
                harness.round_trip_ack();
                harness.take_stream_data(stream_id, &mut received);
                println!(
                    "64 KiB 超の ACK: 配送パケット offset={} datalen={} acked={} written={}",
                    delivered.offset, delivered.datalen, sender.acked, sender.written
                );
                assert!(
                    sender.acked >= COMPACT_THRESHOLD,
                    "ACK 済みオフセットがしきい値以上であること"
                );
                break;
            }
        }
    }

    let drain_start = sender.acked;
    let written_at_drain = sender.written;
    println!(
        "損失発生前: acked(start)={drain_start} written={written_at_drain} pending={} received={}",
        sender.pending.len(),
        received.len()
    );
    assert!(
        drain_start >= COMPACT_THRESHOLD,
        "ACK 済みオフセットがしきい値以上であること: {drain_start}"
    );
    assert!(
        written_at_drain > 2 * drain_start,
        "未 ACK のデータが十分残っていること: written={written_at_drain}, 2*start={}",
        2 * drain_start
    );

    // 時間を進めて損失検出を起こし、落としたパケットを再送させる
    harness.expire_and_handle();

    // 再送パケットを書き出してサーバーへ配送する
    let retransmitted = harness.flush_client_to_server();
    harness.take_stream_data(stream_id, &mut received);
    println!(
        "再送パケット数: {retransmitted}, 受信済み: {} バイト",
        received.len()
    );
    assert!(retransmitted > 0, "損失検出後に再送が起きていること");

    // 受信データをオフセット単位で比較する。受信はストリームオフセット順に
    // 届くため、受信済みの範囲は元データの先頭と一致するはずである
    let mismatch = received
        .iter()
        .zip(data.iter())
        .position(|(actual, expected)| actual != expected);
    assert!(
        mismatch.is_none(),
        "再送データが元のバイト列と一致すること: 最初の不一致={mismatch:?}, 受信={} バイト",
        received.len()
    );
    println!(
        "再送データの検証成功: 受信 {} バイトは元データの先頭と一致",
        received.len()
    );
}

/// 追記で領域が差し替わったあとに損失が起きても、再送データが破損しないこと
///
/// 以前の実装は `append` の `Vec::extend_from_slice` が容量超過で再確保し、
/// ngtcp2 が保持していた旧領域を解放していた (use-after-free)。修正後は
/// 旧領域を ACK されるまで退避するため、再送しても元のバイト列が届く。
#[test]
fn test_realloc_path_retransmission_keeps_stream_data_intact() {
    let cert = TestCert::generate("realloc");
    let mut harness = Harness::new(&cert);

    let stream_id = harness
        .client
        .open_bidi_stream()
        .expect("双方向ストリームを開けること");
    let data = make_data(320 * 1024);
    println!(
        "ストリーム ID: {stream_id}, 送信データ長: {} バイト",
        data.len()
    );

    let mut sender = Sender::new(stream_id);
    let mut received: Vec<u8> = Vec::new();

    // 最初の 1 回だけ 80 KiB を渡して Vec の容量を 80 KiB で確保させる。
    // ngtcp2 は 1 パケットに約 64 KiB まで載せられるため、パケット 0 は
    // 65,487 バイト前後を運ぶ。その後の追記で Vec の領域が差し替わる
    sender.write_until_blocked(&mut harness, &data, Some(80 * 1024));
    println!(
        "書き込み完了: written={} packets={}",
        sender.written, sender.packet_count
    );
    assert!(
        sender.written > 163_840,
        "163,840 バイト (64 KiB 超) のバッファを差し替える追記が起きていること: written={}",
        sender.written
    );

    // パケット 0 だけを配送して ACK させる。ACK 済みはしきい値 64 KiB を
    // わずかに下回り、以前の実装の drain は起きない条件にする
    sender.deliver_n(&mut harness, 1);
    harness.round_trip_ack();
    harness.take_stream_data(stream_id, &mut received);
    println!(
        "パケット 0 だけ ACK: received={} acked={}",
        received.len(),
        sender.acked
    );
    assert!(
        sender.acked < COMPACT_THRESHOLD,
        "drain しきい値には到達していないこと: acked={}",
        sender.acked
    );

    // 時間を進めて損失検出を起こし、旧領域を参照していたパケットを再送させる
    harness.expire_and_handle();
    let retransmitted = harness.flush_client_to_server();
    harness.take_stream_data(stream_id, &mut received);
    println!(
        "再送パケット数: {retransmitted}, 受信済み: {} バイト",
        received.len()
    );
    assert!(retransmitted > 0, "損失検出後に再送が起きていること");

    let mismatch = received
        .iter()
        .zip(data.iter())
        .position(|(actual, expected)| actual != expected);
    assert!(
        mismatch.is_none(),
        "再送データが元のバイト列と一致すること: 最初の不一致={mismatch:?}, 受信={} バイト",
        received.len()
    );
}
