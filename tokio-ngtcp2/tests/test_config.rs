//! 設定型の統合テスト
//!
//! `ClientConfig` / `ServerConfig` / `DatagramConfig` のビルダー API と既定値を
//! 検証する。

use std::time::Duration;

use shiguredo_ngtcp2::TransportParams;
use shiguredo_ngtcp2_tokio::{
    ClientConfig, CongestionAlgorithm, DatagramConfig, QuicVersion, ServerConfig, Settings,
};

/// `ClientConfig::new` の既定値がドキュメントどおりであること
#[test]
fn test_client_config_defaults() {
    let config = ClientConfig::new(&[b"hq-interop"]);

    assert_eq!(
        config.alpn_protocols,
        vec![b"hq-interop".to_vec()],
        "ALPN が設定されること"
    );
    assert!(config.verify_peer, "既定では証明書を検証すること");
    assert!(
        config.datagram.is_enabled(),
        "既定では DATAGRAM が有効であること"
    );
    assert_eq!(
        config.handshake_timeout,
        Duration::from_secs(10),
        "既定のハンドシェイクタイムアウト"
    );
    assert!(
        config.ca_cert_pem.is_empty(),
        "既定ではカスタム CA を登録しないこと"
    );
    assert_eq!(
        config.quic_version,
        QuicVersion::V1,
        "既定の QUIC バージョンは v1 であること"
    );
    assert_eq!(
        config.settings,
        Settings::new(0),
        "既定の接続設定は ngtcp2 の既定値であること"
    );
}

/// 複数の ALPN を指定できること
#[test]
fn test_client_config_multiple_alpn() {
    let config = ClientConfig::new(&[b"hq-interop", b"h3"]);
    assert_eq!(
        config.alpn_protocols,
        vec![b"hq-interop".to_vec(), b"h3".to_vec()],
        "指定した順に保持されること"
    );
}

/// `ClientConfig` のビルダーが自身を返し連結できること
#[test]
fn test_client_config_builder_chain() {
    let config = ClientConfig::new(&[b"hq-interop"])
        .with_verify_peer(false)
        .with_transport_params(TransportParams::new().with_max_streams_bidi(50))
        .with_datagram(DatagramConfig::disabled())
        .with_handshake_timeout(Duration::from_secs(3))
        .with_ca_cert_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
        .with_quic_version(QuicVersion::V2)
        .with_settings(custom_settings());

    assert!(!config.verify_peer, "verify_peer が反映されること");
    assert!(!config.datagram.is_enabled(), "datagram が反映されること");
    assert_eq!(
        config.handshake_timeout,
        Duration::from_secs(3),
        "handshake_timeout が反映されること"
    );
    assert_eq!(config.ca_cert_pem.len(), 1, "CA 証明書が追加されること");
    assert_eq!(
        config.quic_version,
        QuicVersion::V2,
        "quic_version が反映されること"
    );
    assert_eq!(
        config.settings,
        custom_settings(),
        "settings が反映されること"
    );
}

/// テスト用の接続設定
///
/// `initial_ts` は接続の作成時に上書きされるため 0 のままにしてよい。
fn custom_settings() -> Settings {
    let mut settings = Settings::new(0);
    settings.congestion_algorithm = CongestionAlgorithm::Bbr2;
    settings.max_tx_udp_payload_size = 1200;
    settings.initial_rtt = Duration::from_millis(50);
    settings.keep_alive_timeout = Some(Duration::from_secs(15));
    settings.no_pmtud = true;
    settings
}

/// カスタム CA を複数追加できること
#[test]
fn test_client_config_multiple_ca_certs() {
    let config = ClientConfig::new(&[b"hq-interop"])
        .with_ca_cert_pem("first")
        .with_ca_cert_pem("second".to_string());

    assert_eq!(
        config.ca_cert_pem,
        vec!["first".to_string(), "second".to_string()],
        "追加した順に保持されること"
    );
}

/// `ServerConfig::new` の既定値がドキュメントどおりであること
#[test]
fn test_server_config_defaults() {
    let config = ServerConfig::new(&[b"hq-interop"]);

    assert_eq!(
        config.alpn_protocols,
        vec![b"hq-interop".to_vec()],
        "ALPN が設定されること"
    );
    assert!(
        config.datagram.is_enabled(),
        "既定では DATAGRAM が有効であること"
    );
    assert_eq!(config.scid_len, 16, "既定の SCID 長");
    assert_eq!(
        config.quic_versions,
        vec![QuicVersion::V1, QuicVersion::V2],
        "既定では QUIC v1 と v2 をサポートすること"
    );
    assert_eq!(
        config.settings,
        Settings::new(0),
        "既定の接続設定は ngtcp2 の既定値であること"
    );
    assert!(
        !config.early_data,
        "既定では 0-RTT を受け入れないこと (リプレイ攻撃の対策はアプリケーションの責任)"
    );
}

/// `ServerConfig` のビルダーが自身を返し連結できること
#[test]
fn test_server_config_builder_chain() {
    let config = ServerConfig::new(&[b"hq-interop"])
        .with_transport_params(TransportParams::new().with_max_streams_uni(10))
        .with_datagram(DatagramConfig::disabled())
        .with_scid_len(8)
        .with_quic_versions(&[QuicVersion::V2])
        .with_early_data(true)
        .with_settings(custom_settings());

    assert!(!config.datagram.is_enabled(), "datagram が反映されること");
    assert_eq!(config.scid_len, 8, "scid_len が反映されること");
    assert_eq!(
        config.quic_versions,
        vec![QuicVersion::V2],
        "quic_versions が反映されること"
    );
    assert!(config.early_data, "early_data が反映されること");
    assert_eq!(
        config.settings,
        custom_settings(),
        "settings が反映されること"
    );
}

/// サポートする QUIC バージョンを空に設定できること
///
/// 空の一覧はどのクライアントとも接続できない設定ミスだが、ビルダーは
/// 値をそのまま保持し、`Server::bind` が拒否する。ビルダーが `Result` を
/// 返すと他の `with_*` と連結できなくなるため。
#[test]
fn test_server_config_allows_empty_quic_versions() {
    let config = ServerConfig::new(&[b"hq-interop"]).with_quic_versions(&[]);
    assert!(
        config.quic_versions.is_empty(),
        "空の一覧もそのまま保持されること"
    );
}

/// `DatagramConfig::default` と `disabled` の値
#[test]
fn test_datagram_config_values() {
    let config = DatagramConfig::default();
    assert_eq!(config.max_datagram_frame_size, 65535, "受信の上限");
    assert_eq!(config.max_tx_datagram_size, 1200, "送信の上限");
    assert!(config.is_enabled(), "既定では有効");

    let config = DatagramConfig::disabled();
    assert_eq!(config.max_datagram_frame_size, 0, "無効時の受信上限");
    assert_eq!(config.max_tx_datagram_size, 0, "無効時の送信上限");
    assert!(!config.is_enabled(), "無効時は false");
}

/// DATAGRAM のフィールドを直接構築できること
#[test]
fn test_datagram_config_custom() {
    let config = DatagramConfig {
        max_datagram_frame_size: 1000,
        max_tx_datagram_size: 500,
    };
    assert!(config.is_enabled(), "カスタム設定でも有効になること");

    // 片方だけ 0 の場合は無効とみなす
    let config = DatagramConfig {
        max_datagram_frame_size: 1000,
        max_tx_datagram_size: 0,
    };
    assert!(!config.is_enabled(), "送信上限が 0 なら無効");
}

/// `TransportParams` がコアから再公開されていること
#[test]
fn test_transport_params_reexport() {
    let params = TransportParams::new()
        .with_max_idle_timeout(Duration::from_secs(60))
        .with_initial_max_data(1024)
        .with_datagram(1200);

    // ビルダーが連結でき、ClientConfig / ServerConfig に渡せること
    let _ = ClientConfig::new(&[b"hq-interop"]).with_transport_params(params.clone());
    let _ = ServerConfig::new(&[b"hq-interop"]).with_transport_params(params);
}

/// コアの型が再公開されていること
///
/// 利用者が `shiguredo_ngtcp2` を直接依存しなくても使えることを確認する。
#[test]
fn test_core_types_reexported() {
    use shiguredo_ngtcp2_tokio::{
        ConnectionErrorKind, ConnectionId, Error, QuicVersion, SessionTicket, StreamDirection,
        StreamType,
    };

    let cid = ConnectionId::random(16).expect("CID が生成できること");
    assert_eq!(cid.len(), 16, "CID 長");
    assert_eq!(QuicVersion::default(), QuicVersion::V1, "既定のバージョン");
    assert_eq!(StreamType::from_stream_id(0), StreamType::Bidirectional);
    assert_eq!(
        StreamDirection::from_stream_id(0),
        StreamDirection::ClientInitiated
    );
    assert_eq!(
        Error::Internal("x".to_string()).classify_connection_error(),
        ConnectionErrorKind::Internal
    );

    // 0-RTT のセッション情報もコアから再公開されていること
    let ticket = SessionTicket::new(vec![1], vec![2]);
    assert_eq!(ticket.session(), &[1], "セッションのバイト列");
    assert_eq!(ticket.transport_params(), &[2], "トランスポートパラメータ");
}
