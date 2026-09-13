//! ngtcp2 FFI バインディング
//!
//! このクレートは ngtcp2 C ライブラリへの低レベル FFI バインディングを提供する。
//!
//! ngtcp2 のソースコードは `build.rs` が `Cargo.toml` の
//! `[package.metadata.external-dependencies.ngtcp2]` が指すブランチ
//! (`reliable-stream-reset`) を取得して CMake でビルドする。
//! `bindings.rs` は同じブランチから生成したものを同梱している。

// bindgen が生成したコードは Rust の命名規則に従わないため、該当する lint を抑制する。
// C の構造体・定数名をそのまま維持しないと、どの FFI 項目がどのヘッダー由来か
// 追えなくなるため、リネームはしない。
//
// 抑制する lint は実際に発火するものだけを列挙する。`#[expect]` は発火しなかった
// ときに unfulfilled_lint_expectations 警告になるため、過剰に指定できない。
// bindgen のバージョンや ngtcp2 の更新で発火する lint が変わったらここを見直すこと。
#![expect(non_upper_case_globals, non_camel_case_types)]

include!("bindings.rs");

// aws-lc-sys を再公開する。
//
// TLS バックエンドの生ポインタ (SSL / SSL_CTX) は ngtcp2 の C API 越しに
// やり取りするため、sys クレートと利用側で同一の aws-lc を指す必要がある。
// 別々に aws-lc-sys へ依存すると、バージョン解決の結果によっては
// 同一プロセスに 2 つの aws-lc がリンクされてシンボルが衝突する。
// 再公開を唯一の経路にすることでこれを構造的に防ぐ。
pub use aws_lc_sys;

#[cfg(test)]
mod tests {
    use super::*;

    /// ngtcp2 のバージョン文字列がビルドしたタグと一致すること
    #[test]
    fn test_ngtcp2_version() {
        // SAFETY: ngtcp2_version は引数の age に対して有効な静的領域を返す
        let info = unsafe { ngtcp2_version(0) };
        assert!(!info.is_null(), "ngtcp2_info が null であってはならない");

        // SAFETY: info は ngtcp2_version が返した有効なポインタ
        let version_str = unsafe { (*info).version_str };
        assert!(
            !version_str.is_null(),
            "version_str が null であってはならない"
        );

        // SAFETY: version_str は ngtcp2 が管理する NUL 終端文字列
        let version = unsafe { std::ffi::CStr::from_ptr(version_str) }
            .to_str()
            .expect("バージョン文字列は UTF-8 であるべき");

        // ngtcp2 のリポジトリは可動ブランチ `reliable-stream-reset` を取得するため
        // 上流が進むと値が変わる。bindings.rs と実際にリンクされたライブラリの
        // バージョンが一致していることを確認する (食い違うと構造体レイアウトが
        // ずれて未定義動作になる)。
        //
        // NGTCP2_VERSION は NUL 終端を含むバイト列。
        assert_eq!(
            version.as_bytes(),
            NGTCP2_VERSION
                .strip_suffix(&[0u8])
                .unwrap_or(NGTCP2_VERSION),
            "bindings.rs とビルドした ngtcp2 のバージョンが一致すること"
        );
    }

    /// callsbacks 構造体のバージョン定数が公開されていること
    ///
    /// V6 で `extend_max_data` コールバックが追加された。
    #[test]
    fn test_callbacks_version() {
        assert_eq!(
            NGTCP2_CALLBACKS_VERSION, 6,
            "ngtcp2 1.26.0 の callbacks バージョン"
        );
    }

    /// settings のバージョン定数が公開されていること
    #[test]
    fn test_settings_version() {
        assert_eq!(
            NGTCP2_SETTINGS_VERSION, 4,
            "ngtcp2 1.25.0 の settings バージョン"
        );
    }

    /// settings のデフォルト値で構造体が初期化されること
    ///
    /// ngtcp2 1.25.0 の `ngtcp2_settings_default_versioned` は `()` を返す
    /// (ngtcp2 1.25.90 で `c_int` を返すシグネチャに変わっている)。
    /// ここでは呼び出しが panic せず、既定値が書き込まれることを確認する。
    #[test]
    fn test_settings_default_versioned() {
        let mut settings: ngtcp2_settings =
            // SAFETY: ngtcp2_settings は全てのビットパターンが有効な POD
            unsafe { std::mem::zeroed() };

        // SAFETY: settings は書き込み可能な有効な領域
        unsafe {
            ngtcp2_settings_default_versioned(NGTCP2_SETTINGS_VERSION as i32, &mut settings);
        }

        // 既定値が書き込まれたことを確認する (全て 0 のままなら失敗)
        //
        // max_tx_udp_payload_size の既定値 1452 は ngtcp2 が
        // NGTCP2_MAX_UDP_PAYLOAD_SIZE (1200) ではなく初回の PMTU 推定に使う値。
        // NGTCP2_MAX_TX_UDP_PAYLOAD_SIZE (65527) は上限であり既定値ではない。
        assert_eq!(
            settings.max_tx_udp_payload_size, 1452,
            "max_tx_udp_payload_size に既定値が入ること"
        );
        assert_ne!(
            settings.initial_rtt, 0,
            "initial_rtt に既定値が入ること (0 は既定値ではない)"
        );
    }

    /// transport params のデフォルト値で構造体が初期化されること
    #[test]
    fn test_transport_params_default_versioned() {
        let mut params: ngtcp2_transport_params =
            // SAFETY: ngtcp2_transport_params は全てのビットパターンが有効な POD
            unsafe { std::mem::zeroed() };

        // SAFETY: params は書き込み可能な有効な領域
        unsafe {
            ngtcp2_transport_params_default_versioned(
                NGTCP2_TRANSPORT_PARAMS_VERSION as i32,
                &mut params,
            );
        }

        assert_eq!(
            params.max_udp_payload_size, NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE as u64,
            "max_udp_payload_size に既定値が入ること"
        );
        assert_eq!(
            params.ack_delay_exponent, NGTCP2_DEFAULT_ACK_DELAY_EXPONENT as u64,
            "ack_delay_exponent に既定値が入ること"
        );
        assert_eq!(
            params.active_connection_id_limit, NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT as u64,
            "active_connection_id_limit に既定値が入ること"
        );
    }

    /// エラーコードを文字列に変換できること
    #[test]
    fn test_ngtcp2_strerror() {
        // SAFETY: ngtcp2_strerror は静的領域へのポインタを返す
        let s = unsafe { ngtcp2_strerror(NGTCP2_ERR_INVALID_ARGUMENT) };
        assert!(!s.is_null(), "ngtcp2_strerror が null であってはならない");

        // SAFETY: s は ngtcp2 が管理する NUL 終端文字列
        let msg = unsafe { std::ffi::CStr::from_ptr(s) }
            .to_str()
            .expect("エラーメッセージは UTF-8 であるべき");
        assert!(!msg.is_empty(), "エラーメッセージが空であってはならない");
    }

    /// ngtcp2 のエラーコードから QUIC トランスポートエラーコードを導出できること
    #[test]
    fn test_err_infer_quic_transport_error_code() {
        // SAFETY: ngtcp2_err_infer_quic_transport_error_code は引数のみに依存する純粋な変換
        let transport_code =
            unsafe { ngtcp2_err_infer_quic_transport_error_code(NGTCP2_ERR_PROTO) };
        assert_eq!(
            transport_code, NGTCP2_PROTOCOL_VIOLATION as u64,
            "NGTCP2_ERR_PROTO は PROTOCOL_VIOLATION に対応する"
        );
    }

    /// aws-lc-sys が再公開されていること
    #[test]
    fn test_aws_lc_sys_reexport() {
        // TLS バックエンドの生型が参照できることを確認する
        let _: *mut aws_lc_sys::SSL_CTX = std::ptr::null_mut();
    }
}
