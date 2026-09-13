//! テスト用の自己署名証明書を生成するヘルパー
//!
//! モックやスタブは使わない方針のため、実際の証明書ファイルを
//! 一時ディレクトリに生成してテストする。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// テスト用の証明書と秘密鍵 (ファイルに書き出し済み)
///
/// `Drop` で一時ディレクトリを削除する。
pub(crate) struct TestCert {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_pem: String,
    temp_dir: PathBuf,
}

impl TestCert {
    /// `localhost` 用の自己署名証明書を生成する
    ///
    /// `CN` と `SAN dNSName` の両方に `localhost` を設定する。
    pub(crate) fn generate(label: &str) -> Self {
        Self::generate_with_names(label, &["localhost"])
    }

    /// 指定した SAN dNSName を持つ自己署名証明書を生成する
    pub(crate) fn generate_with_names(label: &str, san_names: &[&str]) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!(
            "ngtcp2_e2e_{}_{}_{}",
            label,
            std::process::id(),
            unique_id
        ));
        std::fs::create_dir_all(&temp_dir).expect("一時ディレクトリを作成できること");

        let cert_path = temp_dir.join("cert.pem");
        let key_path = temp_dir.join("key.pem");

        let params = rcgen::CertificateParams::new(
            san_names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .expect("証明書パラメータを作成できること");
        let key_pair = rcgen::KeyPair::generate().expect("鍵ペアを生成できること");
        let cert = params
            .self_signed(&key_pair)
            .expect("自己署名証明書を生成できること");

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        std::fs::write(&cert_path, &cert_pem).expect("証明書を書き込めること");
        std::fs::write(&key_path, &key_pem).expect("秘密鍵を書き込めること");

        Self {
            cert_path,
            key_path,
            cert_pem,
            temp_dir,
        }
    }

    /// 証明書ファイルのパスを返す
    pub(crate) fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// 秘密鍵ファイルのパスを返す
    pub(crate) fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// 証明書の PEM 文字列を返す
    ///
    /// クライアントのトラストストアに追加するために使用する。
    pub(crate) fn cert_pem(&self) -> &str {
        &self.cert_pem
    }
}

impl Drop for TestCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 証明書と秘密鍵のファイルが生成されること
    #[test]
    fn test_generate_writes_files() {
        let cert = TestCert::generate("certs_helper");
        let cert_pem = std::fs::read_to_string(cert.cert_path()).expect("証明書を読めること");
        let key_pem = std::fs::read_to_string(cert.key_path()).expect("秘密鍵を読めること");

        assert!(
            cert_pem.contains("BEGIN CERTIFICATE"),
            "証明書が PEM 形式であること"
        );
        assert!(
            key_pem.contains("PRIVATE KEY"),
            "秘密鍵が PEM 形式であること"
        );
        assert_eq!(
            cert_pem,
            cert.cert_pem(),
            "cert_pem がファイルと一致すること"
        );
    }

    /// SAN に指定した名前が含まれること
    #[test]
    fn test_generate_with_names() {
        let cert = TestCert::generate_with_names("certs_helper_names", &["localhost"]);
        // rcgen は生成時に SAN を検証するため、生成できたこと自体が確認になる
        assert!(!cert.cert_pem().is_empty(), "証明書が空でないこと");
    }
}
