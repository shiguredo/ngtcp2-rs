//! qlog の出力先の管理
//!
//! [`Settings::qlog`] を有効にした接続は、ngtcp2 が出力した qlog のデータ断片を
//! [`Connection::poll_qlog_data`] で取り出せる。このモジュールはそれをファイルへ
//! 書き出す。
//!
//! [`Settings::qlog`]: shiguredo_ngtcp2::Settings::qlog
//! [`Connection::poll_qlog_data`]: shiguredo_ngtcp2::Connection::poll_qlog_data

use std::fs::File;
use std::io::Write;
use std::path::Path;

use shiguredo_ngtcp2::{Connection, ConnectionId};

/// 接続 1 つ分の qlog の出力先
///
/// qlog を有効にしていない場合は何もしない。
pub(crate) struct QlogWriter {
    /// 出力先のファイル。無効な場合は `None`
    file: Option<File>,
}

impl QlogWriter {
    /// qlog を無効にした出力先を作る
    pub(crate) fn disabled() -> Self {
        Self { file: None }
    }

    /// 指定したディレクトリに `<名前>.sqlog` を作る
    ///
    /// ディレクトリが無い場合は作る。ファイルを開けない場合は qlog を無効に
    /// して接続自体は続ける (qlog は診断用のため、失敗で接続を止めない)。
    pub(crate) fn new(dir: &Path, name: &str) -> Self {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!(
                "[shiguredo_ngtcp2_tokio] failed to create the qlog directory {}: {e}",
                dir.display()
            );
            return Self::disabled();
        }

        let path = dir.join(format!("{name}.sqlog"));
        match File::create(&path) {
            Ok(file) => Self { file: Some(file) },
            Err(e) => {
                eprintln!(
                    "[shiguredo_ngtcp2_tokio] failed to create the qlog file {}: {e}",
                    path.display()
                );
                Self::disabled()
            }
        }
    }

    /// 接続が出力した qlog を書き出す
    pub(crate) fn write(&mut self, conn: &mut Connection) {
        let Some(file) = self.file.as_mut() else {
            return;
        };

        while let Some(data) = conn.poll_qlog_data() {
            if let Err(e) = file.write_all(&data) {
                eprintln!("[shiguredo_ngtcp2_tokio] failed to write qlog: {e}");
                self.file = None;
                return;
            }
        }
    }
}

/// コネクション ID をファイル名に使える 16 進表記にする
pub(crate) fn file_name(prefix: &str, cid: &ConnectionId) -> String {
    let mut name = String::with_capacity(prefix.len() + cid.len() * 2);
    name.push_str(prefix);
    for byte in cid.as_bytes() {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ファイル名が 16 進表記になること
    #[test]
    fn test_file_name() {
        let cid = ConnectionId::new(&[0x01, 0xab, 0xff]).expect("CID を作れること");
        assert_eq!(file_name("client-", &cid), "client-01abff", "ファイル名");
    }

    /// 無効な場合は何もしないこと
    #[test]
    fn test_qlog_writer_disabled() {
        let writer = QlogWriter::disabled();
        assert!(writer.file.is_none(), "ファイルを持たないこと");
    }
}
