//! ngtcp2 本体を用意するビルドスクリプト
//!
//! 既定では GitHub Releases から prebuilt の静的ライブラリをダウンロードする。
//! `source-build` feature を有効にすると ngtcp2 をソースからビルドする。
//!
//! ビルド元 (git URL とコミット) は Cargo.toml の
//! `[package.metadata.external-dependencies.ngtcp2]` から読む。
//! バージョンを上げるときは Cargo.toml と bindings.rs の両方を更新すること。

use std::path::{Path, PathBuf};
use std::process::Command;

/// 依存ライブラリの名前 (prebuilt アーカイブの名前にも使う)
const LIB_NAME: &str = "ngtcp2";

/// prebuilt アーカイブに含まれる静的ライブラリ
const STATIC_LIBS: [&str; 2] = ["ngtcp2", "ngtcp2_crypto_boringssl"];

/// aws-lc-sys の links 名を環境変数から自動検出する
///
/// Cargo は依存クレートの links 属性に基づいて `DEP_{LINKS}_INCLUDE` を設定するため、
/// aws-lc-sys のバージョンが変わっても自動で追従できる。
fn detect_aws_lc_links_name() -> String {
    for (key, _) in std::env::vars() {
        if key.starts_with("DEP_AWS_LC_") && key.ends_with("_INCLUDE") {
            // "DEP_AWS_LC_0_43_0_INCLUDE" → "aws_lc_0_43_0"
            let middle = key
                .strip_prefix("DEP_")
                .expect("build script must succeed")
                .strip_suffix("_INCLUDE")
                .expect("build script must succeed");
            return middle.to_lowercase();
        }
    }
    panic!("DEP_AWS_LC_*_INCLUDE not found - aws-lc-sys dependency required");
}

/// aws-lc のインクルードディレクトリを取得する
fn aws_lc_include_dir() -> String {
    let links = detect_aws_lc_links_name();
    let include_env = format!("DEP_{}_INCLUDE", links.to_uppercase());
    std::env::var(&include_env)
        .unwrap_or_else(|_| panic!("{include_env} not set - aws-lc-sys dependency required"))
}

/// Cargo.toml から外部依存関係のメタデータを読み取る
fn read_external_dependency(name: &str) -> shiguredo_toml::Table {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("build script must succeed"));
    let cargo_toml = std::fs::read_to_string(manifest_dir.join("Cargo.toml"))
        .expect("Failed to read Cargo.toml");
    // Cargo.toml は TOML v1.1.0 として読む。tombi は複数行のインラインテーブルを
    // 出力するが、v1.0.0 ではこれが許されないため
    // (shiguredo_toml の from_str は v1.0.0 固定)
    let parsed =
        shiguredo_toml::from_str_with_version(&cargo_toml, shiguredo_toml::TomlVersion::V1_1)
            .expect("Failed to parse Cargo.toml");

    parsed
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("external-dependencies"))
        .and_then(|e| e.get(name))
        .and_then(|d| d.as_table())
        .cloned()
        .unwrap_or_else(|| panic!("Missing [package.metadata.external-dependencies.{name}]"))
}

/// ngtcp2 のソースツリーを取得する
///
/// 既にクローン済みの場合は fetch してからタグにチェックアウトする。
/// fetch に失敗した場合は既存のチェックアウトで続行する (オフラインビルドを壊さないため)。
/// 戻り値は ngtcp2 のソースディレクトリ。
fn fetch_ngtcp2(out_dir: &Path) -> PathBuf {
    let dep = read_external_dependency("ngtcp2");
    let git_url = dep
        .get("git")
        .and_then(|v| v.as_str())
        .expect("Missing 'git' field in ngtcp2 dependency");
    let branch = dep.get("branch").and_then(|v| v.as_str());
    let version = dep.get("version").and_then(|v| v.as_str());
    let commit = dep.get("rev").and_then(|v| v.as_str());

    // 3 つを同時に指定するとどれを使うか曖昧になるため、ちょうど 1 つに限る
    let specified = [version.is_some(), branch.is_some(), commit.is_some()]
        .into_iter()
        .filter(|specified| *specified)
        .count();
    if specified != 1 {
        panic!("ngtcp2 dependency requires exactly one of 'version', 'branch' or 'rev'");
    }

    let ngtcp2_dir = out_dir.join("ngtcp2");

    if ngtcp2_dir.exists() {
        // fetch に失敗しても既存のチェックアウトで続行する
        let status = Command::new("git")
            .current_dir(&ngtcp2_dir)
            .args(["fetch", "origin", "--tags"])
            .status();
        if !matches!(status, Ok(s) if s.success()) {
            println!("cargo:warning=Failed to fetch ngtcp2; using existing checkout");
        }
    } else {
        let status = Command::new("git")
            .args([
                "clone",
                git_url,
                ngtcp2_dir.to_str().expect("build script must succeed"),
            ])
            .status()
            .expect("Failed to execute git clone");
        if !status.success() {
            panic!("Failed to clone ngtcp2 from {git_url}");
        }
    }

    // タグ (version) は不変であるため最も再現性が高い。次にコミット (rev)、
    // 最後に可動ブランチ (branch) の順に再現性が下がる
    let rev = match (version, commit, branch) {
        (Some(ver), _, _) => format!("v{ver}"),
        (_, Some(commit), _) => commit.to_string(),
        (_, _, Some(branch_name)) => branch_name.to_string(),
        (None, None, None) => unreachable!("checked above"),
    };

    let mut checked_out = checkout(&ngtcp2_dir, &rev);
    if !checked_out && commit.is_some() {
        // 分岐が force-push されて clone にコミットが含まれない場合、GitHub は
        // 到達可能なコミットなら直接取得できる。到達できなければ下で panic する
        let _ = Command::new("git")
            .current_dir(&ngtcp2_dir)
            .args(["fetch", "origin", &rev])
            .status();
        checked_out = checkout(&ngtcp2_dir, &rev);
    }

    if !checked_out {
        panic!("Failed to checkout {rev} in ngtcp2");
    }

    ngtcp2_dir
}

/// ngtcp2 のソースを指定したリビジョンへ切り替える
///
/// 切り替えに成功したら true を返す。
fn checkout(ngtcp2_dir: &Path, rev: &str) -> bool {
    Command::new("git")
        .current_dir(ngtcp2_dir)
        .args(["checkout", "--force", rev])
        .status()
        .is_ok_and(|status| status.success())
}

fn main() {
    // Cargo.toml か build.rs が更新されたら再ビルドする
    println!("cargo::rerun-if-changed=Cargo.toml");
    println!("cargo::rerun-if-changed=src/wrapper.h");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=CARGO_FEATURE_SOURCE_BUILD");
    println!("cargo::rerun-if-env-changed=NGTCP2_TARGET");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("build script must succeed"));

    // docs.rs では外部ライブラリを用意しない。
    //
    // bindings.rs は同梱済みのため、リンクしなくてもドキュメントは生成できる。
    // See also: https://docs.rs/about/builds
    if std::env::var("DOCS_RS").is_ok() {
        return;
    }

    let (lib_dir, include_dir) = if should_use_prebuilt() {
        download_prebuilt(&out_dir)
    } else {
        build_from_source(&out_dir)
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    for lib in STATIC_LIBS {
        println!("cargo:rustc-link-lib=static={lib}");
    }

    // 依存クレートに情報を渡す (DEP_NGTCP2_INCLUDE になる)
    println!("cargo:include={}", include_dir.display());
}

/// prebuilt を使うかどうかを返す
///
/// `source-build` feature が有効な場合と、`bindings.rs` の再生成 (`overwrite`) を
/// 行う場合はソースからビルドする。
fn should_use_prebuilt() -> bool {
    !cfg!(any(feature = "source-build", feature = "overwrite"))
}

/// prebuilt の静的ライブラリをダウンロードして展開する
///
/// 戻り値は (ライブラリディレクトリ, インクルードディレクトリ)。
/// アーカイブは `ngtcp2-<target>.tar.gz` で、`lib/` と `include/` を含む。
fn download_prebuilt(out_dir: &Path) -> (PathBuf, PathBuf) {
    let target = target_platform();
    let version = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is not set");
    let base_url = format!("https://github.com/shiguredo/ngtcp2-rs/releases/download/{version}");
    let archive_name = format!("{LIB_NAME}-{target}.tar.gz");
    let archive_url = format!("{base_url}/{archive_name}");
    let checksum_url = format!("{archive_url}.sha256");

    let archive_path = out_dir.join("prebuilt.tar.gz");
    let checksum_path = out_dir.join("prebuilt.tar.gz.sha256");
    let prebuilt_dir = out_dir.join("prebuilt");
    std::fs::create_dir_all(&prebuilt_dir).expect("Failed to create prebuilt directory");

    eprintln!("Downloading prebuilt ngtcp2: {archive_url}");
    download(&archive_url, &archive_path);
    download(&checksum_url, &checksum_path);
    verify_sha256(&archive_path, &checksum_path);

    let status = Command::new("tar")
        .arg("xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&prebuilt_dir)
        .status()
        .expect("Failed to execute tar. Ensure tar is installed");
    if !status.success() {
        panic!("Failed to extract {archive_url}");
    }

    let lib_dir = prebuilt_dir.join("lib");
    let include_dir = prebuilt_dir.join("include");

    // 壊れたアーカイブを早期に検出する
    for lib in STATIC_LIBS {
        let path = lib_dir.join(format!("lib{lib}.a"));
        if !path.exists() {
            panic!(
                "{} is missing in {archive_url}. \
                 Build ngtcp2 from source with `--features source-build` instead",
                path.display()
            );
        }
    }

    (lib_dir, include_dir)
}

/// curl でファイルをダウンロードする
fn download(url: &str, dest: &Path) {
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .expect("Failed to execute curl. Ensure curl is installed");
    if !status.success() {
        panic!(
            "Failed to download {url}. \
             Build ngtcp2 from source with `--features source-build` instead"
        );
    }
}

/// SHA256 チェックサムを検証する
fn verify_sha256(file_path: &Path, checksum_path: &Path) {
    let expected = std::fs::read_to_string(checksum_path)
        .expect("Failed to read SHA256 checksum file")
        .split_whitespace()
        .next()
        .expect("SHA256 checksum file is empty")
        .to_lowercase();

    let actual = compute_sha256(file_path);
    if actual != expected {
        panic!("SHA256 checksum mismatch:\n  expected: {expected}\n  actual:   {actual}");
    }
    eprintln!("SHA256 checksum verified: {actual}");
}

/// ファイルの SHA256 ハッシュを計算する
///
/// 対応プラットフォームは macOS と Linux のみ (README 参照)。
fn compute_sha256(path: &Path) -> String {
    let output = if cfg!(target_os = "macos") {
        Command::new("shasum")
            .args(["-a", "256"])
            .arg(path)
            .output()
            .expect("Failed to execute shasum. Ensure shasum is installed")
    } else {
        Command::new("sha256sum")
            .arg(path)
            .output()
            .expect("Failed to execute sha256sum. Ensure coreutils is installed")
    };

    if !output.status.success() {
        panic!("Failed to compute SHA256 checksum of {}", path.display());
    }

    // 出力形式: <hash>  <filename>
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("Unexpected shasum/sha256sum output format")
        .to_lowercase()
}

/// prebuilt アーカイブのターゲット名を返す
///
/// 環境変数 `NGTCP2_TARGET` で上書きできる (未配布のプラットフォームを
/// 自前でビルドした場合など)。
fn target_platform() -> String {
    if let Ok(target) = std::env::var("NGTCP2_TARGET") {
        return target;
    }

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    match (target_os.as_str(), target_arch.as_str()) {
        ("linux", "x86_64") => format!("ubuntu-{}_x86_64", linux_version()),
        ("linux", "aarch64") => format!("ubuntu-{}_arm64", linux_version()),
        ("macos", "aarch64") => "macos_arm64".to_string(),
        _ => panic!(
            "prebuilt ngtcp2 is not available for os={target_os}, arch={target_arch}. \
             Build ngtcp2 from source with `--features source-build` instead"
        ),
    }
}

/// /etc/os-release から Ubuntu のバージョンを検出する
///
/// prebuilt は glibc の互換性のため Ubuntu のバージョンごとに配布する。
/// 配布していないバージョンではソースビルドを促す。
fn linux_version() -> String {
    let content = std::fs::read_to_string("/etc/os-release")
        .expect("Failed to read /etc/os-release. Build with `--features source-build` instead");
    for line in content.lines() {
        if let Some(version) = line.strip_prefix("VERSION_ID=") {
            let version = version.trim_matches('"');
            if matches!(version, "22.04" | "24.04" | "26.04") {
                return version.to_string();
            }
        }
    }
    panic!(
        "prebuilt ngtcp2 is not available for this Linux distribution. \
         Build ngtcp2 from source with `--features source-build` instead"
    );
}

/// ngtcp2 をソースからビルドする
///
/// 戻り値は (ライブラリディレクトリ, インクルードディレクトリ)。
fn build_from_source(out_dir: &Path) -> (PathBuf, PathBuf) {
    // ngtcp2 のソースを取得する
    let ngtcp2_dir = fetch_ngtcp2(out_dir);

    // aws-lc のインクルードディレクトリとライブラリディレクトリ
    //
    // aws-lc-sys は include パスの親ディレクトリを OUT_DIR とし、
    // ライブラリを {OUT_DIR}/build/artifacts/ に置く。
    let aws_lc_include = aws_lc_include_dir();
    let aws_lc_out_dir = PathBuf::from(&aws_lc_include)
        .parent()
        .expect("Failed to get parent directory of include path")
        .to_path_buf();
    let aws_lc_lib_dir = aws_lc_out_dir.join("build").join("artifacts");
    let aws_lc_links = detect_aws_lc_links_name();

    // Windows (MSVC) では .lib、それ以外では lib*.a
    let (ssl_lib, crypto_lib) = if cfg!(target_env = "msvc") {
        (
            aws_lc_lib_dir.join(format!("{}_ssl.lib", aws_lc_links)),
            aws_lc_lib_dir.join(format!("{}_crypto.lib", aws_lc_links)),
        )
    } else {
        (
            aws_lc_lib_dir.join(format!("lib{}_ssl.a", aws_lc_links)),
            aws_lc_lib_dir.join(format!("lib{}_crypto.a", aws_lc_links)),
        )
    };

    // Windows のバックスラッシュを CMake が無効なエスケープとして解釈するためスラッシュへ変換する
    let ssl_lib_str = ssl_lib
        .to_str()
        .expect("build script must succeed")
        .replace('\\', "/");
    let crypto_lib_str = crypto_lib
        .to_str()
        .expect("build script must succeed")
        .replace('\\', "/");
    let boringssl_libraries = format!("{ssl_lib_str};{crypto_lib_str}");

    // shiguredo_cmake がピン留めした cmake を CMAKE 環境変数に設定する。
    // これを呼ばないと cmake クレートが PATH 上の cmake を探してしまい、
    // 環境によってバージョンが変わって再現性が失われる。
    shiguredo_cmake::set_cmake_env();

    let mut ngtcp2_config = shiguredo_cmake::Config::new(&ngtcp2_dir);
    ngtcp2_config
        .define("ENABLE_STATIC_LIB", "ON")
        .define("ENABLE_SHARED_LIB", "OFF")
        .define("ENABLE_LIB_ONLY", "ON")
        .define("BUILD_TESTING", "OFF")
        .define("ENABLE_OPENSSL", "OFF")
        .define("ENABLE_BORINGSSL", "ON")
        .define("BORINGSSL_INCLUDE_DIR", &aws_lc_include)
        .define("BORINGSSL_LIBRARIES", &boringssl_libraries);

    let ngtcp2_dst = ngtcp2_config.build();

    // ライブラリディレクトリ (環境によっては lib64 になる)
    let lib_dir = if ngtcp2_dst.join("lib64").exists() {
        ngtcp2_dst.join("lib64")
    } else {
        ngtcp2_dst.join("lib")
    };

    // bindings.rs を再生成する (`overwrite` feature でのみコンパイルされる)
    #[cfg(feature = "overwrite")]
    overwrite_bindgen(out_dir);

    (lib_dir, ngtcp2_dst.join("include"))
}

/// bindings.rs を再生成する (`overwrite` feature でのみコンパイルされる)
#[cfg(feature = "overwrite")]
fn overwrite_bindgen(out_dir: &Path) {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("build script must succeed"));

    // ビルド後の include ディレクトリ (version.h が生成される場所)
    let ngtcp2_installed_include = out_dir.join("include");
    // ソースの include ディレクトリ (ngtcp2.h がある場所)
    let ngtcp2_source_include = out_dir.join("ngtcp2").join("lib").join("includes");
    // aws-lc のインクルードディレクトリ (openssl/ssl.h がある場所)
    let aws_lc_include = aws_lc_include_dir();

    let bindings = bindgen::Builder::default()
        .header(
            manifest_dir
                .join("src/wrapper.h")
                .to_str()
                .expect("build script must succeed"),
        )
        .clang_arg(format!("-I{}", ngtcp2_installed_include.display()))
        .clang_arg(format!("-I{}", ngtcp2_source_include.display()))
        .clang_arg(format!("-I{}", aws_lc_include))
        .allowlist_function("ngtcp2_.*")
        .allowlist_type("ngtcp2_.*")
        .allowlist_var("NGTCP2_.*")
        // ソケット型はシステムヘッダー由来でプラットフォームごとに定義が異なる。
        // bindings.rs を全プラットフォームで共用するため、生成後に libc の型へ
        // 置き換える (replace_platform_socket_types を参照)
        .raw_line("// ソケット型はプラットフォームごとに定義が異なるため、libc の型を使う")
        .raw_line("pub use libc::{in6_addr, in_addr, in_addr_t, in_port_t, sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, socklen_t};")
        .raw_line("// NGTCP2_AF_INET6 は <sys/socket.h> の AF_INET6 を指す")
        .raw_line("pub const NGTCP2_AF_INET6: u32 = libc::AF_INET6 as u32;")
        // 生成される値は生成環境の AF_INET6 になるため、libc を使う定義へ差し替える
        .blocklist_var("NGTCP2_AF_INET6")
        .generate()
        .expect("Failed to generate ngtcp2 bindings");

    let bindings = replace_platform_socket_types(&bindings.to_string());
    std::fs::write(manifest_dir.join("src").join("bindings.rs"), bindings)
        .expect("Failed to write ngtcp2 bindings");
}

/// 生成した bindings からプラットフォーム依存のソケット型を取り除く
///
/// ngtcp2 の構造体はソケット型を値で持つため、bindings.rs を全プラットフォームで
/// 共用するには各プラットフォームの正しい定義 (libc) を使う必要がある。bindgen に
/// blocklist を指定すると、それらの型を含む構造体でネイティブ union を生成できず、
/// Copy / Clone の導出も失われる。そのため通常どおり生成してから、システムヘッダー
/// 由来の型定義だけを取り除く。名前はファイル先頭の `pub use libc::{...}` で解決される。
#[cfg(feature = "overwrite")]
fn replace_platform_socket_types(bindings: &str) -> String {
    // システムヘッダーに定義されている型 (glibc と Darwin の内部名を含む)
    const TYPES: &[&str] = &[
        "sockaddr",
        "sockaddr_in",
        "sockaddr_in6",
        "in_addr",
        // in6_addr の入れ子の union は in6_addr の定義の直後に出力されるため、
        // 先に取り除く (後だと in6_addr のレイアウト検査が隣接しない)
        "in6_addr__bindgen_ty_1",
        "in6_addr",
        "__socklen_t",
        "__darwin_socklen_t",
        "__uint8_t",
        "__uint16_t",
        "__uint32_t",
        "socklen_t",
        "sa_family_t",
        "in_addr_t",
        "in_port_t",
    ];

    let mut bindings = bindings.to_string();
    for name in TYPES {
        bindings = remove_generated_item(&bindings, name);
    }
    bindings
}

/// bindgen が生成した 1 つの型定義を削除する
///
/// 構造体・共用体は、付随するレイアウト検査 (`const _: () = { ... };`) も削除する。
#[cfg(feature = "overwrite")]
fn remove_generated_item(bindings: &str, name: &str) -> String {
    for kind in ["struct", "union"] {
        let marker = format!("pub {kind} {name} {{");
        let Some(offset) = bindings.find(&marker) else {
            continue;
        };
        let Some(end) = brace_block_end(bindings, offset + marker.len() - 1) else {
            return bindings.to_string();
        };
        let start = attributes_start(bindings, offset);
        let end = layout_assertion_end(bindings, end).unwrap_or(end);
        let mut result = String::with_capacity(bindings.len());
        result.push_str(&bindings[..start]);
        result.push_str(&bindings[end..]);
        return result;
    }

    let marker = format!("pub type {name} =");
    if let Some(offset) = bindings.find(&marker) {
        if let Some(end) = statement_end(bindings, offset) {
            let start = attributes_start(bindings, offset);
            let mut result = String::with_capacity(bindings.len());
            result.push_str(&bindings[..start]);
            result.push_str(&bindings[end..]);
            return result;
        }
    }
    bindings.to_string()
}

/// 指定した位置の項目に付いている属性の先頭位置を返す
#[cfg(feature = "overwrite")]
fn attributes_start(bindings: &str, offset: usize) -> usize {
    let mut start = offset;
    while start > 0 {
        let previous_break = start - 1;
        let previous_start = bindings[..previous_break]
            .rfind('\n')
            .map_or(0, |position| position + 1);
        let line = bindings[previous_start..previous_break].trim();
        if line.starts_with("#[") {
            start = previous_start;
        } else {
            break;
        }
    }
    start
}

/// 波括弧の対応を取ってブロックの終端 (行末) を返す
///
/// 文字列リテラル内の波括弧は数えない。
#[cfg(feature = "overwrite")]
fn brace_block_end(bindings: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bindings.bytes().enumerate().skip(open) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(
                        bindings[index..]
                            .find('\n')
                            .map_or(bindings.len(), |position| index + position + 1),
                    );
                }
            }
            _ => {}
        }
    }
    None
}

/// セミコロンまでを含む文の終端 (行末) を返す
#[cfg(feature = "overwrite")]
fn statement_end(bindings: &str, offset: usize) -> Option<usize> {
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bindings.bytes().enumerate().skip(offset) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b';' => {
                return Some(
                    bindings[index..]
                        .find('\n')
                        .map_or(bindings.len(), |position| index + position + 1),
                );
            }
            _ => {}
        }
    }
    None
}

/// 型定義の直後にあるレイアウト検査ブロックの終端を返す
#[cfg(feature = "overwrite")]
fn layout_assertion_end(bindings: &str, offset: usize) -> Option<usize> {
    const ALLOW: &str = "#[allow(clippy::unnecessary_operation, clippy::identity_op)]";
    if !bindings[offset..].starts_with(ALLOW) {
        return None;
    }
    let const_offset = offset + ALLOW.len();
    let open = bindings[const_offset..].find('{')? + const_offset;
    brace_block_end(bindings, open)
}
