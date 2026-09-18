import argparse
import re
import subprocess
from datetime import date


# 3 クレートは常に同じバージョンで同時にリリースする
CRATE_MANIFESTS: list[str] = [
    "ngtcp2/Cargo.toml",
    "ngtcp2-sys/Cargo.toml",
    "tokio-ngtcp2/Cargo.toml",
]

# バージョンの基準にする Cargo.toml
#
# リリースワークフロー (release.yml) がタグと突き合わせるのは ngtcp2-sys の
# バージョンなので、これを基準にする。
VERSION_SOURCE_MANIFEST: str = "ngtcp2-sys/Cargo.toml"

# ワークスペースの依存でバージョンを固定している Cargo.toml
#
# `shiguredo_ngtcp2` と `shiguredo_ngtcp2_sys` を `= バージョン` で固定している
# ため、クレートのバージョンと合わせて更新する。
WORKSPACE_MANIFEST: str = "Cargo.toml"

# バージョンを更新したあとに lockfile を同期する workspace とクレート
#
# ルートと fuzz と interop は別々の workspace で lockfile も別にある。
# fuzz は shiguredo_ngtcp2_tokio に依存しないため、指定すると cargo update が
# エラーになる。
WORKSPACE_LOCKFILES: list[tuple[str, list[str]]] = [
    (
        "Cargo.toml",
        ["shiguredo_ngtcp2", "shiguredo_ngtcp2_sys", "shiguredo_ngtcp2_tokio"],
    ),
    ("fuzz/Cargo.toml", ["shiguredo_ngtcp2", "shiguredo_ngtcp2_sys"]),
    (
        "interop/Cargo.toml",
        ["shiguredo_ngtcp2", "shiguredo_ngtcp2_sys", "shiguredo_ngtcp2_tokio"],
    ),
]

# lockfile のパス
LOCKFILE_PATHS: list[str] = [
    "Cargo.lock",
    "fuzz/Cargo.lock",
    "interop/Cargo.lock",
]

# 正式リリースで更新する変更履歴
CHANGES_PATH: str = "CHANGES.md"

# バージョン更新のコミットに含めるファイル (lockfile は cargo update で更新される)
COMMIT_PATHS: list[str] = [*CRATE_MANIFESTS, WORKSPACE_MANIFEST, *LOCKFILE_PATHS]


# バージョン文字列を受け取り、次の canary バージョンを返す純粋関数。
def next_canary_version(version: str) -> str:
    """次の canary バージョンを返す。

    >>> next_canary_version("2026.1.0-canary.3")
    '2026.1.0-canary.4'
    >>> next_canary_version("2026.1.0-canary.99")
    '2026.1.0-canary.100'
    >>> next_canary_version("2026.0.0")
    '2026.1.0-canary.0'
    >>> next_canary_version("2026.1.0")
    '2026.2.0-canary.0'
    >>> next_canary_version("abc")
    Traceback (most recent call last):
        ...
    ValueError: Invalid version format: abc
    """
    # -canary.N が含まれる場合は N をインクリメントする
    canary_match = re.fullmatch(r"(\d+\.\d+\.\d+-canary\.)(\d+)", version)
    if canary_match:
        return f"{canary_match.group(1)}{int(canary_match.group(2)) + 1}"

    # -canary.X がない場合は次のリリース (RELEASE を 1 つ上げたもの) の canary にする
    plain_match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if plain_match:
        return f"{plain_match.group(1)}.{int(plain_match.group(2)) + 1}.0-canary.0"

    raise ValueError(f"Invalid version format: {version}")


# バージョン文字列を受け取り、正式リリースのバージョンを返す純粋関数。
def release_version(version: str) -> str:
    """canary バージョンから正式リリースのバージョンを返す。

    >>> release_version("2026.1.0-canary.3")
    '2026.1.0'
    >>> release_version("2026.1.0")
    Traceback (most recent call last):
        ...
    ValueError: Not a canary version: 2026.1.0
    """
    canary_match = re.fullmatch(r"(\d+\.\d+\.\d+)-canary\.\d+", version)
    if not canary_match:
        raise ValueError(f"Not a canary version: {version}")

    return canary_match.group(1)


# Cargo.toml 全体を [package] セクションと前後に分離する純粋関数。
def split_package_section(content: str) -> tuple[str, str, str]:
    """Cargo.toml 全体から [package] セクションと前後を分離する。

    >>> split_package_section(
    ...     '[package]\\nversion = "1.0.0"\\n\\n[dependencies]\\ntokio = { version = "1.53" }'
    ... )
    ('[package]\\nversion = "1.0.0"\\n', '', '\\n[dependencies]\\ntokio = { version = "1.53" }')
    """
    package_start = content.find("[package]")
    if package_start == -1:
        raise ValueError("[package] section not found in Cargo.toml")

    # 後続の [dependencies] などは package セクションに含めない
    # (`[package.metadata.*]` は `[package` で始まるため区切りにしない)
    next_section = re.search(r"\n\[(?!package)", content[package_start:])
    if next_section:
        package_end = package_start + next_section.start()
        return (
            content[package_start:package_end],
            content[:package_start],
            content[package_end:],
        )

    return content[package_start:], content[:package_start], ""


# Cargo.toml 全体から [package] セクションのバージョンを取り出す純粋関数。
def read_package_version(content: str) -> str:
    """Cargo.toml の `[package]` セクションのバージョンを返す。

    行頭アンカーで `version` キーに限定するため、`rust-version` の末尾
    `version` にはマッチしない。

    >>> read_package_version('[package]\\nname = "x"\\nversion = "2026.1.0-canary.0"')
    '2026.1.0-canary.0'
    >>> read_package_version('[package]\\nname = "x"')
    Traceback (most recent call last):
        ...
    ValueError: Version not found in [package] section of Cargo.toml
    """
    package_content, _, _ = split_package_section(content)
    version_match = re.search(
        r'(?m)^[ \t]*version\s*=\s*"([\d\.\w-]+)"', package_content
    )
    if not version_match:
        raise ValueError("Version not found in [package] section of Cargo.toml")

    return version_match.group(1)


# Cargo.toml 全体の [package] セクションのバージョンだけを置き換える純粋関数。
def replace_package_version(content: str, new_version: str) -> str:
    """`[package]` セクションのバージョンを置き換えた Cargo.toml を返す。

    >>> replace_package_version(
    ...     '[package]\\nname = "x"\\nversion = "2026.1.0-canary.0"', "2026.1.0-canary.1"
    ... )
    '[package]\\nname = "x"\\nversion = "2026.1.0-canary.1"'
    """
    package_content, before, after = split_package_section(content)
    version_match = re.search(
        r'(?m)^[ \t]*version\s*=\s*"([\d\.\w-]+)"', package_content
    )
    if not version_match:
        raise ValueError("Version not found in [package] section of Cargo.toml")

    # マッチした値の範囲だけを置き換え、行の書式は変えない
    value_start, value_end = version_match.span(1)
    updated_package = (
        package_content[:value_start] + new_version + package_content[value_end:]
    )

    return before + updated_package + after


# ルート Cargo.toml の = 固定の依存バージョンを置き換える純粋関数。
def replace_workspace_dependency_versions(
    content: str, current_version: str, new_version: str
) -> str:
    """`[workspace.dependencies]` の `= バージョン` を置き換えた Cargo.toml を返す。

    >>> replace_workspace_dependency_versions(
    ...     '[workspace.dependencies]\\nshiguredo_ngtcp2 = { path = "ngtcp2", version = "=2026.1.0-canary.0" }',
    ...     "2026.1.0-canary.0",
    ...     "2026.1.0-canary.1",
    ... )
    '[workspace.dependencies]\\nshiguredo_ngtcp2 = { path = "ngtcp2", version = "=2026.1.0-canary.1" }'
    """
    old_value = f'version = "={current_version}"'
    new_value = f'version = "={new_version}"'
    if old_value not in content:
        raise ValueError(
            f"{old_value} not found in [workspace.dependencies] of {WORKSPACE_MANIFEST}"
        )

    return content.replace(old_value, new_value)


# ファイルを読み込む
def read_file(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


# ファイルに書き込む
def write_file(file_path: str, content: str) -> None:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)


# 3 クレートの Cargo.toml のバージョンが揃っていることを確認して返す
def read_current_version() -> str:
    current_version: str = read_package_version(read_file(VERSION_SOURCE_MANIFEST))

    for manifest_path in CRATE_MANIFESTS:
        version: str = read_package_version(read_file(manifest_path))
        if version != current_version:
            raise SystemExit(
                f"{manifest_path} version {version} does not match "
                f"{VERSION_SOURCE_MANIFEST} version {current_version}"
            )

    return current_version


# 3 クレートとルートの workspace 依存のバージョンを new_version に更新する
def update_versions(current_version: str, new_version: str, dry_run: bool) -> None:
    for manifest_path in CRATE_MANIFESTS:
        content: str = read_file(manifest_path)
        updated: str = replace_package_version(content, new_version)
        if read_package_version(updated) != new_version:
            raise SystemExit(f"Failed to update version in {manifest_path}")

        if dry_run:
            print(f"Dry-run: Would update {manifest_path} to {new_version}")
        else:
            write_file(manifest_path, updated)
            print(f"{manifest_path} updated to {new_version}")

    workspace_content: str = read_file(WORKSPACE_MANIFEST)
    updated_workspace: str = replace_workspace_dependency_versions(
        workspace_content, current_version, new_version
    )
    if dry_run:
        print(
            f"Dry-run: Would update [workspace.dependencies] of "
            f"{WORKSPACE_MANIFEST} to {new_version}"
        )
    else:
        write_file(WORKSPACE_MANIFEST, updated_workspace)
        print(
            f"[workspace.dependencies] of {WORKSPACE_MANIFEST} updated to {new_version}"
        )


# CHANGES.md の develop セクションをリリース版に置き換える純粋関数。
def update_changes_content(content: str, new_version: str, release_date: str) -> str:
    """`## develop` セクションを `## バージョン` とリリース日に置き換える。

    >>> update_changes_content("## develop\\n", "2026.1.0", "2026-09-18")
    '## 2026.1.0\\n\\n**リリース日**: 2026-09-18\\n'
    >>> update_changes_content("## 2026.1.0\\n", "2026.1.0", "2026-09-18")
    Traceback (most recent call last):
        ...
    ValueError: ## develop section not found in CHANGES.md
    """
    updated, count = re.subn(
        r"## develop",
        f"## {new_version}\n\n**リリース日**: {release_date}",
        content,
        count=1,
    )
    if count == 0:
        raise ValueError("## develop section not found in CHANGES.md")

    return updated


# CHANGES.md の develop セクションをリリース版に更新する
def update_changes(new_version: str, dry_run: bool) -> None:
    content: str = read_file(CHANGES_PATH)
    updated: str = update_changes_content(
        content, new_version, date.today().isoformat()
    )

    if dry_run:
        print(f"Dry-run: Would update {CHANGES_PATH} to:")
        print(updated)
    else:
        write_file(CHANGES_PATH, updated)
        print(f"{CHANGES_PATH} updated for release {new_version}")


# カレントブランチと作業ツリーがリリース可能な状態かどうかを確認する
def verify_release_state() -> None:
    branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if not (branch == "develop" or branch.startswith("release/")):
        raise SystemExit(
            f"Release must be executed on develop or release/* branch (current: {branch})"
        )

    # 作業ツリーがクリーンであることを確認する。
    # 汚れているとリリースと無関係な変更をコミットしてしまう。
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if status:
        raise SystemExit("Working tree is not clean. Commit or stash changes first")

    print(f"Branch: {branch}")


# 各 workspace の lockfile を同期する
def run_cargo_update(current_version: str, new_version: str, dry_run: bool) -> None:
    for manifest_path, crate_names in WORKSPACE_LOCKFILES:
        command: list[str] = ["cargo", "update", "--manifest-path", manifest_path]
        command.extend(crate_names)
        if dry_run:
            print(f"Dry-run: Would run '{' '.join(command)}'")
        else:
            subprocess.run(command, check=True)
            print(f"cargo update executed for {manifest_path}")

    if not dry_run:
        verify_lockfiles(current_version, new_version)


# lockfile のバージョンが更新されていることを確認する
def verify_lockfiles(current_version: str, new_version: str) -> None:
    old_entry: str = f'version = "{current_version}"'
    new_entry: str = f'version = "{new_version}"'
    for lockfile_path in LOCKFILE_PATHS:
        content: str = read_file(lockfile_path)
        if old_entry in content:
            raise SystemExit(
                f"{lockfile_path} still contains version {current_version}"
            )
        if new_entry not in content:
            raise SystemExit(f"{lockfile_path} does not contain version {new_version}")
        print(f"{lockfile_path} synced to {new_version}")


# バージョン更新をコミットする
def git_commit_version(
    new_version: str, release: bool, dry_run: bool, paths: list[str]
) -> None:
    message: str = (
        f"バージョンを {new_version} に更新する"
        if release
        else f"canary バージョンを {new_version} に更新する"
    )
    if dry_run:
        print(f"Dry-run: Would run 'git add {' '.join(paths)}'")
        print(f"Dry-run: Would commit '{message}'")
    else:
        subprocess.run(["git", "add", *paths], check=True)
        subprocess.run(["git", "commit", "-m", message], check=True)
        print(f"Version bumped and committed: {new_version}")


# タグ付けとプッシュを実行する
def git_tag_and_push(new_version: str, dry_run: bool) -> None:
    if dry_run:
        print(f"Dry-run: Would run 'git tag {new_version}'")
        print("Dry-run: Would run 'git push'")
        print(f"Dry-run: Would run 'git push origin {new_version}'")
    else:
        subprocess.run(["git", "tag", new_version], check=True)
        subprocess.run(["git", "push"], check=True)
        subprocess.run(["git", "push", "origin", new_version], check=True)
        print(f"Tagged and pushed: {new_version}")


# メイン処理
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update the version of the three crates and release them."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in dry-run mode without making actual changes",
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help=(
            "Convert the current canary version to a release version "
            "(e.g. 2026.1.0-canary.2 -> 2026.1.0) and update CHANGES.md"
        ),
    )
    args = parser.parse_args()

    current_version: str = read_current_version()
    new_version: str = (
        release_version(current_version)
        if args.release
        else next_canary_version(current_version)
    )

    print(f"Current version: {current_version}")
    print(f"New version: {new_version}")

    if args.dry_run:
        # dry-run は非対話モードのため、確認プロンプトを挟まずに進める
        print("Dry-run: Version would be updated")
    else:
        confirmation: str = (
            input("Do you want to update the version? (Y/n): ").strip().lower()
        )
        # (Y/n) 慣例に従い、空入力 / y / yes を Yes として扱う
        if confirmation not in ("", "y", "yes"):
            print("Version update canceled.")
            return

        # タグを打つ前にブランチと作業ツリーを確認する
        verify_release_state()

    if args.release:
        update_changes(new_version, args.dry_run)

    update_versions(current_version, new_version, args.dry_run)

    run_cargo_update(current_version, new_version, args.dry_run)

    paths: list[str] = [*COMMIT_PATHS]
    if args.release:
        paths.append(CHANGES_PATH)

    git_commit_version(new_version, args.release, args.dry_run, paths)
    git_tag_and_push(new_version, args.dry_run)


if __name__ == "__main__":
    main()
