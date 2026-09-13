.PHONY: test doc-test check clippy fmt package-list clean interop-test fuzzing fuzzing-list

# 全テストを実行する
#
# --tests を付けて doctest を除外する。ngtcp2-sys の bindings.rs には
# bindgen が C ヘッダーのコメントから生成した doc コメントが含まれ、
# その中の Rust 風のサンプルが rustc でパースできないため。
#
# --features source-build を付けて ngtcp2 をソースからビルドする。既定は
# GitHub Releases の prebuilt をダウンロードするが、開発中のバージョンには
# リリースが無いため。
test:
	cargo test --workspace --tests --features source-build

# doctest を実行する (bindgen 生成 doc を含むクレートを除外する)
doc-test:
	cargo test --doc --workspace --exclude shiguredo_ngtcp2_sys --features source-build

# cargo check を実行する
check:
	cargo check --workspace --features source-build

# cargo clippy を実行する
clippy:
	cargo clippy --workspace --all-targets --features source-build -- -D warnings

# cargo fmt を実行する
fmt:
	cargo fmt --all

# s2n-quic / quiche との相互運用テストを実行する
#
# ルートの workspace とは別の workspace にしている (quiche が BoringSSL を
# ビルドするため)。quiche を動かすドライバは別パッケージのバイナリなので
# 先にビルドする。
interop-test:
	cd interop && cargo build --workspace --bins
	cd interop && cargo test

# fuzz ターゲットを全件 30 秒ずつ実行する
#
# fuzz はルートの workspace とは別の workspace のため、fuzz ディレクトリで実行する。
fuzzing:
	@cd fuzz && for target in $$(cargo +nightly fuzz list); do \
		echo "=== Fuzzing $$target ==="; \
		cargo +nightly fuzz run $$target -- -max_total_time=30 || exit 1; \
	done

# fuzz ターゲットの一覧を表示する
fuzzing-list:
	cd fuzz && cargo +nightly fuzz list

# パッケージに含まれるファイルを確認する
#
# `cargo package` は依存先が crates.io に存在することを要求するため、
# 未公開の状態では shiguredo_ngtcp2 以降のパッケージングはできない。
# 公開順は shiguredo_ngtcp2_sys -> shiguredo_ngtcp2 -> shiguredo_ngtcp2_tokio。
package-list:
	cargo package -p shiguredo_ngtcp2_sys --allow-dirty --no-verify --list
	cargo package -p shiguredo_ngtcp2 --allow-dirty --no-verify --list
	cargo package -p shiguredo_ngtcp2_tokio --allow-dirty --no-verify --list

# ビルド成果物を削除する
clean:
	cargo clean
