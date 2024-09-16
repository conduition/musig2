.PHONY: check check-* test test-*
check: check-default check-mixed check-secp256k1 check-k256

# Checks the source code with default features enabled.
check-default:
	cargo clippy -- -D warnings

# Checks the source code with all features enabled.
check-mixed:
	cargo clippy --all-features -- -D warnings
	cargo clippy --all-features --tests -- -D warnings

# Checks the source code with variations of libsecp256k1 feature sets.
check-secp256k1:
	cargo clippy --no-default-features --features secp256k1 -- -D warnings
	cargo clippy --no-default-features --features secp256k1,serde -- -D warnings
	cargo clippy --no-default-features --features secp256k1,serde,rand -- -D warnings
	cargo clippy --no-default-features --features secp256k1,serde,rand --tests -- -D warnings

# Checks the source code with variations of pure-rust feature sets.
check-k256:
	cargo clippy --no-default-features --features k256 -- -D warnings
	cargo clippy --no-default-features --features k256,serde -- -D warnings
	cargo clippy --no-default-features --features k256,serde,rand -- -D warnings
	cargo clippy --no-default-features --features k256,serde,rand --tests -- -D warnings


test: test-default test-mixed test-secp256k1 test-k256

test-default:
	cargo test

test-mixed:
	cargo test --all-features

test-secp256k1:
	cargo test --no-default-features --features secp256k1,serde,rand

test-k256:
	cargo test --no-default-features --features k256,serde,rand

.PHONY: docwatch
docwatch:
	watch -n 5 cargo doc --all-features
