[private]
default:
    @just --list

# Build the release binary.
build:
    cargo build --release --locked

# Check Rust formatting and lint all targets.
check:
    cargo fmt --all --check
    cargo clippy --all-targets --locked -- -D warnings

# Run Rust unit and integration tests.
test-rust:
    cargo test --all-targets --locked

# Run DNSSEC integration tests with BIND tools installed.
test-bind:
    cargo test --test bind --locked -- --ignored

# Build the Debian package on Debian 13; requires cargo-deb 3.8.0.
deb: build
    cargo deb --locked --no-build

# Regenerate third-party notices using cargo-about 0.9.2.
generate-notices:
    cargo about generate --locked --fail about.hbs -o THIRD_PARTY_NOTICES.md
