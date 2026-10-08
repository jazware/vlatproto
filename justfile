# vlatproto: the atproto crate vlsync, vlpds and vlRelay build on.

# Type-check every target
check:
    cargo check --all-targets --all-features

test *args:
    cargo test {{args}}

clippy:
    cargo clippy --all-targets -- -D warnings

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

# No private names or secrets (the public export's audit patterns; monorepo only)
check-private:
    python3 ../../scripts/vlatproto-public/vlatproto_public.py scan .

ci: fmt-check check-private check clippy test
