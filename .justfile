[private]
default:
    @just --list

## Format (check only)
fmt:
  cargo fmt --all -- --check

## Clippy (treat warnings as errors)
clippy:
  cargo clippy --workspace --all-targets --all-features -- -D warnings

## Baseline tests (default features, debug)
test:
  cargo test --workspace

## Baseline tests (default features, release)
test-release:
  cargo test --workspace --release

## TNID crate tests with serde enabled (debug + release)
test-tnid-serde:
  cargo test -p tnid --features serde
  cargo test -p tnid --features serde --release

## TNID crate tests with all features (debug + release)
test-tnid-all-features:
  cargo test -p tnid --all-features
  cargo test -p tnid --all-features --release

## TNID crate compile-check with no features enabled (debug + release)
check-tnid-no-features:
  cargo check -p tnid --no-default-features
  cargo check -p tnid --no-default-features --release

## TNID crate tests with no features enabled (debug + release)
##
## Note: `--lib` avoids doctests, which often assume the default feature set.
test-tnid-no-features:
  cargo test -p tnid --no-default-features --lib
  cargo test -p tnid --no-default-features --release --lib

## Compile-check SQLx feature combos (no-default-features)
check-tnid-sqlx:
  cargo check -p tnid --no-default-features --features "sqlx-postgres"
  cargo check -p tnid --no-default-features --features "sqlx-mysql"
  cargo check -p tnid --no-default-features --features "sqlx-sqlite"

## Quick CI-ish suite (safe to run locally)
ci: fmt clippy test test-release test-tnid-serde test-tnid-all-features check-tnid-no-features test-tnid-no-features check-tnid-sqlx
