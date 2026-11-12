set shell := ["bash", "-uc"]

default:
    @just --list

# Format the workspace
fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --all-targets --all-features --locked -- -D warnings

test:
    cargo test --all-targets --locked

# Dependency, license, and advisory policy
deny:
    cargo deny check

# Full local gate; mirrors CI
check: fmt-check clippy test deny
    @echo "all checks passed"

run:
    cargo run

# Local Postgres from compose.yml
db-up:
    docker compose up -d db

db-down:
    docker compose down

db-logs:
    docker compose logs -f db
