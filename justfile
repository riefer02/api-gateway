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
    cargo run -- serve

# Local Postgres from compose.yml
db-up:
    docker compose up -d db

db-down:
    docker compose down

db-logs:
    docker compose logs -f db

# Register the demo upstream and route (idempotent)
demo-route:
    cargo run --quiet -- admin upstream put swapi --base-url https://swapi.dev/api
    cargo run --quiet -- admin route put swapi-people --prefix /swapi --upstream swapi --scope read

docker:
    docker build -t api-gateway:dev .

# Measures gateway overhead against a local stub upstream
bench:
    ./scripts/bench.sh

# Starts two replicas and proves revocation + route convergence across them
replicas:
    ./scripts/replicas.sh

# Mutation testing (slow, on demand only). Needs `cargo install cargo-mutants`.
mutants:
    cargo mutants --jobs 4

up:
    docker compose up -d --build

down:
    docker compose down
