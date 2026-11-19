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

# Local MCP upstream for the policy/audit path: run `just mcp-stub` in one shell
# and `just mcp-route` in another. The stub is on loopback, which the default
# egress policy blocks, so these recipes relax it explicitly.
mcp-stub:
    UPSTREAM_EGRESS=allow-all cargo run --quiet --example mcp_stub

mcp-route:
    UPSTREAM_EGRESS=allow-all cargo run --quiet -- admin upstream put mcp-stub --base-url http://127.0.0.1:18100 --timeout-ms 30000
    UPSTREAM_EGRESS=allow-all cargo run --quiet -- admin route put mcp --prefix /mcp --upstream mcp-stub --method POST \
        --rewrite /mcp \
        --request-timeout-ms 120000 \
        --tool-policy '{"mode":"allow_list","roles":{"service":["search_tickets"]}}'

docker:
    docker build -t api-gateway:dev .

# Three replicas, one Postgres, one load balancer, one MCP stub. See
# deploy/local/README.md for what it can and cannot prove.
cluster-up:
    docker compose -f deploy/local/compose.yml up -d --build --wait

cluster-down:
    docker compose -f deploy/local/compose.yml down -v

cluster-limit:
    ./scripts/cluster-limit-demo.sh

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
