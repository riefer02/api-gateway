# The MCP stub, built from the same workspace so the local cluster exercises
# the real policy path rather than a mock of it.
FROM rust:1.99-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
COPY examples ./examples

RUN cargo build --release --locked --example mcp_stub

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /app/target/release/examples/mcp_stub /usr/local/bin/mcp_stub

ENV MCP_STUB_HOST=0.0.0.0
ENV MCP_STUB_PORT=18100

USER nonroot:nonroot
EXPOSE 18100
ENTRYPOINT ["/usr/local/bin/mcp_stub"]
