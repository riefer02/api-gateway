# Build stage. Cache-friendly: dependencies are compiled before the sources are
# copied, so day-to-day edits only rebuild this crate.
FROM rust:1.99-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src

RUN cargo build --release --locked --bin api-gateway

# Runtime stage: no shell, no package manager, runs as non-root.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /app/target/release/api-gateway /usr/local/bin/api-gateway

USER nonroot:nonroot
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/api-gateway", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/api-gateway", "serve"]
