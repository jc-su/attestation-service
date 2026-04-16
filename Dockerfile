# Build stage
FROM rust:1.90-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    ca-certificates \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src

RUN cargo build --release --locked

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/attestation-service /usr/local/bin/attestation-service

USER 65532:65532

EXPOSE 50051

ENTRYPOINT ["/usr/local/bin/attestation-service"]
