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

# Runtime stage — adds Intel DCAP quote-verify library so the binary's
# dlopen("libsgx_dcap_quoteverify.so.1") path can succeed and we can drop
# the --insecure-skip-quote-verify bypass. Pulls from Intel's SGX APT repo
# (same repo we used to install sgx-dcap-pccs on the host).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
       | gpg --dearmor -o /etc/apt/keyrings/intel-sgx.gpg \
    && printf '%s\n' \
        'deb [signed-by=/etc/apt/keyrings/intel-sgx.gpg arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' \
       > /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        libsgx-dcap-quote-verify \
        libsgx-dcap-default-qpl \
    && apt-get purge -y --auto-remove curl gnupg \
    && rm -rf /var/lib/apt/lists/*

# QCNL configures the QPL (libsgx_dcap_default_qpl) — tells DCAP where to
# fetch PCK certs/CRLs/TCB info. We point at the host's PCCS via the cluster
# node IP. hostNetwork=true on the Deployment makes localhost work; otherwise
# this falls back to the host gateway via the pod network.
COPY sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf

# PCCS uses a self-signed TLS cert. Add it to the container CA store so
# QPL's `use_secure_cert: true` accepts the connection.
COPY pccs-localhost.crt /usr/local/share/ca-certificates/pccs-localhost.crt
RUN update-ca-certificates

COPY --from=builder /build/target/release/attestation-service /usr/local/bin/attestation-service

USER 65532:65532

EXPOSE 50051

ENTRYPOINT ["/usr/local/bin/attestation-service"]
