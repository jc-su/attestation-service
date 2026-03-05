# attestation-service

Rust verifier service for TrustFnCall container attestation.

Repository status: Rust implementation only (legacy Go server path removed).

## Design

- `src/refstore.rs`: durable manual reference store + policy-managed references with glob matching.
- `src/policy.rs`: `AttestationPolicy` YAML compiler (multi-document, strict digest validation).
- `src/policy_action_store.rs`: selector-based policy action resolver for verdict-driven remediation (`none|alert|restart|kill`).
- `src/policy_sync.rs`: periodic policy sync loop (`--policy-file`) with add/update/remove semantics.
- `src/quote.rs`: strict TDX quote parser (v4 and v5, TDX 1.0/1.5 body formats).
- `src/quote_backend.rs`: pluggable quote verification backends:
  - `dcap`: Intel QVL (`tee_verify_quote`) via runtime dynamic loading.
  - `ita`: external command adapter for Intel Trust Authority workflows.
  - `insecure`: skip signature verification (development only).
- `src/verifier.rs`: RTMR3 replay, measurement comparison, strict quote body binding, verdict synthesis.
- `src/verification_cache.rs`: authority-side short-TTL verification cache with in-flight dedupe for identical `VerifyContainerEvidence` requests.
- `src/token.rs`: signed JWT issuance (HS256) for local attestation result tokens.
- `src/service.rs`: tonic gRPC handlers for `VerifyContainerEvidence`, `GetLatestVerdict`, `WatchVerdictUpdates`, reference value management, and health.
- `src/main.rs`: runtime wiring, CLI config, and graceful shutdown.

Proto authority:

- `proto/v1/attestation.proto` is the canonical contract for all consumers.
- KubeVirt vendoring path is `../kubevirt/pkg/virt-handler/trustd/attestationproto/v1`.
- Sync command from kubevirt repo root: `./hack/sync-attestation-proto.sh`.
- Drift check command from kubevirt repo root: `./hack/verify-attestation-proto-sync.sh`.

## Build and test

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Run

```bash
cargo run -- \
  --addr 0.0.0.0:50051 \
  --reference-store-path ./data/reference-values.json \
  --policy-file ../examples/attestation-policy.yaml \
  --policy-reload-seconds 30
```

## Container Build

```bash
docker build -t trustfncall/attestation-service:latest .
docker run --rm -p 50051:50051 trustfncall/attestation-service:latest
```

Quote backend flags:

- `--quote-verifier dcap|ita|insecure` (default: `dcap`)
- `--dcap-library-path /path/to/libsgx_dcap_quoteverify.so` (optional override)
- `--ita-command /path/to/ita-adapter` (required for `--quote-verifier ita`)
- `--ita-arg ...` (repeatable args for `--ita-command`)
- `--insecure-skip-quote-verify` (deprecated alias for `--quote-verifier insecure`)

Token flags:

- `--token-issuer trustfncall-attestation-service`
- `--token-ttl-seconds 300`
- `--jwt-secret-path /path/to/secret`

Reference/policy flags:

- `--reference-store-path /var/lib/trustfncall/reference-values.json`
- `--policy-file /path/to/attestation-policy.yaml` (repeatable)
- `--policy-reload-seconds 30`
- `--verify-cache-ttl-seconds 5`
- `--verify-cache-max-entries 4096`

Identity matching behavior:

- First tries `container_image` from evidence.
- Falls back to `cgroup://<cgroup_path>` when image identity is unavailable.
- Supports wildcard selectors (`*` and `?`) in policy or manual reference keys.

Policy-driven action behavior:

- `enforcementAction: enforce` maps `UNTRUSTED` to `restart`; `audit`/`disabled` map to `none`.
- `heartbeatPolicy.action` maps `STALE` to `alert|restart|kill`.
- `VerifyResponse.policy_action` returns the selected action (`none|alert|restart|kill`).

To use `../examples/attestation-policy.yaml` in Kubernetes:

1. Create/update a ConfigMap from the policy file.
2. Mount it into the attestation-service pod (for example at `/etc/trustfncall/policies/attestation-policy.yaml`).
3. Start service with `--policy-file=/etc/trustfncall/policies/attestation-policy.yaml`.

## DCAP Runtime Requirements

`dcap` mode requires Intel DCAP quote verification library to be available at runtime:

- `libsgx_dcap_quoteverify.so.1` (or compatible)
- optional override via env `SGX_DCAP_QUOTE_VERIFY_LIB_PATH` or CLI `--dcap-library-path`

## ITA Command Contract

In `ita` mode, the verifier invokes `--ita-command` and exchanges JSON over stdio.

Input JSON:

```json
{
  "quote_base64": "<base64 quote>",
  "nonce_hex": "<hex nonce>",
  "rtmr3_hex": "<hex rtmr3>",
  "report_data_hex": "<hex report data>"
}
```

Output JSON:

```json
{
  "status": "TRUSTED|STALE|UNTRUSTED",
  "signature_valid": true,
  "message": "human readable message",
  "attestation_token": "optional token"
}
```
