#!/usr/bin/env bash
# Apply the full attestation-service stack: RBAC, ConfigMap (TCB ref-values),
# Service, Deployment.  Idempotent — re-running is safe.
#
# Prereqs:
#   1. KUBECONFIG points at the cluster (default: /etc/rancher/k3s/k3s.yaml).
#   2. localhost/trustweave-attestation-service:latest built and imported
#      into k3s containerd (see ../Dockerfile + tdx-guest/build-all.sh).
#   3. Host PCCS reachable at https://localhost:8081 (we run with
#      hostNetwork=true for the DCAP collateral path).
#
# Per-image reference values (file SHA-384 digests for IMA matching) are
# uploaded separately via the gRPC API — see ablation/microbench/upload_ref.py.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
: "${KUBECONFIG:=/etc/rancher/k3s/k3s.yaml}"
export KUBECONFIG

NS=kubevirt

echo "[apply] RBAC"
kubectl apply -f "${SCRIPT_DIR}/rbac.yaml"

echo "[apply] CRDs"
kubectl apply -f "${SCRIPT_DIR}/crd-attestation-policy.yaml"

echo "[apply] TCB ref-values ConfigMap"
kubectl apply -f "${SCRIPT_DIR}/tcb-ref.configmap.yaml"

echo "[apply] Service"
kubectl apply -f "${SCRIPT_DIR}/service.yaml"

echo "[apply] Deployment"
kubectl apply -f "${SCRIPT_DIR}/deployment.yaml"

echo "[apply] forcing rollout (hostNetwork=true means port 50051 is single-instance)"
# scale → 0 → 1 to free the host port between revisions
kubectl scale -n "$NS" deploy/attestation-service --replicas=0
sleep 3
kubectl scale -n "$NS" deploy/attestation-service --replicas=1
kubectl rollout status -n "$NS" deploy/attestation-service --timeout=120s

echo "[apply] verify TCB ref-values loaded"
POD="$(kubectl get pod -n "$NS" -l app=attestation-service -o name | head -1)"
kubectl logs -n "$NS" "$POD" --tail=30 | grep -i 'tcb reference store loaded' || {
    echo "WARN: TCB ref-values were not detected in startup logs — verify_workload will skip the TCB check (fail-open)" >&2
}

echo "[apply] done"
