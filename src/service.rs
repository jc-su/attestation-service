use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{RwLock, broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::warn;

use crate::policy_action_store::{PolicyAction, PolicyActionStore, PolicyCondition};
use crate::proto;
use crate::quote_backend::QuoteVerifierBackend;
use crate::refstore::{ReferenceEntry, ReferenceStore, TcbReferenceStore};
use crate::token::{TokenClaims, TokenIssuer};
use crate::verifier::{TrustVerdict, Verifier, WorkloadVerifyRequest, WorkloadVerifyResult};

const VERDICT_SOURCE: &str = "attestation-service/verify_workload";
const VERDICT_EXPIRED_SOURCE: &str = "attestation-service/verdict-expired";
const VERDICT_REFERENCE_VALUES_SOURCE: &str = "attestation-service/reference-values-updated";
const VERDICT_MANUAL_UPDATE_SOURCE: &str = "attestation-service/update-latest-verdict";
const UPDATE_LATEST_VERDICT_TOKEN_HEADER: &str = "x-attestation-update-token";
const VERDICT_BROADCAST_CAPACITY: usize = 1024;
const EXPIRED_VERDICT_MESSAGE: &str = "latest verdict expired; re-attestation required";
const REFERENCE_VALUES_UPDATED_MESSAGE: &str = "reference values updated; re-attestation required";

#[derive(Clone, Debug)]
struct VerdictRecord {
    subject: String,
    verdict: i32,
    message: String,
    policy_action: String,
    attestation_token: String,
    verified_at: i64,
    expires_at: i64,
    version: u64,
    source: String,
}

impl VerdictRecord {
    fn is_trusted(&self) -> bool {
        self.verdict == proto::Verdict::Trusted as i32
    }

    fn is_expired(&self, now: i64) -> bool {
        self.expires_at > 0 && now >= self.expires_at
    }

    fn with_stale_verdict(&self, version: u64, now: i64, source: &str, message: &str) -> Self {
        Self {
            subject: self.subject.clone(),
            verdict: proto::Verdict::Stale as i32,
            message: append_message(&self.message, message),
            policy_action: self.policy_action.clone(),
            attestation_token: String::new(),
            verified_at: now,
            expires_at: 0,
            version,
            source: source.to_owned(),
        }
    }

    fn as_latest_response(&self) -> proto::GetLatestVerdictResponse {
        proto::GetLatestVerdictResponse {
            subject: self.subject.clone(),
            verdict: self.verdict,
            message: self.message.clone(),
            policy_action: self.policy_action.clone(),
            attestation_token: self.attestation_token.clone(),
            verified_at: self.verified_at,
            expires_at: self.expires_at,
            version: self.version,
            source: self.source.clone(),
        }
    }

    fn as_update(&self) -> proto::VerdictUpdate {
        proto::VerdictUpdate {
            subject: self.subject.clone(),
            verdict: self.verdict,
            message: self.message.clone(),
            policy_action: self.policy_action.clone(),
            attestation_token: self.attestation_token.clone(),
            verified_at: self.verified_at,
            expires_at: self.expires_at,
            version: self.version,
            source: self.source.clone(),
        }
    }
}

struct VerdictStore {
    entries: RwLock<HashMap<String, VerdictRecord>>,
    next_version: AtomicU64,
    updates: broadcast::Sender<VerdictRecord>,
    ttl_seconds: i64,
}

impl VerdictStore {
    fn new(ttl_seconds: i64) -> Self {
        let (updates, _) = broadcast::channel(VERDICT_BROADCAST_CAPACITY);
        Self {
            entries: RwLock::new(HashMap::new()),
            next_version: AtomicU64::new(1),
            updates,
            ttl_seconds,
        }
    }

    fn ttl_seconds(&self) -> i64 {
        self.ttl_seconds
    }

    fn allocate_version(&self) -> u64 {
        self.next_version.fetch_add(1, Ordering::SeqCst)
    }

    async fn upsert(&self, record: VerdictRecord) {
        let required_next = record.version.saturating_add(1);
        let mut current = self.next_version.load(Ordering::SeqCst);
        while required_next > current {
            match self.next_version.compare_exchange(
                current,
                required_next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        self.entries
            .write()
            .await
            .insert(record.subject.clone(), record.clone());
        let _ = self.updates.send(record);
    }

    async fn get_effective(
        &self,
        subject: &str,
        now: i64,
        source: &str,
        message: &str,
    ) -> Option<VerdictRecord> {
        let existing = self.entries.read().await.get(subject).cloned()?;
        if !existing.is_trusted() || !existing.is_expired(now) {
            return Some(existing);
        }

        let stale = existing.with_stale_verdict(self.allocate_version(), now, source, message);
        self.upsert(stale.clone()).await;
        Some(stale)
    }

    async fn list_since(&self, after_version: u64) -> Vec<VerdictRecord> {
        let mut records = self
            .entries
            .read()
            .await
            .values()
            .filter(|record| record.version > after_version)
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.version);
        records
    }

    fn subscribe(&self) -> broadcast::Receiver<VerdictRecord> {
        self.updates.subscribe()
    }

    async fn expire_due_records(&self, now: i64, source: &str, message: &str) -> usize {
        let expired = {
            let entries = self.entries.read().await;
            entries
                .values()
                .filter(|record| record.is_trusted() && record.is_expired(now))
                .cloned()
                .collect::<Vec<_>>()
        };

        for record in &expired {
            let stale = record.with_stale_verdict(self.allocate_version(), now, source, message);
            self.upsert(stale).await;
        }

        expired.len()
    }

    async fn invalidate_trusted(&self, now: i64, source: &str, message: &str) -> usize {
        let trusted = {
            let entries = self.entries.read().await;
            entries
                .values()
                .filter(|record| record.is_trusted())
                .cloned()
                .collect::<Vec<_>>()
        };

        for record in &trusted {
            let stale = record.with_stale_verdict(self.allocate_version(), now, source, message);
            self.upsert(stale).await;
        }

        trusted.len()
    }

    async fn update_subjects(
        &self,
        subjects: &[String],
        verdict: i32,
        message: &str,
        policy_action: &str,
        source: &str,
        now: i64,
    ) -> usize {
        let mut updated = 0;
        for subject in subjects {
            if subject.trim().is_empty() {
                continue;
            }
            let expires_at = if verdict == proto::Verdict::Trusted as i32 {
                now.saturating_add(self.ttl_seconds())
            } else {
                0
            };
            let record = VerdictRecord {
                subject: subject.clone(),
                verdict,
                message: message.to_owned(),
                policy_action: policy_action.to_owned(),
                attestation_token: String::new(),
                verified_at: now,
                expires_at,
                version: self.allocate_version(),
                source: source.to_owned(),
            };
            self.upsert(record).await;
            updated += 1;
        }
        updated
    }
}

#[derive(Clone)]
pub struct PolicyReloadHooks {
    verdict_store: Arc<VerdictStore>,
}

impl PolicyReloadHooks {
    pub async fn invalidate(&self) {
        let now = unix_seconds(SystemTime::now());
        let _ = self
            .verdict_store
            .invalidate_trusted(
                now,
                VERDICT_REFERENCE_VALUES_SOURCE,
                REFERENCE_VALUES_UPDATED_MESSAGE,
            )
            .await;
    }
}

fn append_message(base: &str, extra: &str) -> String {
    if extra.is_empty() {
        return base.to_owned();
    }
    if base.is_empty() {
        return extra.to_owned();
    }
    format!("{base}; {extra}")
}

pub struct AttestationService {
    verifier: Verifier<Arc<dyn ReferenceStore>>,
    policy_actions: Arc<dyn PolicyActionStore>,
    token_issuer: TokenIssuer,
    verdict_store: Arc<VerdictStore>,
    update_latest_verdict_token: Option<Arc<str>>,
    version: Arc<str>,
    started_at: Instant,
}

impl AttestationService {
    pub fn new(
        store: Arc<dyn ReferenceStore>,
        policy_actions: Arc<dyn PolicyActionStore>,
        token_issuer: TokenIssuer,
        quote_backend: QuoteVerifierBackend,
        verdict_ttl_seconds: i64,
        update_latest_verdict_token: Option<Arc<str>>,
        version: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            verifier: Verifier::new(store, quote_backend),
            policy_actions,
            token_issuer,
            verdict_store: Arc::new(VerdictStore::new(verdict_ttl_seconds)),
            update_latest_verdict_token,
            version: version.into(),
            started_at: Instant::now(),
        }
    }

    /// Builder-style: attach a TCB reference store so `verify_workload`
    /// can check RTMR[2] against a known-good kernel allow-list.
    pub fn with_tcb_store(mut self, tcb: Arc<dyn TcbReferenceStore>) -> Self {
        self.verifier = self.verifier.with_tcb_store(tcb);
        self
    }

    pub fn policy_reload_hooks(&self) -> PolicyReloadHooks {
        PolicyReloadHooks {
            verdict_store: Arc::clone(&self.verdict_store),
        }
    }

    fn map_verdict(verdict: TrustVerdict) -> i32 {
        match verdict {
            TrustVerdict::Trusted => proto::Verdict::Trusted as i32,
            TrustVerdict::Untrusted => proto::Verdict::Untrusted as i32,
            TrustVerdict::Stale => proto::Verdict::Stale as i32,
            TrustVerdict::Unknown => proto::Verdict::Unknown as i32,
        }
    }

    fn resolve_policy_action(&self, workload_id: &str, verdict: TrustVerdict) -> PolicyAction {
        let condition = match verdict {
            TrustVerdict::Untrusted => PolicyCondition::Untrusted,
            TrustVerdict::Stale => PolicyCondition::Stale,
            TrustVerdict::Trusted | TrustVerdict::Unknown => return PolicyAction::None,
        };
        let identities = [format!("workload://{workload_id}")];
        self.policy_actions.resolve_action(&identities, condition)
    }

    fn build_workload_token_claims(
        workload_id: &str,
        result: &WorkloadVerifyResult,
        policy_action: PolicyAction,
    ) -> TokenClaims {
        TokenClaims {
            verdict: result.verdict.as_str().to_owned(),
            policy_action: policy_action.as_str().to_owned(),
            // cgroup_path comes from the kernel-emitted per-container
            // event-log header — populated when the request carried
            // event_log bytes; empty otherwise.
            cgroup_path: result.cgroup_path.clone(),
            container_image: format!("workload://{workload_id}"),
            // vmi_{name,namespace} are not part of the workload-evidence
            // wire format. Left empty by design — relying parties that
            // need K8s identity should consume the JWT claim
            // `container_image` (workload://<id>) and resolve out-of-band.
            vmi_name: String::new(),
            vmi_namespace: String::new(),
            // rtmr3 is the CVM-shared accumulator at attestation time —
            // useful as JWT evidence even though it is *not* gated by
            // the TCB check (per-container measurements live in
            // event_log, not RTMR[3]).
            rtmr3: result.rtmr3_hex.clone().unwrap_or_default(),
            measurement_count: (result.matched_count + result.unknown_count) as i32,
            matched_count: result.matched_count,
            unknown_count: result.unknown_count,
            // This verifier intentionally does not perform an RTMR[3]
            // replay (per-container measurements come from the
            // virtual event log, not from extending RTMR[3]). Claim
            // is left false; relying parties should rely on
            // matched_count + all_required_present instead.
            rtmr3_replay_valid: false,
            all_required_present: result.all_required_present,
            quote_verified: result.quote_signature_valid,
        }
    }

    async fn publish_workload_verdict(&self, workload_id: &str, response: &proto::VerifyWorkloadResponse) {
        let subject = format!("workload://{workload_id}");
        let now = unix_seconds(SystemTime::now());
        let expires_at = now.saturating_add(self.verdict_store.ttl_seconds());
        let record = VerdictRecord {
            subject,
            verdict: response.verdict,
            message: response.message.clone(),
            policy_action: response.policy_action.clone(),
            attestation_token: response.attestation_token.clone(),
            verified_at: now,
            expires_at,
            version: self.verdict_store.allocate_version(),
            source: VERDICT_SOURCE.to_owned(),
        };
        self.verdict_store.upsert(record).await;
    }

    fn authorize_update_latest_verdict(
        &self,
        request: &Request<proto::UpdateLatestVerdictRequest>,
    ) -> Result<(), Status> {
        let Some(expected) = self.update_latest_verdict_token.as_deref() else {
            return Err(Status::failed_precondition(
                "update latest verdict is disabled",
            ));
        };
        let provided = request
            .metadata()
            .get(UPDATE_LATEST_VERDICT_TOKEN_HEADER)
            .ok_or_else(|| Status::unauthenticated("missing update latest verdict auth token"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid update latest verdict auth token"))?;

        if provided.as_bytes() != expected.as_bytes() {
            return Err(Status::unauthenticated(
                "invalid update latest verdict auth token",
            ));
        }

        Ok(())
    }
}

#[tonic::async_trait]
impl proto::attestation_service_server::AttestationService for AttestationService {
    type WatchVerdictUpdatesStream = ReceiverStream<Result<proto::VerdictUpdate, Status>>;

    async fn verify_workload(
        &self,
        request: Request<proto::VerifyWorkloadRequest>,
    ) -> Result<Response<proto::VerifyWorkloadResponse>, Status> {
        let request = request.into_inner();
        if request.workload_id.is_empty() {
            return Err(Status::invalid_argument("workload_id required"));
        }
        if request.nonce_hex.is_empty() {
            return Err(Status::invalid_argument("nonce_hex required"));
        }

        let result = self
            .verifier
            .verify_workload(&WorkloadVerifyRequest {
                workload_id: request.workload_id.clone(),
                td_quote: request.td_quote,
                event_log: request.event_log,
                nonce_hex: request.nonce_hex,
                peer_pk: request.peer_pk,
            })
            .map_err(|error| Status::internal(format!("verify_workload failed: {error}")))?;

        let policy_action = self.resolve_policy_action(&request.workload_id, result.verdict.clone());
        let policy_action_value = policy_action.as_str().to_owned();

        let attestation_token = if matches!(result.verdict, TrustVerdict::Trusted) {
            let claims = Self::build_workload_token_claims(
                &request.workload_id,
                &result,
                policy_action,
            );
            match self.token_issuer.issue(&claims) {
                Ok(token) => token,
                Err(error) => {
                    warn!(error = %error, "token issuance failed; returning verdict without token");
                    String::new()
                }
            }
        } else {
            String::new()
        };

        let response = proto::VerifyWorkloadResponse {
            verdict: Self::map_verdict(result.verdict.clone()),
            message: result.message,
            attestation_token,
            details: Some(proto::WorkloadVerificationDetails {
                quote_signature_valid: result.quote_signature_valid,
                quote_verification_skipped: result.quote_verification_skipped,
                tcb_matches: result.tcb_matches,
                report_data_valid: result.report_data_valid,
                matched_count: result.matched_count,
                unknown_count: result.unknown_count,
                missing_count: result.missing_count,
                all_required_present: result.all_required_present,
                unknown_files: result.unknown_files,
                missing_files: result.missing_files,
            }),
            policy_action: policy_action_value,
        };

        self.publish_workload_verdict(&request.workload_id, &response).await;
        Ok(Response::new(response))
    }

    async fn set_reference_values(
        &self,
        request: Request<proto::SetReferenceValuesRequest>,
    ) -> Result<Response<proto::SetReferenceValuesResponse>, Status> {
        let request = request.into_inner();

        if request.container_image.is_empty() {
            return Err(Status::invalid_argument("container_image required"));
        }

        let Some(reference_values) = request.reference_values else {
            return Err(Status::invalid_argument("reference_values required"));
        };

        let entries = reference_values
            .entries
            .into_iter()
            .map(|entry| ReferenceEntry {
                filename: entry.filename,
                expected_digest: entry.expected_digest,
                required: entry.required,
            })
            .collect::<Vec<_>>();

        // The new-contract caller keys by workload_id, not container_image.
        // Keep the field name for backward compatibility on the wire.
        self.verifier_ref_store()
            .set(&request.container_image, entries)
            .map_err(|error| Status::internal(format!("set reference values failed: {error}")))?;
        let now = unix_seconds(SystemTime::now());
        let _ = self
            .verdict_store
            .invalidate_trusted(
                now,
                VERDICT_REFERENCE_VALUES_SOURCE,
                REFERENCE_VALUES_UPDATED_MESSAGE,
            )
            .await;

        Ok(Response::new(proto::SetReferenceValuesResponse {
            message: format!("reference values stored for {}", request.container_image),
        }))
    }

    async fn get_reference_values(
        &self,
        request: Request<proto::GetReferenceValuesRequest>,
    ) -> Result<Response<proto::ReferenceValues>, Status> {
        let request = request.into_inner();

        if request.container_image.is_empty() {
            return Err(Status::invalid_argument("container_image required"));
        }

        let values = self
            .verifier_ref_store()
            .get(&request.container_image)
            .map_err(|error| {
                Status::not_found(format!(
                    "reference values for {} not found: {error}",
                    request.container_image
                ))
            })?;

        let response = proto::ReferenceValues {
            container_image: values.container_image,
            entries: values
                .entries
                .into_iter()
                .map(|entry| proto::ReferenceEntry {
                    filename: entry.filename,
                    expected_digest: entry.expected_digest,
                    required: entry.required,
                })
                .collect(),
            created_at: values.created_at,
        };

        Ok(Response::new(response))
    }

    async fn health(
        &self,
        _request: Request<proto::HealthRequest>,
    ) -> Result<Response<proto::HealthResponse>, Status> {
        Ok(Response::new(proto::HealthResponse {
            status: "healthy".to_owned(),
            version: self.version.to_string(),
            uptime_seconds: self.started_at.elapsed().as_secs() as i64,
        }))
    }

    async fn update_latest_verdict(
        &self,
        request: Request<proto::UpdateLatestVerdictRequest>,
    ) -> Result<Response<proto::UpdateLatestVerdictResponse>, Status> {
        self.authorize_update_latest_verdict(&request)?;
        let request = request.into_inner();
        let subjects = request
            .subjects
            .into_iter()
            .map(|subject| subject.trim().to_owned())
            .filter(|subject| !subject.is_empty())
            .collect::<Vec<_>>();
        if subjects.is_empty() {
            return Err(Status::invalid_argument("subjects required"));
        }
        if request.verdict == proto::Verdict::Unspecified as i32 {
            return Err(Status::invalid_argument("verdict required"));
        }
        if request.verdict == proto::Verdict::Trusted as i32 {
            return Err(Status::invalid_argument(
                "trusted verdicts cannot be updated manually",
            ));
        }

        let now = unix_seconds(SystemTime::now());
        let source = if request.source.trim().is_empty() {
            VERDICT_MANUAL_UPDATE_SOURCE
        } else {
            request.source.trim()
        };
        let updated = self
            .verdict_store
            .update_subjects(
                &subjects,
                request.verdict,
                &request.message,
                &request.policy_action,
                source,
                now,
            )
            .await;

        Ok(Response::new(proto::UpdateLatestVerdictResponse {
            updated: updated as u32,
        }))
    }

    async fn get_latest_verdict(
        &self,
        request: Request<proto::GetLatestVerdictRequest>,
    ) -> Result<Response<proto::GetLatestVerdictResponse>, Status> {
        let request = request.into_inner();
        if request.subject.is_empty() {
            return Err(Status::invalid_argument("subject required"));
        }

        let now = unix_seconds(SystemTime::now());
        let Some(record) = self
            .verdict_store
            .get_effective(
                &request.subject,
                now,
                VERDICT_EXPIRED_SOURCE,
                EXPIRED_VERDICT_MESSAGE,
            )
            .await
        else {
            return Err(Status::not_found(format!(
                "no verdict available for subject {}",
                request.subject
            )));
        };

        Ok(Response::new(record.as_latest_response()))
    }

    async fn watch_verdict_updates(
        &self,
        request: Request<proto::WatchVerdictUpdatesRequest>,
    ) -> Result<Response<Self::WatchVerdictUpdatesStream>, Status> {
        let request = request.into_inner();
        let after_version = request.after_version;
        let subjects = if request.subjects.is_empty() {
            None
        } else {
            Some(request.subjects.into_iter().collect::<HashSet<_>>())
        };

        let (tx, rx) = mpsc::channel::<Result<proto::VerdictUpdate, Status>>(64);

        let now = unix_seconds(SystemTime::now());
        let _ = self
            .verdict_store
            .expire_due_records(now, VERDICT_EXPIRED_SOURCE, EXPIRED_VERDICT_MESSAGE)
            .await;

        let initial = self.verdict_store.list_since(after_version).await;
        for record in initial {
            if let Some(subject_filter) = &subjects {
                if !subject_filter.contains(&record.subject) {
                    continue;
                }
            }
            if tx.send(Ok(record.as_update())).await.is_err() {
                return Ok(Response::new(ReceiverStream::new(rx)));
            }
        }

        let mut updates = self.verdict_store.subscribe();
        tokio::spawn(async move {
            let mut cursor = after_version;
            loop {
                match updates.recv().await {
                    Ok(record) => {
                        if record.version <= cursor {
                            continue;
                        }
                        cursor = record.version;
                        if let Some(subject_filter) = &subjects {
                            if !subject_filter.contains(&record.subject) {
                                continue;
                            }
                        }
                        if tx.send(Ok(record.as_update())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

impl AttestationService {
    fn verifier_ref_store(&self) -> &Arc<dyn ReferenceStore> {
        self.verifier.ref_store()
    }
}

pub fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::policy_action_store::InMemoryPolicyActionStore;
    use crate::proto::attestation_service_server::AttestationService as _;
    use crate::quote_backend::{QuoteBackendConfig, QuoteBackendMode, QuoteVerifierBackend};
    use crate::refstore::{MemoryStore, ReferenceEntry, ReferenceStore};
    use crate::token::TokenIssuer;

    use super::*;

    const TEST_UPDATE_LATEST_VERDICT_TOKEN: &str = "test-update-token";

    fn new_service_with_update_token(update_token: Option<&str>) -> AttestationService {
        let store = Arc::new(MemoryStore::new());
        store
            .set(
                "wl-1",
                vec![ReferenceEntry {
                    filename: "/a".to_owned(),
                    expected_digest: "01".repeat(48),
                    required: true,
                }],
            )
            .expect("set should succeed");

        let issuer =
            TokenIssuer::from_secret("issuer", std::time::Duration::from_secs(60), vec![1_u8; 32])
                .expect("issuer should be created");
        let quote_backend = QuoteVerifierBackend::from_config(QuoteBackendConfig {
            mode: QuoteBackendMode::Insecure,
            dcap_library_path: None,
            ita_command: None,
            ita_args: Vec::new(),
        })
        .expect("backend should be created");
        let reference_store: Arc<dyn ReferenceStore> = store;
        AttestationService::new(
            reference_store,
            Arc::new(InMemoryPolicyActionStore::new()),
            issuer,
            quote_backend,
            60,
            update_token.map(Arc::<str>::from),
            "test",
        )
    }

    fn new_service() -> AttestationService {
        new_service_with_update_token(Some(TEST_UPDATE_LATEST_VERDICT_TOKEN))
    }

    fn authenticated_update_request(
        request: proto::UpdateLatestVerdictRequest,
    ) -> Request<proto::UpdateLatestVerdictRequest> {
        let mut request = Request::new(request);
        request.metadata_mut().insert(
            UPDATE_LATEST_VERDICT_TOKEN_HEADER,
            TEST_UPDATE_LATEST_VERDICT_TOKEN
                .parse()
                .expect("test token should be valid metadata"),
        );
        request
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let service = new_service();
        let response = service
            .health(Request::new(proto::HealthRequest {}))
            .await
            .expect("health should succeed")
            .into_inner();

        assert_eq!(response.status, "healthy");
        assert_eq!(response.version, "test");
    }

    #[tokio::test]
    async fn verify_workload_rejects_empty_workload_id() {
        let service = new_service();
        let err = service
            .verify_workload(Request::new(proto::VerifyWorkloadRequest::default()))
            .await
            .expect_err("invalid request should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn get_latest_verdict_after_verify_workload() {
        let service = new_service();
        // Empty event_log + missing td_quote → verify returns a verdict,
        // which we publish. We only need a response to exist, not Trusted.
        let _ = service
            .verify_workload(Request::new(proto::VerifyWorkloadRequest {
                workload_id: "wl-1".to_owned(),
                nonce_hex: "ab".repeat(32),
                td_quote: Vec::new(),
                event_log: Vec::new(),
                peer_pk: Vec::new(),
            }))
            .await
            .expect("verify_workload should succeed");

        let latest = service
            .get_latest_verdict(Request::new(proto::GetLatestVerdictRequest {
                subject: "workload://wl-1".to_owned(),
            }))
            .await
            .expect("latest verdict should exist")
            .into_inner();

        assert_eq!(latest.subject, "workload://wl-1");
        assert!(!latest.source.is_empty());
    }

    #[tokio::test]
    async fn set_reference_values_invalidates_trusted_verdicts() {
        let service = new_service();
        service
            .verdict_store
            .upsert(VerdictRecord {
                subject: "workload://wl-ref".to_owned(),
                verdict: proto::Verdict::Trusted as i32,
                message: "trusted".to_owned(),
                policy_action: "none".to_owned(),
                attestation_token: "token".to_owned(),
                verified_at: 100,
                expires_at: unix_seconds(SystemTime::now()) + 60,
                version: 1,
                source: VERDICT_SOURCE.to_owned(),
            })
            .await;

        service
            .set_reference_values(Request::new(proto::SetReferenceValuesRequest {
                container_image: "wl-1".to_owned(),
                reference_values: Some(proto::ReferenceValues {
                    container_image: "wl-1".to_owned(),
                    entries: vec![proto::ReferenceEntry {
                        filename: "/a".to_owned(),
                        expected_digest: "02".repeat(48),
                        required: true,
                    }],
                    created_at: unix_seconds(SystemTime::now()),
                }),
            }))
            .await
            .expect("set reference values should succeed");

        let latest = service
            .get_latest_verdict(Request::new(proto::GetLatestVerdictRequest {
                subject: "workload://wl-ref".to_owned(),
            }))
            .await
            .expect("latest verdict should exist")
            .into_inner();

        assert_eq!(latest.verdict, proto::Verdict::Stale as i32);
        assert_eq!(latest.source, VERDICT_REFERENCE_VALUES_SOURCE);
        assert!(latest.message.contains(REFERENCE_VALUES_UPDATED_MESSAGE));
        assert!(latest.attestation_token.is_empty());
    }

    #[tokio::test]
    async fn update_latest_verdict_publishes_override() {
        let service = new_service();

        let response = service
            .update_latest_verdict(authenticated_update_request(
                proto::UpdateLatestVerdictRequest {
                    subjects: vec!["workload://wl-update".to_owned()],
                    verdict: proto::Verdict::Stale as i32,
                    message: "heartbeat timeout detected by trustd".to_owned(),
                    policy_action: "restart".to_owned(),
                    source: "kubevirt/trustd".to_owned(),
                },
            ))
            .await
            .expect("update latest verdict should succeed")
            .into_inner();

        assert_eq!(response.updated, 1);

        let latest = service
            .get_latest_verdict(Request::new(proto::GetLatestVerdictRequest {
                subject: "workload://wl-update".to_owned(),
            }))
            .await
            .expect("latest verdict should exist")
            .into_inner();

        assert_eq!(latest.verdict, proto::Verdict::Stale as i32);
        assert_eq!(latest.policy_action, "restart");
        assert_eq!(latest.source, "kubevirt/trustd");
        assert_eq!(latest.message, "heartbeat timeout detected by trustd");
    }

    #[tokio::test]
    async fn update_latest_verdict_requires_auth_token() {
        let service = new_service();

        let err = service
            .update_latest_verdict(Request::new(proto::UpdateLatestVerdictRequest {
                subjects: vec!["workload://wl-update".to_owned()],
                verdict: proto::Verdict::Stale as i32,
                message: "heartbeat timeout detected by trustd".to_owned(),
                policy_action: "restart".to_owned(),
                source: "kubevirt/trustd".to_owned(),
            }))
            .await
            .expect_err("missing auth token should fail");

        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn update_latest_verdict_is_disabled_without_configured_token() {
        let service = new_service_with_update_token(None);

        let err = service
            .update_latest_verdict(Request::new(proto::UpdateLatestVerdictRequest {
                subjects: vec!["workload://wl-update".to_owned()],
                verdict: proto::Verdict::Stale as i32,
                message: "heartbeat timeout detected by trustd".to_owned(),
                policy_action: "restart".to_owned(),
                source: "kubevirt/trustd".to_owned(),
            }))
            .await
            .expect_err("disabled update path should fail");

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn update_latest_verdict_rejects_trusted_override() {
        let service = new_service();

        let err = service
            .update_latest_verdict(authenticated_update_request(
                proto::UpdateLatestVerdictRequest {
                    subjects: vec!["workload://wl-update".to_owned()],
                    verdict: proto::Verdict::Trusted as i32,
                    message: "manual trust".to_owned(),
                    policy_action: "none".to_owned(),
                    source: "kubevirt/trustd".to_owned(),
                },
            ))
            .await
            .expect_err("trusted override should fail");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
