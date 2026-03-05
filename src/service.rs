use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{RwLock, broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::warn;

use crate::policy_action_store::{PolicyAction, PolicyActionStore, PolicyCondition};
use crate::proto;
use crate::quote_backend::QuoteVerifierBackend;
use crate::refstore::{ReferenceEntry, ReferenceStore};
use crate::token::{TokenClaims, TokenIssuer};
use crate::verification_cache::{InFlightTurn, VerificationResultCache};
use crate::verifier::{MeasurementLog, TrustVerdict, VerificationResult, Verifier, VerifyRequest};

const VERDICT_SOURCE: &str = "attestation-service/verify_container_evidence";
const VERDICT_BROADCAST_CAPACITY: usize = 1024;

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
        self.entries
            .write()
            .await
            .insert(record.subject.clone(), record.clone());
        let _ = self.updates.send(record);
    }

    async fn get(&self, subject: &str) -> Option<VerdictRecord> {
        self.entries.read().await.get(subject).cloned()
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
}

pub struct AttestationService {
    verifier: Verifier<Arc<dyn ReferenceStore>>,
    store: Arc<dyn ReferenceStore>,
    policy_actions: Arc<dyn PolicyActionStore>,
    token_issuer: TokenIssuer,
    verdict_store: Arc<VerdictStore>,
    verify_cache: Arc<VerificationResultCache>,
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
        verify_cache_ttl: Duration,
        verify_cache_max_entries: usize,
        version: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            verifier: Verifier::new(Arc::clone(&store), quote_backend),
            store,
            policy_actions,
            token_issuer,
            verdict_store: Arc::new(VerdictStore::new(verdict_ttl_seconds)),
            verify_cache: Arc::new(VerificationResultCache::new(
                verify_cache_ttl,
                verify_cache_max_entries,
            )),
            version: version.into(),
            started_at: Instant::now(),
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

    fn build_token_claims(
        request: &proto::VerifyRequest,
        result: &VerificationResult,
        policy_action: PolicyAction,
    ) -> TokenClaims {
        TokenClaims {
            verdict: result.verdict.as_str().to_owned(),
            policy_action: policy_action.as_str().to_owned(),
            cgroup_path: request.cgroup_path.clone(),
            container_image: request.container_image.clone(),
            vmi_name: request.vmi_name.clone(),
            vmi_namespace: request.vmi_namespace.clone(),
            rtmr3: request.rtmr3.clone(),
            measurement_count: request.measurements.len() as i32,
            matched_count: result.matched_count,
            unknown_count: result.unknown_count,
            rtmr3_replay_valid: result.rtmr3_replay_valid,
            all_required_present: result.all_required_present,
            quote_verified: result.quote_signature_valid,
        }
    }

    fn resolve_policy_action(
        &self,
        request: &proto::VerifyRequest,
        verdict: TrustVerdict,
    ) -> PolicyAction {
        let condition = match verdict {
            TrustVerdict::Untrusted => PolicyCondition::Untrusted,
            TrustVerdict::Stale => PolicyCondition::Stale,
            TrustVerdict::Trusted | TrustVerdict::Unknown => return PolicyAction::None,
        };

        let mut identities = Vec::with_capacity(2);
        if !request.container_image.is_empty() {
            identities.push(request.container_image.clone());
        }
        if !request.cgroup_path.is_empty() {
            identities.push(format!("cgroup://{}", request.cgroup_path));
        }

        self.policy_actions.resolve_action(&identities, condition)
    }

    fn verdict_subjects(request: &proto::VerifyRequest) -> Vec<String> {
        let mut subjects = HashSet::new();

        if !request.cgroup_path.is_empty() {
            subjects.insert(format!("cgroup://{}", request.cgroup_path));
        }
        if !request.container_image.is_empty() {
            subjects.insert(request.container_image.clone());
        }

        let mut result = subjects.into_iter().collect::<Vec<_>>();
        result.sort();
        result
    }

    async fn publish_latest_verdict(
        &self,
        request: &proto::VerifyRequest,
        response: &proto::VerifyResponse,
    ) {
        let subjects = Self::verdict_subjects(request);
        if subjects.is_empty() {
            return;
        }

        let now = unix_seconds(SystemTime::now());
        let expires_at = now.saturating_add(self.verdict_store.ttl_seconds());

        for subject in subjects {
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
    }

    async fn evaluate_verify_request(
        &self,
        request: &proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, Status> {
        let verify_request = VerifyRequest {
            cgroup_path: request.cgroup_path.clone(),
            rtmr3_hex: request.rtmr3.clone(),
            initial_rtmr3_hex: request.initial_rtmr3.clone(),
            measurements: request
                .measurements
                .iter()
                .map(|measurement| MeasurementLog {
                    digest: measurement.digest.clone(),
                    filename: measurement.file.clone(),
                })
                .collect(),
            nonce_hex: request.nonce.clone(),
            report_data_hex: request.report_data.clone(),
            td_quote: request.td_quote.clone(),
            container_image: request.container_image.clone(),
        };

        let result = self
            .verifier
            .verify(&verify_request)
            .map_err(|error| Status::internal(format!("verification failed: {error}")))?;
        let policy_action = self.resolve_policy_action(request, result.verdict.clone());
        let policy_action_value = policy_action.as_str().to_owned();

        let attestation_token = if let Some(token) = result.attestation_token.clone() {
            token
        } else {
            let token_claims = Self::build_token_claims(request, &result, policy_action);
            match self.token_issuer.issue(&token_claims) {
                Ok(token) => token,
                Err(error) => {
                    warn!(error = %error, "token issuance failed; returning verdict without token");
                    String::new()
                }
            }
        };

        Ok(proto::VerifyResponse {
            verdict: Self::map_verdict(result.verdict),
            message: result.message,
            attestation_token,
            details: Some(proto::VerificationDetails {
                rtmr3_replay_valid: result.rtmr3_replay_valid,
                all_required_present: result.all_required_present,
                matched_count: result.matched_count,
                unknown_count: result.unknown_count,
                missing_count: result.missing_count,
                quote_signature_valid: result.quote_signature_valid,
                quote_verification_skipped: result.quote_verification_skipped,
                unknown_files: result.unknown_files,
                missing_files: result.missing_files,
            }),
            policy_action: policy_action_value,
        })
    }
}

#[tonic::async_trait]
impl proto::attestation_service_server::AttestationService for AttestationService {
    type WatchVerdictUpdatesStream = ReceiverStream<Result<proto::VerdictUpdate, Status>>;

    async fn verify_container_evidence(
        &self,
        request: Request<proto::VerifyRequest>,
    ) -> Result<Response<proto::VerifyResponse>, Status> {
        let request = request.into_inner();

        if request.cgroup_path.is_empty() {
            return Err(Status::invalid_argument("cgroup_path required"));
        }
        if request.rtmr3.is_empty() {
            return Err(Status::invalid_argument("rtmr3 required"));
        }
        let cache_key = self.verify_cache.key_for_request(&request);
        if let Some(cached) = self.verify_cache.get(cache_key).await {
            return Ok(Response::new(cached));
        }

        match self.verify_cache.begin(cache_key).await {
            InFlightTurn::Wait(rx) => match rx.await {
                Ok(Ok(response)) => return Ok(Response::new(response)),
                Ok(Err(message)) => return Err(Status::internal(message)),
                Err(_) => {
                    // Fall through and become leader if the original call was dropped.
                }
            },
            InFlightTurn::Leader => {}
        }

        match self.evaluate_verify_request(&request).await {
            Ok(response) => {
                self.publish_latest_verdict(&request, &response).await;
                self.verify_cache
                    .finish(cache_key, Ok(response.clone()))
                    .await;
                Ok(Response::new(response))
            }
            Err(error) => {
                self.verify_cache
                    .finish(cache_key, Err(error.message().to_owned()))
                    .await;
                Err(error)
            }
        }
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

        self.store
            .set(&request.container_image, entries)
            .map_err(|error| Status::internal(format!("set reference values failed: {error}")))?;
        self.verify_cache.invalidate_all().await;

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

        let values = self.store.get(&request.container_image).map_err(|error| {
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

    async fn get_latest_verdict(
        &self,
        request: Request<proto::GetLatestVerdictRequest>,
    ) -> Result<Response<proto::GetLatestVerdictResponse>, Status> {
        let request = request.into_inner();
        if request.subject.is_empty() {
            return Err(Status::invalid_argument("subject required"));
        }

        let Some(record) = self.verdict_store.get(&request.subject).await else {
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

        // Send current snapshot entries newer than after_version first.
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

        // Then stream live updates.
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
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Keep streaming the freshest updates.
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
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

    fn new_service() -> AttestationService {
        let store = Arc::new(MemoryStore::new());
        store
            .set(
                "img",
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
            std::time::Duration::from_secs(5),
            1024,
            "test",
        )
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
    async fn verify_rejects_empty_cgroup() {
        let service = new_service();
        let err = service
            .verify_container_evidence(Request::new(proto::VerifyRequest::default()))
            .await
            .expect_err("invalid request should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn verify_response_contains_policy_action_field() {
        let service = new_service();
        let response = service
            .verify_container_evidence(Request::new(proto::VerifyRequest {
                cgroup_path: "cg1".to_owned(),
                rtmr3: "00".repeat(48),
                initial_rtmr3: "00".repeat(48),
                ..proto::VerifyRequest::default()
            }))
            .await
            .expect("verify should succeed")
            .into_inner();

        assert_eq!(response.policy_action, "none");
    }

    #[tokio::test]
    async fn get_latest_verdict_returns_last_published_verdict() {
        let service = new_service();
        let verify_response = service
            .verify_container_evidence(Request::new(proto::VerifyRequest {
                cgroup_path: "cg1".to_owned(),
                rtmr3: "00".repeat(48),
                initial_rtmr3: "00".repeat(48),
                ..proto::VerifyRequest::default()
            }))
            .await
            .expect("verify should succeed")
            .into_inner();

        let latest = service
            .get_latest_verdict(Request::new(proto::GetLatestVerdictRequest {
                subject: "cgroup://cg1".to_owned(),
            }))
            .await
            .expect("latest verdict should exist")
            .into_inner();

        assert_eq!(latest.subject, "cgroup://cg1");
        assert_eq!(latest.verdict, verify_response.verdict);
        assert!(!latest.source.is_empty());
    }

    #[tokio::test]
    async fn verify_cache_hit_does_not_republish_verdict() {
        let service = new_service();
        let request = proto::VerifyRequest {
            cgroup_path: "cg-cache".to_owned(),
            rtmr3: "00".repeat(48),
            initial_rtmr3: "00".repeat(48),
            ..proto::VerifyRequest::default()
        };

        service
            .verify_container_evidence(Request::new(request.clone()))
            .await
            .expect("first verify should succeed");
        let first = service
            .get_latest_verdict(Request::new(proto::GetLatestVerdictRequest {
                subject: "cgroup://cg-cache".to_owned(),
            }))
            .await
            .expect("latest verdict should exist")
            .into_inner();

        service
            .verify_container_evidence(Request::new(request))
            .await
            .expect("second verify should succeed");
        let second = service
            .get_latest_verdict(Request::new(proto::GetLatestVerdictRequest {
                subject: "cgroup://cg-cache".to_owned(),
            }))
            .await
            .expect("latest verdict should exist")
            .into_inner();

        assert_eq!(first.version, second.version);
    }
}
