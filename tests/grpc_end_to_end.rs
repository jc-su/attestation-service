use std::sync::Arc;

use attestation_service::policy_action_store::InMemoryPolicyActionStore;
use attestation_service::proto;
use attestation_service::quote_backend::{
    QuoteBackendConfig, QuoteBackendMode, QuoteVerifierBackend,
};
use attestation_service::refstore::{MemoryStore, ReferenceEntry, ReferenceStore};
use attestation_service::service::AttestationService;
use attestation_service::token::TokenIssuer;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Code, Request};

const TEST_UPDATE_LATEST_VERDICT_TOKEN: &str = "test-update-token";

async fn spawn_server() -> (
    proto::attestation_service_client::AttestationServiceClient<tonic::transport::Channel>,
    oneshot::Sender<()>,
) {
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
        TokenIssuer::from_secret("issuer", std::time::Duration::from_secs(60), vec![9_u8; 32])
            .expect("issuer should be created");
    let quote_backend = QuoteVerifierBackend::from_config(QuoteBackendConfig {
        mode: QuoteBackendMode::Insecure,
        dcap_library_path: None,
        ita_command: None,
        ita_args: Vec::new(),
    })
    .expect("backend should be created");
    let reference_store: Arc<dyn ReferenceStore> = store;
    let service = AttestationService::new(
        reference_store,
        Arc::new(InMemoryPolicyActionStore::new()),
        issuer,
        quote_backend,
        60,
        Some(Arc::<str>::from(TEST_UPDATE_LATEST_VERDICT_TOKEN)),
        "test",
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let address = listener
        .local_addr()
        .expect("local addr should be available");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        Server::builder()
            .add_service(proto::attestation_service_server::AttestationServiceServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should stop cleanly");
    });

    let endpoint = format!("http://{address}");
    let client = proto::attestation_service_client::AttestationServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    (client, shutdown_tx)
}

#[tokio::test]
async fn verify_workload_and_health_roundtrip() {
    let (mut client, shutdown_tx) = spawn_server().await;

    let health = client
        .health(proto::HealthRequest {})
        .await
        .expect("health should succeed")
        .into_inner();
    assert_eq!(health.status, "healthy");

    // Empty quote + empty event log → verifier returns Untrusted (no refs
    // match), but the RPC roundtrips and publishes the verdict.
    let verify = client
        .verify_workload(proto::VerifyWorkloadRequest {
            workload_id: "wl-1".to_owned(),
            nonce_hex: "ab".repeat(32),
            td_quote: Vec::new(),
            event_log: Vec::new(),
            peer_pk: Vec::new(),
        })
        .await
        .expect("verify_workload should succeed")
        .into_inner();
    assert_eq!(verify.verdict, proto::Verdict::Untrusted as i32);

    let latest = client
        .get_latest_verdict(proto::GetLatestVerdictRequest {
            subject: "workload://wl-1".to_owned(),
        })
        .await
        .expect("latest verdict should exist")
        .into_inner();
    assert_eq!(latest.verdict, verify.verdict);

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn update_latest_verdict_requires_auth_and_roundtrips() {
    let (mut client, shutdown_tx) = spawn_server().await;

    let err = client
        .update_latest_verdict(proto::UpdateLatestVerdictRequest {
            subjects: vec!["workload://wl-update".to_owned()],
            verdict: proto::Verdict::Stale as i32,
            message: "heartbeat timeout detected by trustd".to_owned(),
            policy_action: "restart".to_owned(),
            source: "kubevirt/trustd".to_owned(),
        })
        .await
        .expect_err("missing auth token should fail");
    assert_eq!(err.code(), Code::Unauthenticated);

    let mut request = Request::new(proto::UpdateLatestVerdictRequest {
        subjects: vec!["workload://wl-update".to_owned()],
        verdict: proto::Verdict::Stale as i32,
        message: "heartbeat timeout detected by trustd".to_owned(),
        policy_action: "restart".to_owned(),
        source: "kubevirt/trustd".to_owned(),
    });
    request.metadata_mut().insert(
        "x-attestation-update-token",
        TEST_UPDATE_LATEST_VERDICT_TOKEN
            .parse()
            .expect("test token should be valid metadata"),
    );

    let update = client
        .update_latest_verdict(request)
        .await
        .expect("authorized update should succeed")
        .into_inner();
    assert_eq!(update.updated, 1);

    let latest = client
        .get_latest_verdict(proto::GetLatestVerdictRequest {
            subject: "workload://wl-update".to_owned(),
        })
        .await
        .expect("latest verdict should exist")
        .into_inner();
    assert_eq!(latest.verdict, proto::Verdict::Stale as i32);
    assert_eq!(latest.policy_action, "restart");

    let _ = shutdown_tx.send(());
}
