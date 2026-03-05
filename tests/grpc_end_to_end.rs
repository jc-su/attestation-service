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

async fn spawn_server() -> (
    proto::attestation_service_client::AttestationServiceClient<tonic::transport::Channel>,
    oneshot::Sender<()>,
) {
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
        std::time::Duration::from_secs(5),
        1024,
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
async fn verify_and_health_roundtrip() {
    let (mut client, shutdown_tx) = spawn_server().await;

    let health = client
        .health(proto::HealthRequest {})
        .await
        .expect("health should succeed")
        .into_inner();
    assert_eq!(health.status, "healthy");

    let verify = client
        .verify_container_evidence(proto::VerifyRequest {
            cgroup_path: "cg1".to_owned(),
            vmi_name: String::new(),
            vmi_namespace: String::new(),
            rtmr3: "00".repeat(48),
            initial_rtmr3: "00".repeat(48),
            measurements: Vec::new(),
            nonce: "ab".repeat(32),
            report_data: String::new(),
            td_quote: Vec::new(),
            container_image: String::new(),
        })
        .await
        .expect("verify should succeed")
        .into_inner();
    assert_eq!(verify.verdict, proto::Verdict::Unknown as i32);
    assert_eq!(verify.policy_action, "none");

    let _ = shutdown_tx.send(());
}
