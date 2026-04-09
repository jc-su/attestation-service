use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use attestation_service::config::Config;
use attestation_service::policy_action_store::InMemoryPolicyActionStore;
use attestation_service::policy_sync::PolicyFileSync;
use attestation_service::proto;
use attestation_service::quote_backend::QuoteVerifierBackend;
use attestation_service::refstore::{PersistentFileStore, PolicyReferenceStore, ReferenceStore};
use attestation_service::service::AttestationService;
use attestation_service::token::TokenIssuer;
use clap::Parser;
use tokio::signal;
use tonic::transport::Server;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();
    let config = Config::parse();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        addr = %config.addr,
        "attestation-service starting"
    );

    let token_issuer = match &config.jwt_secret_path {
        Some(secret_path) => TokenIssuer::from_secret_file(
            config.token_issuer.clone(),
            config.token_ttl(),
            secret_path,
        )?,
        None => {
            warn!("no --jwt-secret-path provided; using random in-memory secret");
            TokenIssuer::random(config.token_issuer.clone(), config.token_ttl())?
        }
    };

    let store = Arc::new(PersistentFileStore::open(
        config.reference_store_path.clone(),
    )?);
    let reference_store: Arc<dyn ReferenceStore> = store.clone();
    let policy_store: Arc<dyn PolicyReferenceStore> = store;
    let policy_action_store = Arc::new(InMemoryPolicyActionStore::new());

    let quote_backend = QuoteVerifierBackend::from_config(config.quote_backend_config())?;
    let update_latest_verdict_token = load_optional_secret(
        config.update_latest_verdict_token_path.as_deref(),
        "--update-latest-verdict-token-path",
    )?;
    if update_latest_verdict_token.is_none() {
        warn!("no --update-latest-verdict-token-path provided; UpdateLatestVerdict is disabled");
    }
    let service = AttestationService::new(
        reference_store,
        policy_action_store.clone(),
        token_issuer,
        quote_backend,
        config.token_ttl_seconds as i64,
        config.verify_cache_ttl(),
        config.verify_cache_max_entries,
        update_latest_verdict_token,
        env!("CARGO_PKG_VERSION"),
    );

    let _policy_sync_handle = if !config.policy_file.is_empty() {
        let sync = Arc::new(PolicyFileSync::new(
            policy_store,
            policy_action_store,
            config.policy_file.clone(),
            config.policy_reload_interval(),
            Some(service.policy_reload_hooks()),
        ));
        match sync.sync_once().await {
            Ok(count) => info!(policy_count = count, "initial policy sync completed"),
            Err(error) => warn!(error = %error, "initial policy sync failed"),
        }
        Some(sync.start())
    } else {
        None
    };
    let grpc_service = proto::attestation_service_server::AttestationServiceServer::new(service);

    let listen_addr = config.addr.parse()?;
    Server::builder()
        .add_service(grpc_service)
        .serve_with_shutdown(listen_addr, shutdown_signal())
        .await
        .map_err(Box::<dyn Error>::from)
}

fn load_optional_secret(
    path: Option<&Path>,
    flag_name: &str,
) -> Result<Option<Arc<str>>, Box<dyn Error>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let value = std::fs::read_to_string(path)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{flag_name} file {} is empty", path.display()).into());
    }
    Ok(Some(Arc::<str>::from(trimmed)))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);
}
