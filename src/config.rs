use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

use crate::quote_backend::{QuoteBackendConfig, QuoteBackendMode};

pub const DEFAULT_ADDR: &str = "0.0.0.0:50051";
pub const DEFAULT_ISSUER: &str = "trustfncall-attestation-service";
pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 300;
pub const DEFAULT_REFERENCE_STORE_PATH: &str = "/var/lib/trustfncall/reference-values.json";
pub const DEFAULT_POLICY_RELOAD_SECONDS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum QuoteVerifierBackend {
    Dcap,
    Ita,
    Insecure,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "attestation-service", about = "TrustFnCall verifier service")]
pub struct Config {
    /// gRPC listen address.
    #[arg(long, default_value = DEFAULT_ADDR)]
    pub addr: String,

    /// Quote verification backend.
    #[arg(long, value_enum, default_value_t = QuoteVerifierBackend::Dcap)]
    pub quote_verifier: QuoteVerifierBackend,

    /// Skip TD Quote signature verification (deprecated; equivalent to --quote-verifier insecure).
    #[arg(long, default_value_t = false)]
    pub insecure_skip_quote_verify: bool,

    /// Optional explicit path to libsgx_dcap_quoteverify shared library.
    #[arg(long)]
    pub dcap_library_path: Option<String>,

    /// Command for ITA verification mode. The command reads JSON request from stdin and writes JSON response to stdout.
    #[arg(long)]
    pub ita_command: Option<String>,

    /// Arguments passed to --ita-command.
    #[arg(long)]
    pub ita_arg: Vec<String>,

    /// JWT issuer name.
    #[arg(long, default_value = DEFAULT_ISSUER)]
    pub token_issuer: String,

    /// JWT token TTL in seconds.
    #[arg(long, default_value_t = DEFAULT_TOKEN_TTL_SECONDS)]
    pub token_ttl_seconds: u64,

    /// Optional path to a shared HS256 secret. If omitted, a random secret is used.
    #[arg(long)]
    pub jwt_secret_path: Option<PathBuf>,

    /// Optional path to a shared token authorizing UpdateLatestVerdict callers.
    #[arg(long)]
    pub update_latest_verdict_token_path: Option<PathBuf>,

    /// JSON file where manual reference values are persisted.
    #[arg(long, default_value = DEFAULT_REFERENCE_STORE_PATH)]
    pub reference_store_path: PathBuf,

    /// Path to AttestationPolicy YAML file(s). Can be repeated.
    #[arg(long)]
    pub policy_file: Vec<PathBuf>,

    /// Reload interval for --policy-file in seconds.
    #[arg(long, default_value_t = DEFAULT_POLICY_RELOAD_SECONDS)]
    pub policy_reload_seconds: u64,
}

impl Config {
    pub fn token_ttl(&self) -> Duration {
        Duration::from_secs(self.token_ttl_seconds)
    }

    pub fn quote_backend_config(&self) -> QuoteBackendConfig {
        let mode = if self.insecure_skip_quote_verify {
            QuoteBackendMode::Insecure
        } else {
            match self.quote_verifier {
                QuoteVerifierBackend::Dcap => QuoteBackendMode::Dcap,
                QuoteVerifierBackend::Ita => QuoteBackendMode::Ita,
                QuoteVerifierBackend::Insecure => QuoteBackendMode::Insecure,
            }
        };

        QuoteBackendConfig {
            mode,
            dcap_library_path: self.dcap_library_path.clone(),
            ita_command: self.ita_command.clone(),
            ita_args: self.ita_arg.clone(),
        }
    }

    pub fn policy_reload_interval(&self) -> Duration {
        Duration::from_secs(self.policy_reload_seconds)
    }
}
