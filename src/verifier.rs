use sha2::Sha256;
use sha2::{Digest, Sha384};

use crate::error::{Result, ServiceError};
use crate::quote::parse_tdx_quote;
use crate::quote_backend::{QuoteBackendInput, QuoteTrustLevel, QuoteVerifierBackend};
use crate::refstore::{ReferenceEntry, ReferenceStore};

pub const RTMR3_DIGEST_SIZE: usize = 48;
pub const MCP_PUBKEY_HASH_PREFIX: &str = "__mcp_pubkey_sha256__:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustVerdict {
    Trusted,
    Untrusted,
    Stale,
    Unknown,
}

impl TrustVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustVerdict::Trusted => "TRUSTED",
            TrustVerdict::Untrusted => "UNTRUSTED",
            TrustVerdict::Stale => "STALE",
            TrustVerdict::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasurementLog {
    pub digest: String,
    pub filename: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyRequest {
    pub cgroup_path: String,
    pub rtmr3_hex: String,
    pub initial_rtmr3_hex: String,
    pub measurements: Vec<MeasurementLog>,
    pub nonce_hex: String,
    pub report_data_hex: String,
    pub td_quote: Vec<u8>,
    pub container_image: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub verdict: TrustVerdict,
    pub message: String,
    pub rtmr3_replay_valid: bool,
    pub all_required_present: bool,
    pub matched_count: i32,
    pub unknown_count: i32,
    pub missing_count: i32,
    pub quote_signature_valid: bool,
    pub quote_verification_skipped: bool,
    pub unknown_files: Vec<String>,
    pub missing_files: Vec<String>,
    pub attestation_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MeasurementVerifyResult {
    all_required_present: bool,
    matched_count: i32,
    unknown_count: i32,
    missing_count: i32,
    unknown_files: Vec<String>,
    missing_files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReferenceCheckState {
    Verified { matched_identity: String },
    MissingReference(String),
}

#[derive(Debug, Clone)]
pub struct Verifier<S>
where
    S: ReferenceStore,
{
    ref_store: S,
    quote_backend: QuoteVerifierBackend,
}

impl<S> Verifier<S>
where
    S: ReferenceStore,
{
    pub fn new(ref_store: S, quote_backend: QuoteVerifierBackend) -> Self {
        Self {
            ref_store,
            quote_backend,
        }
    }

    pub fn verify(&self, req: &VerifyRequest) -> Result<VerificationResult> {
        if req.cgroup_path.is_empty() {
            return Err(ServiceError::InvalidInput(
                "cgroup_path is required".to_owned(),
            ));
        }
        if req.rtmr3_hex.is_empty() {
            return Err(ServiceError::InvalidInput("rtmr3 is required".to_owned()));
        }
        if req.initial_rtmr3_hex.is_empty() {
            return Err(ServiceError::InvalidInput(
                "initial_rtmr3 is required".to_owned(),
            ));
        }

        let expected_rtmr3 = decode_fixed_hex("rtmr3", &req.rtmr3_hex, RTMR3_DIGEST_SIZE)?;
        let mcp_pubkey_hash = parse_mcp_pubkey_hash(req.container_image.as_str())?;
        let expected_report_data_block = if req.report_data_hex.is_empty()
            && req.nonce_hex.is_empty()
            && req.td_quote.is_empty()
        {
            None
        } else if let Some(pubkey_hash) = mcp_pubkey_hash.as_ref() {
            Some(compute_expected_mcp_report_data_block(
                req.nonce_hex.as_str(),
                pubkey_hash,
            )?)
        } else {
            Some(compute_expected_report_data_block(
                req.nonce_hex.as_str(),
                req.rtmr3_hex.as_str(),
            )?)
        };

        let mut hard_failures = Vec::new();
        let mut stale_reasons = Vec::new();

        let (rtmr3_replay_valid, replay_message) = if req.measurements.is_empty() {
            (true, "no measurements in evidence".to_owned())
        } else {
            verify_rtmr3(
                &req.rtmr3_hex,
                &req.initial_rtmr3_hex,
                req.measurements.as_slice(),
            )?
        };
        if !rtmr3_replay_valid {
            hard_failures.push(replay_message);
        }

        let report_data_matches = if req.report_data_hex.is_empty() {
            true
        } else {
            let Some(expected_block) = expected_report_data_block.as_ref() else {
                return Err(ServiceError::InvalidInput(
                    "nonce is required when report_data is provided".to_owned(),
                ));
            };
            report_data_matches_expected(expected_block, req.report_data_hex.as_str())?
        };
        if !report_data_matches {
            hard_failures.push("reportdata binding mismatch".to_owned());
        }

        let mut measurement_result = MeasurementVerifyResult {
            all_required_present: true,
            matched_count: 0,
            unknown_count: 0,
            missing_count: 0,
            unknown_files: Vec::new(),
            missing_files: Vec::new(),
        };
        let lookup_identities = reference_lookup_identities(req);
        let mut lookup_errors = Vec::new();
        let mut matched_identity = None;
        let mut matched_values = None;

        for identity in lookup_identities {
            match self.ref_store.get(identity.as_str()) {
                Ok(values) => {
                    matched_identity = Some(identity);
                    matched_values = Some(values);
                    break;
                }
                Err(error) => {
                    lookup_errors.push(format!("{identity}: {error}"));
                }
            }
        }

        let reference_state =
            if let (Some(identity), Some(values)) = (matched_identity, matched_values) {
                measurement_result =
                    verify_measurements(req.measurements.as_slice(), values.entries.as_slice());
                if !measurement_result.all_required_present {
                    hard_failures.push(format!(
                        "{} required files missing",
                        measurement_result.missing_count
                    ));
                }
                if measurement_result.unknown_count > 0 {
                    hard_failures.push(format!(
                        "{} unknown files detected",
                        measurement_result.unknown_count
                    ));
                }
                ReferenceCheckState::Verified {
                    matched_identity: identity,
                }
            } else {
                measurement_result.all_required_present = false;
                ReferenceCheckState::MissingReference(lookup_errors.join("; "))
            };

        let mut quote_signature_valid = false;
        let mut quote_verification_skipped = req.td_quote.is_empty();
        let mut quote_attestation_token = None;
        if !req.td_quote.is_empty() {
            quote_verification_skipped = false;

            match parse_tdx_quote(req.td_quote.as_slice()) {
                Ok(parsed_quote) => {
                    if parsed_quote.rtmr3.as_slice() != expected_rtmr3.as_slice() {
                        hard_failures
                            .push("td quote RTMR3 does not match reported RTMR3".to_owned());
                    }

                    if let Some(expected_block) = expected_report_data_block.as_ref() {
                        if parsed_quote.report_data != *expected_block {
                            hard_failures.push(
                                "td quote reportdata does not match expected SHA384(nonce||rtmr3)"
                                    .to_owned(),
                            );
                        }
                    } else if mcp_pubkey_hash.is_some() {
                        hard_failures.push(
                            "nonce is required when td_quote is provided in MCP verifier mode"
                                .to_owned(),
                        );
                    } else {
                        hard_failures
                            .push("nonce is required when td_quote is provided".to_owned());
                    }
                }
                Err(error) => {
                    hard_failures.push(format!("malformed td quote: {error}"));
                }
            }

            match self.quote_backend.verify(&QuoteBackendInput {
                quote_bytes: req.td_quote.as_slice(),
                nonce_hex: req.nonce_hex.as_str(),
                rtmr3_hex: req.rtmr3_hex.as_str(),
                report_data_hex: req.report_data_hex.as_str(),
            }) {
                Ok(backend_result) => {
                    quote_signature_valid = backend_result.signature_valid;
                    quote_verification_skipped = backend_result.verification_skipped;
                    quote_attestation_token = backend_result.attestation_token;

                    match backend_result.trust_level {
                        QuoteTrustLevel::Trusted => {}
                        QuoteTrustLevel::Stale => stale_reasons.push(backend_result.message),
                        QuoteTrustLevel::Untrusted => hard_failures.push(format!(
                            "TD Quote verification failed: {}",
                            backend_result.message
                        )),
                    }
                }
                Err(error) => {
                    hard_failures.push(format!("TD Quote verification backend error: {error}"));
                }
            }
        }

        if mcp_pubkey_hash.is_none()
            && req.measurements.is_empty()
            && req.rtmr3_hex.eq_ignore_ascii_case(&req.initial_rtmr3_hex)
        {
            stale_reasons
                .push("no measurements recorded (container may not have started)".to_owned());
        }

        let (mut verdict, mut message) = if !hard_failures.is_empty() {
            (
                TrustVerdict::Untrusted,
                format!("verification failed: {}", hard_failures.join("; ")),
            )
        } else if mcp_pubkey_hash.is_some() {
            if !stale_reasons.is_empty() {
                (
                    TrustVerdict::Stale,
                    format!(
                        "MCP verifier checks passed with stale quote backend state: {}",
                        stale_reasons.join("; "),
                    ),
                )
            } else {
                (
                    TrustVerdict::Trusted,
                    "MCP verifier checks passed: quote + reportdata key-binding verified"
                        .to_owned(),
                )
            }
        } else {
            match reference_state {
                ReferenceCheckState::MissingReference(error) => (
                    TrustVerdict::Unknown,
                    format!(
                        "no reference values matched evidence identity (image='{}', cgroup='{}'): {error}",
                        req.container_image, req.cgroup_path
                    ),
                ),
                ReferenceCheckState::Verified { matched_identity } if !stale_reasons.is_empty() => {
                    (
                        TrustVerdict::Stale,
                        format!(
                            "verification passed with stale state for {matched_identity}: {}",
                            stale_reasons.join("; "),
                        ),
                    )
                }
                ReferenceCheckState::Verified { matched_identity } => (
                    TrustVerdict::Trusted,
                    format!(
                        "all checks passed for {matched_identity}: {} measurements verified",
                        measurement_result.matched_count,
                    ),
                ),
            }
        };

        if req.td_quote.is_empty() && matches!(verdict, TrustVerdict::Trusted | TrustVerdict::Stale)
        {
            verdict = TrustVerdict::Unknown;
            message = format!("{message}; td quote missing; attestation trust requires a TD quote");
        }

        Ok(VerificationResult {
            verdict,
            message,
            rtmr3_replay_valid,
            all_required_present: measurement_result.all_required_present,
            matched_count: measurement_result.matched_count,
            unknown_count: measurement_result.unknown_count,
            missing_count: measurement_result.missing_count,
            quote_signature_valid,
            quote_verification_skipped,
            unknown_files: measurement_result.unknown_files,
            missing_files: measurement_result.missing_files,
            attestation_token: quote_attestation_token,
        })
    }
}

fn parse_mcp_pubkey_hash(container_image: &str) -> Result<Option<[u8; 32]>> {
    if !container_image.starts_with(MCP_PUBKEY_HASH_PREFIX) {
        return Ok(None);
    }
    let hex_part = container_image
        .strip_prefix(MCP_PUBKEY_HASH_PREFIX)
        .unwrap_or_default();
    let decoded = decode_fixed_hex("mcp_pubkey_hash", hex_part, 32)?;
    let mut value = [0_u8; 32];
    value.copy_from_slice(decoded.as_slice());
    Ok(Some(value))
}

fn compute_expected_mcp_report_data_block(
    nonce_hex: &str,
    pubkey_hash: &[u8; 32],
) -> Result<[u8; 64]> {
    if nonce_hex.is_empty() {
        return Err(ServiceError::InvalidInput(
            "nonce is required for MCP reportdata binding".to_owned(),
        ));
    }

    let nonce = hex::decode(nonce_hex)
        .map_err(|error| ServiceError::Parse(format!("decode nonce: {error}")))?;
    let mut block = [0_u8; 64];
    let nonce_digest = Sha256::digest(nonce);
    block[..32].copy_from_slice(nonce_digest.as_slice());
    block[32..64].copy_from_slice(pubkey_hash);
    Ok(block)
}

fn report_data_matches_expected(expected_block: &[u8; 64], provided_hex: &str) -> Result<bool> {
    let provided = hex::decode(provided_hex)
        .map_err(|error| ServiceError::Parse(format!("decode report_data: {error}")))?;
    match provided.len() {
        RTMR3_DIGEST_SIZE => Ok(provided == expected_block[..RTMR3_DIGEST_SIZE]),
        64 => Ok(provided == expected_block),
        other => Err(ServiceError::InvalidInput(format!(
            "report_data must be 48 or 64 bytes, got {other}"
        ))),
    }
}

fn reference_lookup_identities(req: &VerifyRequest) -> Vec<String> {
    let mut identities = Vec::with_capacity(2);
    if !req.container_image.is_empty() {
        identities.push(req.container_image.clone());
    }

    if !req.cgroup_path.is_empty() {
        let cgroup_identity = format!("cgroup://{}", req.cgroup_path);
        if identities.iter().all(|value| value != &cgroup_identity) {
            identities.push(cgroup_identity);
        }
    }

    identities
}

fn verify_rtmr3(
    reported_rtmr3_hex: &str,
    initial_rtmr3_hex: &str,
    measurements: &[MeasurementLog],
) -> Result<(bool, String)> {
    let computed = replay_rtmr3(initial_rtmr3_hex, measurements)?;
    if computed.eq_ignore_ascii_case(reported_rtmr3_hex) {
        Ok((true, "RTMR3 replay matches reported value".to_owned()))
    } else {
        Ok((
            false,
            format!(
                "RTMR3 mismatch: reported={} computed={}",
                reported_rtmr3_hex, computed
            ),
        ))
    }
}

/// Replays RTMR3 from initial value and measurements.
///
/// # Examples
///
/// ```
/// use attestation_service::verifier::{replay_rtmr3, MeasurementLog};
///
/// let initial = "00".repeat(48);
/// let replayed = replay_rtmr3(
///     initial.as_str(),
///     &[MeasurementLog {
///         digest: "01".repeat(48),
///         filename: "/a".to_owned(),
///     }],
/// )
/// .expect("replay should work");
/// assert_eq!(replayed.len(), 96);
/// ```
pub fn replay_rtmr3(initial_rtmr3_hex: &str, measurements: &[MeasurementLog]) -> Result<String> {
    let initial = decode_fixed_hex("initial_rtmr3", initial_rtmr3_hex, RTMR3_DIGEST_SIZE)?;

    let mut current = [0_u8; RTMR3_DIGEST_SIZE];
    current.copy_from_slice(initial.as_slice());

    for (index, measurement) in measurements.iter().enumerate() {
        let digest = hex::decode(&measurement.digest).map_err(|error| {
            ServiceError::Parse(format!("decode measurement {index} digest: {error}"))
        })?;

        let mut padded = [0_u8; RTMR3_DIGEST_SIZE];
        let copy_len = digest.len().min(RTMR3_DIGEST_SIZE);
        padded[..copy_len].copy_from_slice(&digest[..copy_len]);

        let mut hasher = Sha384::new();
        hasher.update(current);
        hasher.update(padded);
        let hash = hasher.finalize();
        current.copy_from_slice(hash.as_slice());
    }

    Ok(hex::encode(current))
}

fn verify_measurements(
    measurements: &[MeasurementLog],
    references: &[ReferenceEntry],
) -> MeasurementVerifyResult {
    let mut ref_map = std::collections::HashMap::with_capacity(references.len());
    for entry in references {
        ref_map.insert(entry.filename.as_str(), entry);
    }

    let mut seen = std::collections::HashSet::new();
    let mut result = MeasurementVerifyResult {
        all_required_present: true,
        matched_count: 0,
        unknown_count: 0,
        missing_count: 0,
        unknown_files: Vec::new(),
        missing_files: Vec::new(),
    };

    for measurement in measurements {
        match ref_map.get(measurement.filename.as_str()) {
            Some(reference)
                if measurement
                    .digest
                    .eq_ignore_ascii_case(&reference.expected_digest) =>
            {
                result.matched_count += 1;
                seen.insert(reference.filename.as_str());
            }
            Some(reference) => {
                result.unknown_count += 1;
                result
                    .unknown_files
                    .push(format!("{} (digest mismatch)", reference.filename));
            }
            None => {
                result.unknown_count += 1;
                result.unknown_files.push(measurement.filename.clone());
            }
        }
    }

    for reference in references {
        if reference.required && !seen.contains(reference.filename.as_str()) {
            result.missing_count += 1;
            result.missing_files.push(reference.filename.clone());
            result.all_required_present = false;
        }
    }

    result
}

fn decode_fixed_hex(field: &str, value: &str, expected_len: usize) -> Result<Vec<u8>> {
    let decoded = hex::decode(value)
        .map_err(|error| ServiceError::Parse(format!("decode {field}: {error}")))?;
    if decoded.len() != expected_len {
        return Err(ServiceError::InvalidInput(format!(
            "{field} must be {expected_len} bytes, got {}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

fn compute_expected_report_data_block(nonce_hex: &str, rtmr3_hex: &str) -> Result<[u8; 64]> {
    if nonce_hex.is_empty() {
        return Err(ServiceError::InvalidInput(
            "nonce is required for reportdata binding".to_owned(),
        ));
    }

    let nonce = hex::decode(nonce_hex)
        .map_err(|error| ServiceError::Parse(format!("decode nonce: {error}")))?;
    let rtmr3 = decode_fixed_hex("rtmr3", rtmr3_hex, RTMR3_DIGEST_SIZE)?;

    let mut hasher = Sha384::new();
    hasher.update(nonce);
    hasher.update(rtmr3);
    let digest = hasher.finalize();

    let mut block = [0_u8; 64];
    block[..RTMR3_DIGEST_SIZE].copy_from_slice(digest.as_slice());
    Ok(block)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sha2::{Digest, Sha256};

    use crate::quote_backend::{QuoteBackendConfig, QuoteBackendMode, QuoteVerifierBackend};
    use crate::refstore::{MemoryStore, ReferenceEntry, ReferenceStore};

    use super::{
        MCP_PUBKEY_HASH_PREFIX, MeasurementLog, RTMR3_DIGEST_SIZE, TrustVerdict, Verifier,
        VerifyRequest, replay_rtmr3,
    };

    fn insecure_backend() -> QuoteVerifierBackend {
        QuoteVerifierBackend::from_config(QuoteBackendConfig {
            mode: QuoteBackendMode::Insecure,
            dcap_library_path: None,
            ita_command: None,
            ita_args: Vec::new(),
        })
        .expect("backend should be created")
    }

    fn build_v4_quote(rtmr3: &[u8; 48], report_data: &[u8; 64]) -> Vec<u8> {
        let mut quote = vec![0_u8; 48 + 584 + 4 + 16];
        quote[0..2].copy_from_slice(&4_u16.to_le_bytes());
        quote[4..8].copy_from_slice(&0x0000_0081_u32.to_le_bytes());
        quote[48 + 472..48 + 520].copy_from_slice(rtmr3.as_slice());
        quote[48 + 520..48 + 584].copy_from_slice(report_data.as_slice());
        quote[48 + 584..48 + 588].copy_from_slice(&16_u32.to_le_bytes());
        quote
    }

    #[test]
    fn replay_produces_expected_length() {
        let replayed = replay_rtmr3("00".repeat(48).as_str(), &[]).expect("replay should work");
        assert_eq!(replayed.len(), 96);
    }

    #[test]
    fn verifier_reports_unknown_without_reference_values() {
        let store = Arc::new(MemoryStore::new());
        let verifier = Verifier::new(Arc::clone(&store), insecure_backend());
        let initial = "00".repeat(48);
        let measurements = vec![MeasurementLog {
            digest: "01".repeat(48),
            filename: "/a".to_owned(),
        }];
        let rtmr3 =
            replay_rtmr3(initial.as_str(), measurements.as_slice()).expect("replay should work");

        let result = verifier
            .verify(&VerifyRequest {
                cgroup_path: "cg1".to_owned(),
                rtmr3_hex: rtmr3,
                initial_rtmr3_hex: initial,
                measurements,
                nonce_hex: "ab".repeat(32),
                report_data_hex: String::new(),
                td_quote: Vec::new(),
                container_image: "img".to_owned(),
            })
            .expect("verification should return a result");

        assert_eq!(result.verdict, TrustVerdict::Unknown);
    }

    #[test]
    fn verifier_reports_unknown_when_image_missing() {
        let store = Arc::new(MemoryStore::new());
        let verifier = Verifier::new(Arc::clone(&store), insecure_backend());

        let result = verifier
            .verify(&VerifyRequest {
                cgroup_path: "cg1".to_owned(),
                rtmr3_hex: "00".repeat(48),
                initial_rtmr3_hex: "00".repeat(48),
                measurements: Vec::new(),
                nonce_hex: String::new(),
                report_data_hex: String::new(),
                td_quote: Vec::new(),
                container_image: String::new(),
            })
            .expect("verification should return a result");

        assert_eq!(result.verdict, TrustVerdict::Unknown);
    }

    #[test]
    fn verifier_requires_td_quote_when_cgroup_reference_matches() {
        let store = Arc::new(MemoryStore::new());
        store
            .set(
                "cgroup://cg1",
                vec![ReferenceEntry {
                    filename: "/a".to_owned(),
                    expected_digest: "01".repeat(48),
                    required: true,
                }],
            )
            .expect("set should succeed");

        let verifier = Verifier::new(Arc::clone(&store), insecure_backend());
        let initial = "00".repeat(48);
        let measurements = vec![MeasurementLog {
            digest: "01".repeat(48),
            filename: "/a".to_owned(),
        }];
        let rtmr3 =
            replay_rtmr3(initial.as_str(), measurements.as_slice()).expect("replay should work");

        let result = verifier
            .verify(&VerifyRequest {
                cgroup_path: "cg1".to_owned(),
                rtmr3_hex: rtmr3,
                initial_rtmr3_hex: initial,
                measurements,
                nonce_hex: "ab".repeat(32),
                report_data_hex: String::new(),
                td_quote: Vec::new(),
                container_image: String::new(),
            })
            .expect("verification should succeed");

        assert_eq!(result.verdict, TrustVerdict::Unknown);
        assert!(result.message.contains("td quote missing"));
    }

    #[test]
    fn verifier_requires_td_quote_even_when_reference_matches() {
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

        let verifier = Verifier::new(Arc::clone(&store), insecure_backend());
        let initial = "00".repeat(48);
        let measurements = vec![MeasurementLog {
            digest: "01".repeat(48),
            filename: "/a".to_owned(),
        }];
        let rtmr3 =
            replay_rtmr3(initial.as_str(), measurements.as_slice()).expect("replay should work");

        let result = verifier
            .verify(&VerifyRequest {
                cgroup_path: "cg1".to_owned(),
                rtmr3_hex: rtmr3,
                initial_rtmr3_hex: initial,
                measurements,
                nonce_hex: "ab".repeat(32),
                report_data_hex: String::new(),
                td_quote: Vec::new(),
                container_image: "img".to_owned(),
            })
            .expect("verification should succeed");

        assert_eq!(result.verdict, TrustVerdict::Unknown);
        assert!(result.message.contains("td quote missing"));
    }

    #[test]
    fn quote_binding_mismatch_is_untrusted() {
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

        let verifier = Verifier::new(Arc::clone(&store), insecure_backend());
        let initial = "00".repeat(48);
        let measurements = vec![MeasurementLog {
            digest: "01".repeat(48),
            filename: "/a".to_owned(),
        }];
        let rtmr3 =
            replay_rtmr3(initial.as_str(), measurements.as_slice()).expect("replay should work");
        let nonce = "ab".repeat(32);
        let mut expected_report_data = [0_u8; 64];
        expected_report_data[..RTMR3_DIGEST_SIZE].fill(0x44);
        let mut quote_rtmr3 = [0_u8; 48];
        quote_rtmr3.fill(0x11);
        let quote = build_v4_quote(&quote_rtmr3, &expected_report_data);

        let result = verifier
            .verify(&VerifyRequest {
                cgroup_path: "cg1".to_owned(),
                rtmr3_hex: rtmr3,
                initial_rtmr3_hex: initial,
                measurements,
                nonce_hex: nonce,
                report_data_hex: String::new(),
                td_quote: quote,
                container_image: "img".to_owned(),
            })
            .expect("verification should succeed");

        assert_eq!(result.verdict, TrustVerdict::Untrusted);
        assert!(result.message.contains("RTMR3"));
    }

    #[test]
    fn mcp_mode_accepts_sha256_nonce_pubkey_reportdata_without_reference_values() {
        let store = Arc::new(MemoryStore::new());
        let verifier = Verifier::new(Arc::clone(&store), insecure_backend());

        let mut rtmr3 = [0_u8; 48];
        rtmr3.fill(0x11);

        let nonce_hex = "ab".repeat(32);
        let nonce = hex::decode(nonce_hex.as_str()).expect("nonce hex should decode");
        let pubkey = b"mock-mcp-public-key";
        let pubkey_hash = Sha256::digest(pubkey);

        let mut report_data = [0_u8; 64];
        let nonce_digest = Sha256::digest(nonce);
        report_data[..32].copy_from_slice(nonce_digest.as_slice());
        report_data[32..64].copy_from_slice(pubkey_hash.as_slice());

        let quote = build_v4_quote(&rtmr3, &report_data);

        let result = verifier
            .verify(&VerifyRequest {
                cgroup_path: "cg1".to_owned(),
                rtmr3_hex: hex::encode(rtmr3),
                initial_rtmr3_hex: "00".repeat(48),
                measurements: Vec::new(),
                nonce_hex,
                report_data_hex: hex::encode(report_data),
                td_quote: quote,
                container_image: format!("{}{}", MCP_PUBKEY_HASH_PREFIX, hex::encode(pubkey_hash)),
            })
            .expect("verification should succeed");

        assert_eq!(result.verdict, TrustVerdict::Trusted);
    }
}
