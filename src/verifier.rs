use sha2::{Digest, Sha384};

use crate::error::{Result, ServiceError};
use crate::quote_backend::{QuoteBackendInput, QuoteVerifierBackend};
use crate::refstore::ReferenceStore;

pub const RTMR3_DIGEST_SIZE: usize = 48;

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

#[derive(Clone)]
pub struct Verifier<S>
where
    S: ReferenceStore,
{
    ref_store: S,
    quote_backend: QuoteVerifierBackend,
    /// Optional TCB reference store. When present, verify_workload rejects
    /// evidence whose RTMR[2] is not in the TCB allow-list.
    tcb_store: Option<std::sync::Arc<dyn crate::refstore::TcbReferenceStore>>,
}

impl<S> std::fmt::Debug for Verifier<S>
where
    S: ReferenceStore + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("ref_store", &self.ref_store)
            .field("quote_backend", &self.quote_backend)
            .field("tcb_store", &self.tcb_store.is_some())
            .finish()
    }
}

/// Canonical per-workload evidence payload. Matches trustd's
/// AttestWorkloadResponse 1:1.
#[derive(Debug, Clone)]
pub struct WorkloadVerifyRequest {
    /// Stable workload identity — the refstore lookup key.
    pub workload_id: String,
    /// Raw TDX quote bytes.
    pub td_quote: Vec<u8>,
    /// Bytes of the kernel's per-container event log at
    /// /sys/kernel/security/ima/container_rtmr/<mangled-cgroup>.
    /// One JSON object per file (terminated by `]}\n`).
    pub event_log: Vec<u8>,
    /// Verifier-chosen nonce (hex). Must match what trustd's
    /// AttestWorkloadRequest carried.
    pub nonce_hex: String,
    /// Peer public key bytes (empty = no peer binding).
    pub peer_pk: Vec<u8>,
}

/// Structured verdict with per-check breakdown — reviewers and
/// operators see exactly which subcheck failed.
#[derive(Debug, Clone)]
pub struct WorkloadVerifyResult {
    pub verdict: TrustVerdict,
    pub quote_signature_valid: bool,
    pub quote_verification_skipped: bool,
    /// MRTD + RTMR[0..2] in quote match TcbReferenceValues. True if
    /// tcb_store is None (check skipped) or all populated TCB fields
    /// match at least one entry's allow-list.
    pub tcb_matches: bool,
    /// report_data == SHA384(nonce) || SHA384(peer_pk or 0s).
    pub report_data_valid: bool,
    pub matched_count: i32,
    pub unknown_count: i32,
    pub missing_count: i32,
    pub all_required_present: bool,
    pub unknown_files: Vec<String>,
    pub missing_files: Vec<String>,
    pub message: String,
    /// Hex-encoded MRTD parsed from quote (for JWT claim emission).
    pub mrtd_hex: Option<String>,
    /// Hex-encoded RTMR[0..3] parsed from quote (for JWT claim emission).
    pub rtmr0_hex: Option<String>,
    pub rtmr1_hex: Option<String>,
    pub rtmr2_hex: Option<String>,
    pub rtmr3_hex: Option<String>,
    /// Cgroup path parsed from the per-container event log header
    /// (for JWT claim emission).  Empty when event log is not available.
    pub cgroup_path: String,
    /// Per-stage wall time in microseconds for verify_workload's four
    /// internal stages: dcap_verify, tcb_match, report_data, eventlog_replay.
    /// Service-level callers append jwt_sign + verify_total before logging.
    /// Internal-only (not exposed on the wire).
    pub stage_us: Vec<(&'static str, u64)>,
}

impl<S> Verifier<S>
where
    S: ReferenceStore,
{
    pub fn new(ref_store: S, quote_backend: QuoteVerifierBackend) -> Self {
        Self {
            ref_store,
            quote_backend,
            tcb_store: None,
        }
    }

    /// Builder-style: attach a TCB reference store. Required for the
    /// canonical verify_workload flow's RTMR[2] check; without it, the
    /// check is skipped (fail-open on that dimension).
    pub fn with_tcb_store(
        mut self,
        store: std::sync::Arc<dyn crate::refstore::TcbReferenceStore>,
    ) -> Self {
        self.tcb_store = Some(store);
        self
    }

    pub fn ref_store(&self) -> &S {
        &self.ref_store
    }

    /// Canonical per-workload verification matching the current kernel
    /// design (interleaved HW RTMR[3] + per-container event log in
    /// securityfs). Three independent checks must all pass:
    ///
    ///   1. Quote signature (DCAP / ITA) — the quote came from genuine
    ///      TDX hardware.
    ///   2. Quote's RTMR[2] matches a TCB reference — the kernel that
    ///      wrote the event log is genuine, so the log is trustworthy.
    ///   3. Quote's report_data equals `SHA384(nonce) || SHA384(pk)`
    ///      (or `SHA384(nonce) || 0s` when peer_pk is empty) — freshness
    ///      + channel binding.
    ///
    /// Plus the per-workload measurement replay against the refstore.
    ///
    /// Notably absent: RTMR[3] replay. The kernel's HW RTMR[3] is now
    /// a shared interleaved chain across all containers in the CVM and
    /// cannot be replayed per-container by construction. Trust in the
    /// per-container log comes from check (2).
    pub fn verify_workload(&self, req: &WorkloadVerifyRequest) -> Result<WorkloadVerifyResult> {
        if req.workload_id.is_empty() {
            return Err(ServiceError::InvalidInput(
                "workload_id is required".to_owned(),
            ));
        }
        if req.nonce_hex.is_empty() {
            return Err(ServiceError::InvalidInput(
                "nonce_hex is required".to_owned(),
            ));
        }
        let nonce_bytes = hex::decode(&req.nonce_hex)
            .map_err(|_| ServiceError::InvalidInput("nonce_hex must be valid hex".to_owned()))?;

        let mut hard_failures: Vec<String> = Vec::new();
        let mut stage_us: Vec<(&'static str, u64)> = Vec::with_capacity(6);

        // --- Check 1: quote signature ---
        let t0 = std::time::Instant::now();
        let (quote_signature_valid, quote_verification_skipped, parsed_quote) =
            if req.td_quote.is_empty() {
                (false, true, None)
            } else {
                let input = QuoteBackendInput {
                    quote_bytes: req.td_quote.as_slice(),
                    nonce_hex: "",
                    rtmr3_hex: "",
                    report_data_hex: "",
                };
                let outcome = self.quote_backend.verify(&input)?;
                if !outcome.signature_valid && !outcome.verification_skipped {
                    hard_failures.push("td quote signature verification failed".into());
                }
                (outcome.signature_valid, outcome.verification_skipped, Some(outcome))
            };
        stage_us.push(("dcap_verify", t0.elapsed().as_micros() as u64));

        // --- Check 2: TCB ∈ TCB references ---
        // Each populated field on the TCB ref-set must match the quote's
        // value. Empty allow-lists mean "skip this measurement". The
        // matching ref-set is selected as a self-consistent tuple — see
        // `TcbReferenceStore::measurement_allowed`.
        let t1 = std::time::Instant::now();
        let tcb_matches = match (&self.tcb_store, &parsed_quote) {
            (None, _) => true, // not configured → skip
            (Some(_), None) => {
                hard_failures.push(
                    "tcb store configured but no quote was supplied; cannot verify kernel".into(),
                );
                false
            }
            (Some(store), Some(q)) => {
                let mrtd = q.mrtd_hex_opt();
                let r0 = q.rtmr0_hex_opt();
                let r1 = q.rtmr1_hex_opt();
                let r2 = q.rtmr2_hex_opt();
                let mut ok = true;
                if !store.allows_mrtd(mrtd.as_deref())? {
                    hard_failures.push(format!(
                        "MRTD={} not in TCB reference set",
                        mrtd.as_deref().unwrap_or("<unparsed>")
                    ));
                    ok = false;
                }
                if !store.allows_rtmr0(r0.as_deref())? {
                    hard_failures.push(format!(
                        "RTMR[0]={} not in TCB reference set",
                        r0.as_deref().unwrap_or("<unparsed>")
                    ));
                    ok = false;
                }
                if !store.allows_rtmr1(r1.as_deref())? {
                    hard_failures.push(format!(
                        "RTMR[1]={} not in TCB reference set",
                        r1.as_deref().unwrap_or("<unparsed>")
                    ));
                    ok = false;
                }
                if !store.allows_rtmr2(r2.as_deref())? {
                    hard_failures.push(format!(
                        "RTMR[2]={} not in TCB reference set",
                        r2.as_deref().unwrap_or("<unparsed>")
                    ));
                    ok = false;
                }
                ok
            }
        };

        stage_us.push(("tcb_match", t1.elapsed().as_micros() as u64));

        // --- Check 3: report_data binding ---
        // Expected: SHA384(nonce)[..32] || SHA384(peer_pk)[..32] (or 0s).
        let t2 = std::time::Instant::now();
        let mut expected_report_data = [0_u8; 64];
        let nonce_hash = Sha384::digest(&nonce_bytes);
        expected_report_data[..32].copy_from_slice(&nonce_hash[..32]);
        if !req.peer_pk.is_empty() {
            let pk_hash = Sha384::digest(&req.peer_pk);
            expected_report_data[32..].copy_from_slice(&pk_hash[..32]);
        }
        let report_data_valid = match &parsed_quote {
            None => true, // no quote parsed → caller must skip explicitly
            Some(q) => match q.report_data_hex_opt() {
                Some(rd_hex) => {
                    let rd = hex::decode(&rd_hex).unwrap_or_default();
                    if rd.as_slice() != expected_report_data.as_slice() {
                        hard_failures.push(
                            "quote report_data does not match SHA384(nonce)||SHA384(peer_pk)"
                                .into(),
                        );
                        false
                    } else {
                        true
                    }
                }
                None => {
                    hard_failures.push("quote does not expose report_data".into());
                    false
                }
            },
        };

        stage_us.push(("report_data", t2.elapsed().as_micros() as u64));

        // --- Per-workload measurement replay ---
        let t3 = std::time::Instant::now();
        let parsed_log = parse_event_log(&req.event_log)?;
        let measurements = parsed_log.measurements;
        let cgroup_path = parsed_log.cgroup;
        let mut matched_count = 0_i32;
        let mut unknown_count = 0_i32;
        let mut missing_count = 0_i32;
        let mut unknown_files: Vec<String> = Vec::new();
        let mut missing_files: Vec<String> = Vec::new();
        let mut all_required_present = true;

        let mut drift_count = 0_i32;
        let mut drift_files: Vec<String> = Vec::new();
        match self.ref_store.get(&req.workload_id) {
            Ok(refs) => {
                let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
                for m in &measurements {
                    let matched = refs.entries.iter().find(|e| {
                        e.filename == m.filename
                            && e.expected_digest.eq_ignore_ascii_case(&m.digest)
                    });
                    if let Some(e) = matched {
                        matched_count += 1;
                        seen.insert(e.filename.as_str());
                    } else {
                        // Strict-mode drift detection: a measurement whose
                        // filename matches a tracked reference but whose
                        // digest does not match is drift, not just unknown.
                        // (Drift = post-attestation file mutation, the
                        // exact case TrustFnCall E1b is designed to catch.)
                        let filename_tracked = refs
                            .entries
                            .iter()
                            .any(|e| e.filename == m.filename);
                        if filename_tracked {
                            drift_count += 1;
                            let preview = if m.digest.len() >= 16 {
                                &m.digest[..16]
                            } else {
                                m.digest.as_str()
                            };
                            drift_files.push(format!("{}@{}", m.filename, preview));
                        } else {
                            unknown_count += 1;
                            unknown_files.push(m.filename.clone());
                        }
                    }
                }
                for e in &refs.entries {
                    if e.required && !seen.contains(e.filename.as_str()) {
                        missing_count += 1;
                        missing_files.push(e.filename.clone());
                        all_required_present = false;
                    }
                }
            }
            Err(ServiceError::NotFound(_)) => {
                hard_failures.push(format!(
                    "no reference values for workload_id='{}'",
                    req.workload_id
                ));
            }
            Err(other) => return Err(other),
        }

        if !all_required_present {
            hard_failures.push(format!("{} required reference file(s) missing", missing_count));
        }
        if drift_count > 0 {
            hard_failures.push(format!(
                "{} drifted measurement(s): {}",
                drift_count,
                drift_files.join(", ")
            ));
        }
        stage_us.push(("eventlog_replay", t3.elapsed().as_micros() as u64));

        let verdict = if hard_failures.is_empty() {
            TrustVerdict::Trusted
        } else {
            TrustVerdict::Untrusted
        };
        let message = if hard_failures.is_empty() {
            "all checks passed".into()
        } else {
            hard_failures.join("; ")
        };

        let (mrtd_hex, rtmr0_hex, rtmr1_hex, rtmr2_hex, rtmr3_hex) = match &parsed_quote {
            Some(q) => (
                q.mrtd_hex_opt(),
                q.rtmr0_hex_opt(),
                q.rtmr1_hex_opt(),
                q.rtmr2_hex_opt(),
                q.rtmr3_hex_opt(),
            ),
            None => (None, None, None, None, None),
        };
        Ok(WorkloadVerifyResult {
            verdict,
            quote_signature_valid,
            quote_verification_skipped,
            tcb_matches,
            report_data_valid,
            matched_count,
            unknown_count,
            missing_count,
            all_required_present,
            unknown_files,
            missing_files,
            message,
            mrtd_hex,
            rtmr0_hex,
            rtmr1_hex,
            rtmr2_hex,
            rtmr3_hex,
            cgroup_path,
            stage_us,
        })
    }
}

/// Parsed per-container event log: header (`cgroup`, baseline) +
/// `measurements`. Kept as a small struct so the canonical
/// verify_workload flow can lift `cgroup` straight into the JWT
/// `cgroup_path` claim without re-parsing the raw bytes.
struct ParsedEventLog {
    cgroup: String,
    measurements: Vec<MeasurementLog>,
}

/// Parse the kernel's per-container event log. The kernel emits a single
/// JSON object per file, shape:
/// `{"cgroup": ..., "baseline": ..., "count": N,
///   "measurements": [{"digest": hex, "file": path}, ...]}`
/// (see `security/integrity/ima/ima_container.c` and
/// `DEVELOPER_GUIDE_CONTAINER_RTMR3.md`).
fn parse_event_log(bytes: &[u8]) -> Result<ParsedEventLog> {
    if bytes.is_empty() {
        return Ok(ParsedEventLog {
            cgroup: String::new(),
            measurements: Vec::new(),
        });
    }
    #[derive(Debug, serde::Deserialize)]
    struct LogEntry {
        #[serde(default)]
        digest: String,
        #[serde(default)]
        file: String,
    }
    #[derive(Debug, serde::Deserialize)]
    struct LogFile {
        #[serde(default)]
        cgroup: String,
        #[serde(default)]
        measurements: Vec<LogEntry>,
    }

    let text = std::str::from_utf8(bytes)
        .map_err(|e| ServiceError::InvalidInput(format!("event_log is not valid UTF-8: {e}")))?;
    let doc: LogFile = serde_json::from_str(text)
        .map_err(|e| ServiceError::Parse(format!("event_log JSON: {e}")))?;

    Ok(ParsedEventLog {
        cgroup: doc.cgroup,
        measurements: doc
            .measurements
            .into_iter()
            .filter(|e| !e.digest.is_empty() && !e.file.is_empty())
            .map(|e| MeasurementLog {
                digest: e.digest,
                filename: e.file,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sha2::{Digest, Sha384};

    use crate::quote_backend::{QuoteBackendConfig, QuoteBackendMode, QuoteVerifierBackend};
    use crate::refstore::{MemoryStore, ReferenceEntry, ReferenceStore};

    use super::{TrustVerdict, Verifier, WorkloadVerifyRequest};

    fn insecure_backend() -> QuoteVerifierBackend {
        QuoteVerifierBackend::from_config(QuoteBackendConfig {
            mode: QuoteBackendMode::Insecure,
            dcap_library_path: None,
            ita_command: None,
            ita_args: Vec::new(),
        })
        .expect("backend should be created")
    }

    /// Build a minimal TDX v4 quote with the given RTMR[2] and report_data.
    fn build_v4_quote(rtmr2: &[u8; 48], report_data: &[u8; 64]) -> Vec<u8> {
        let mut quote = vec![0_u8; 48 + 584 + 4 + 16];
        quote[0..2].copy_from_slice(&4_u16.to_le_bytes());
        quote[4..8].copy_from_slice(&0x0000_0081_u32.to_le_bytes());
        quote[48 + 424..48 + 472].copy_from_slice(rtmr2.as_slice());
        quote[48 + 520..48 + 584].copy_from_slice(report_data.as_slice());
        quote[48 + 584..48 + 588].copy_from_slice(&16_u32.to_le_bytes());
        quote
    }

    fn event_log_json(measurements: &[(&str, &str)]) -> Vec<u8> {
        let measurements = measurements
            .iter()
            .map(|(digest, file)| {
                format!(r#"{{"digest":"{digest}","file":"{file}"}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"cgroup":"/docker/cg1","baseline":"","count":1,"measurements":[{measurements}]}}"#
        )
        .into_bytes()
    }

    fn expected_report_data(nonce: &[u8], peer_pk: Option<&[u8]>) -> [u8; 64] {
        let mut rd = [0_u8; 64];
        let n = Sha384::digest(nonce);
        rd[..32].copy_from_slice(&n[..32]);
        if let Some(pk) = peer_pk {
            let p = Sha384::digest(pk);
            rd[32..].copy_from_slice(&p[..32]);
        }
        rd
    }

    #[test]
    fn verify_workload_missing_refs_is_untrusted() {
        let store = Arc::new(MemoryStore::new());
        let verifier = Verifier::new(Arc::clone(&store) as Arc<dyn ReferenceStore>, insecure_backend());

        let nonce_hex = "ab".repeat(32);
        let nonce_bytes = hex::decode(&nonce_hex).unwrap();
        let report_data = expected_report_data(&nonce_bytes, None);
        let rtmr2 = [0_u8; 48];
        let quote = build_v4_quote(&rtmr2, &report_data);

        let result = verifier
            .verify_workload(&WorkloadVerifyRequest {
                workload_id: "wl-1".to_owned(),
                td_quote: quote,
                event_log: event_log_json(&[]),
                nonce_hex,
                peer_pk: Vec::new(),
            })
            .expect("verify should return");
        assert_eq!(result.verdict, TrustVerdict::Untrusted);
        assert!(result.message.contains("no reference values"));
    }

    #[test]
    fn verify_workload_all_checks_passing_is_trusted() {
        let store = Arc::new(MemoryStore::new());
        store
            .set(
                "wl-1",
                vec![ReferenceEntry {
                    filename: "/bin/app".to_owned(),
                    expected_digest: "01".repeat(48),
                    required: true,
                }],
            )
            .expect("set should succeed");
        let verifier = Verifier::new(Arc::clone(&store) as Arc<dyn ReferenceStore>, insecure_backend());

        let nonce_hex = "ab".repeat(32);
        let nonce_bytes = hex::decode(&nonce_hex).unwrap();
        let report_data = expected_report_data(&nonce_bytes, None);
        let rtmr2 = [0_u8; 48];
        let quote = build_v4_quote(&rtmr2, &report_data);

        let result = verifier
            .verify_workload(&WorkloadVerifyRequest {
                workload_id: "wl-1".to_owned(),
                td_quote: quote,
                event_log: event_log_json(&[(&"01".repeat(48), "/bin/app")]),
                nonce_hex,
                peer_pk: Vec::new(),
            })
            .expect("verify should return");
        assert_eq!(result.verdict, TrustVerdict::Trusted, "msg={}", result.message);
        assert_eq!(result.matched_count, 1);
        assert_eq!(result.missing_count, 0);
    }

    #[test]
    fn verify_workload_mismatched_report_data_is_untrusted() {
        let store = Arc::new(MemoryStore::new());
        store
            .set(
                "wl-1",
                vec![ReferenceEntry {
                    filename: "/bin/app".to_owned(),
                    expected_digest: "01".repeat(48),
                    required: true,
                }],
            )
            .expect("set should succeed");
        let verifier = Verifier::new(Arc::clone(&store) as Arc<dyn ReferenceStore>, insecure_backend());

        let nonce_hex = "ab".repeat(32);
        let rtmr2 = [0_u8; 48];
        let bad_report_data = [0x77_u8; 64];
        let quote = build_v4_quote(&rtmr2, &bad_report_data);

        let result = verifier
            .verify_workload(&WorkloadVerifyRequest {
                workload_id: "wl-1".to_owned(),
                td_quote: quote,
                event_log: event_log_json(&[(&"01".repeat(48), "/bin/app")]),
                nonce_hex,
                peer_pk: Vec::new(),
            })
            .expect("verify should return");
        assert_eq!(result.verdict, TrustVerdict::Untrusted);
        assert!(!result.report_data_valid);
    }
}
