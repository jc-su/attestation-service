use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Result, ServiceError};

#[cfg(target_os = "linux")]
const DCAP_LIBRARY_PATH_ENV: &str = "SGX_DCAP_QUOTE_VERIFY_LIB_PATH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteBackendMode {
    Dcap,
    Ita,
    Insecure,
}

#[derive(Debug, Clone)]
pub struct QuoteBackendConfig {
    pub mode: QuoteBackendMode,
    pub dcap_library_path: Option<String>,
    pub ita_command: Option<String>,
    pub ita_args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteTrustLevel {
    Trusted,
    Stale,
    Untrusted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteVerificationResult {
    pub trust_level: QuoteTrustLevel,
    pub signature_valid: bool,
    pub verification_skipped: bool,
    pub message: String,
    pub attestation_token: Option<String>,
    /// Hex-encoded MRTD extracted from the quote body, if parsed.
    pub parsed_mrtd_hex: Option<String>,
    /// Hex-encoded RTMR[0] extracted from the quote body, if parsed.
    pub parsed_rtmr0_hex: Option<String>,
    /// Hex-encoded RTMR[1] extracted from the quote body, if parsed.
    pub parsed_rtmr1_hex: Option<String>,
    /// Hex-encoded RTMR[2] extracted from the quote body, if parsed.
    /// Anchor for the TCB check in the canonical verify_workload flow.
    pub parsed_rtmr2_hex: Option<String>,
    /// Hex-encoded RTMR[3] extracted from the quote body, if parsed.
    /// Carried in JWT claims as evidence of the CVM-shared accumulator
    /// state at attestation time; not used for TCB matching.
    pub parsed_rtmr3_hex: Option<String>,
    /// Hex-encoded report_data (64 bytes) extracted from the quote body.
    /// Used by the canonical verify_workload flow for the nonce+peer_pk
    /// binding check. None = parser did not run.
    pub parsed_report_data_hex: Option<String>,
}

impl QuoteVerificationResult {
    pub fn mrtd_hex_opt(&self) -> Option<String> {
        self.parsed_mrtd_hex.clone()
    }
    pub fn rtmr0_hex_opt(&self) -> Option<String> {
        self.parsed_rtmr0_hex.clone()
    }
    pub fn rtmr1_hex_opt(&self) -> Option<String> {
        self.parsed_rtmr1_hex.clone()
    }
    pub fn rtmr2_hex_opt(&self) -> Option<String> {
        self.parsed_rtmr2_hex.clone()
    }
    pub fn rtmr3_hex_opt(&self) -> Option<String> {
        self.parsed_rtmr3_hex.clone()
    }
    pub fn report_data_hex_opt(&self) -> Option<String> {
        self.parsed_report_data_hex.clone()
    }
}

/// Bundle of measurement-register fields parsed out of a TDX v4 quote
/// body. Reported to the caller alongside the signature-verification
/// outcome so the TCB-check + JWT-claim paths share one parser.
struct ParsedTd10 {
    mrtd_hex: String,
    rtmr0_hex: String,
    rtmr1_hex: String,
    rtmr2_hex: String,
    rtmr3_hex: String,
    report_data_hex: String,
}

/// Parse RTMR[2] and report_data out of a raw TDX v4 quote (TD 1.0 body,
/// 584-byte report). Returns (rtmr2_hex, report_data_hex) on success.
/// This is a best-effort parser — only the fields verify_workload needs.
/// For anything stricter use the DCAP backend's full parser.
///
/// TDX v4 quote layout (from Intel DCAP v1.20+ spec):
///   Header:        0..48   (version, attestation_key_type, tee_type, ...)
///   Report (TD10): 48..632
///     tee_tcb_svn       [48..64]
///     mrseam            [64..112]
///     mrsignerseam      [112..160]
///     seamattributes    [160..168]
///     tdattributes      [168..176]
///     xfam              [176..184]
///     mrtd              [184..232]
///     mrconfigid        [232..280]
///     mrowner           [280..328]
///     mrownerconfig     [328..376]
///     rtmr0             [376..424]
///     rtmr1             [424..472]
///     rtmr2             [472..520]
///     rtmr3             [520..568]
///     reportdata        [568..632]
fn parse_td10_quote(bytes: &[u8]) -> Option<ParsedTd10> {
    // Minimum size: header (48) + TD10 report (584) = 632 bytes.
    // Real quotes are larger (include signature material) but those 632
    // bytes are always at the front.
    if bytes.len() < 632 {
        return None;
    }
    Some(ParsedTd10 {
        mrtd_hex:        hex::encode(&bytes[184..232]),
        rtmr0_hex:       hex::encode(&bytes[376..424]),
        rtmr1_hex:       hex::encode(&bytes[424..472]),
        rtmr2_hex:       hex::encode(&bytes[472..520]),
        rtmr3_hex:       hex::encode(&bytes[520..568]),
        report_data_hex: hex::encode(&bytes[568..632]),
    })
}

#[derive(Debug, Clone)]
pub struct QuoteBackendInput<'a> {
    pub quote_bytes: &'a [u8],
    pub nonce_hex: &'a str,
    pub rtmr3_hex: &'a str,
    pub report_data_hex: &'a str,
}

#[derive(Debug, Clone)]
pub enum QuoteVerifierBackend {
    Dcap(Arc<DcapQuoteVerifier>),
    Ita(Arc<ItaCommandQuoteVerifier>),
    Insecure,
}

impl QuoteVerifierBackend {
    pub fn from_config(config: QuoteBackendConfig) -> Result<Self> {
        match config.mode {
            QuoteBackendMode::Insecure => Ok(Self::Insecure),
            QuoteBackendMode::Dcap => Ok(Self::Dcap(Arc::new(DcapQuoteVerifier::new(
                config.dcap_library_path,
            )?))),
            QuoteBackendMode::Ita => Ok(Self::Ita(Arc::new(ItaCommandQuoteVerifier::new(
                config.ita_command,
                config.ita_args,
            )?))),
        }
    }

    pub fn verify(&self, input: &QuoteBackendInput<'_>) -> Result<QuoteVerificationResult> {
        let mut result = match self {
            Self::Insecure => QuoteVerificationResult {
                trust_level: QuoteTrustLevel::Trusted,
                signature_valid: false,
                verification_skipped: true,
                message: "quote signature verification skipped (insecure mode)".to_owned(),
                attestation_token: None,
                parsed_mrtd_hex: None,
                parsed_rtmr0_hex: None,
                parsed_rtmr1_hex: None,
                parsed_rtmr2_hex: None,
                parsed_rtmr3_hex: None,
                parsed_report_data_hex: None,
            },
            Self::Dcap(backend) => backend.verify(input)?,
            Self::Ita(backend) => backend.verify(input)?,
        };
        // MRTD / RTMR[0..3] / report_data live at fixed offsets in the
        // TD10 report body; their location is independent of whether the
        // signature was verified. Backends that parse them natively (e.g.
        // future ITA JSON extraction) can set these fields; otherwise we
        // fill from the raw bytes here so `verify_workload` has a single
        // source of truth for both TCB matching and JWT claim emission.
        if result.parsed_mrtd_hex.is_none()
            || result.parsed_rtmr0_hex.is_none()
            || result.parsed_rtmr1_hex.is_none()
            || result.parsed_rtmr2_hex.is_none()
            || result.parsed_rtmr3_hex.is_none()
            || result.parsed_report_data_hex.is_none()
        {
            if let Some(parsed) = parse_td10_quote(input.quote_bytes) {
                result.parsed_mrtd_hex.get_or_insert(parsed.mrtd_hex);
                result.parsed_rtmr0_hex.get_or_insert(parsed.rtmr0_hex);
                result.parsed_rtmr1_hex.get_or_insert(parsed.rtmr1_hex);
                result.parsed_rtmr2_hex.get_or_insert(parsed.rtmr2_hex);
                result.parsed_rtmr3_hex.get_or_insert(parsed.rtmr3_hex);
                result
                    .parsed_report_data_hex
                    .get_or_insert(parsed.report_data_hex);
            }
        }
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct ItaCommandQuoteVerifier {
    command: String,
    args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ItaCommandRequest {
    quote_base64: String,
    nonce_hex: String,
    rtmr3_hex: String,
    report_data_hex: String,
}

#[derive(Debug, Deserialize)]
struct ItaCommandResponse {
    status: Option<String>,
    trusted: Option<bool>,
    stale: Option<bool>,
    signature_valid: Option<bool>,
    message: Option<String>,
    attestation_token: Option<String>,
}

impl ItaCommandQuoteVerifier {
    pub fn new(command: Option<String>, args: Vec<String>) -> Result<Self> {
        let command = command.ok_or_else(|| {
            ServiceError::InvalidInput("ita backend requires --ita-command".to_owned())
        })?;

        Ok(Self { command, args })
    }

    pub fn verify(&self, input: &QuoteBackendInput<'_>) -> Result<QuoteVerificationResult> {
        let request = ItaCommandRequest {
            quote_base64: base64::engine::general_purpose::STANDARD.encode(input.quote_bytes),
            nonce_hex: input.nonce_hex.to_owned(),
            rtmr3_hex: input.rtmr3_hex.to_owned(),
            report_data_hex: input.report_data_hex.to_owned(),
        };
        let payload = serde_json::to_vec(&request)
            .map_err(|error| ServiceError::Internal(format!("serialize ita request: {error}")))?;

        let mut child = Command::new(&self.command)
            .args(self.args.as_slice())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                ServiceError::Internal(format!("spawn ita command '{}': {error}", self.command))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(payload.as_slice()).map_err(|error| {
                ServiceError::Internal(format!(
                    "write request to ita command '{}': {error}",
                    self.command
                ))
            })?;
        }

        let output = child.wait_with_output().map_err(|error| {
            ServiceError::Internal(format!("wait for ita command '{}': {error}", self.command))
        })?;
        if !output.status.success() {
            return Err(ServiceError::Internal(format!(
                "ita command '{}' failed: {}",
                self.command,
                String::from_utf8_lossy(output.stderr.as_slice())
            )));
        }

        let response: ItaCommandResponse = serde_json::from_slice(output.stdout.as_slice())
            .map_err(|error| {
                ServiceError::Parse(format!("parse ita command output as json: {error}"))
            })?;

        map_ita_response(response)
    }
}

fn map_ita_response(response: ItaCommandResponse) -> Result<QuoteVerificationResult> {
    let (trust_level, signature_default) = if let Some(status) = response.status {
        match status.to_ascii_uppercase().as_str() {
            "TRUSTED" => (QuoteTrustLevel::Trusted, true),
            "STALE" => (QuoteTrustLevel::Stale, true),
            "UNTRUSTED" => (QuoteTrustLevel::Untrusted, false),
            other => {
                return Err(ServiceError::Parse(format!(
                    "unknown ita response status: {other}"
                )));
            }
        }
    } else if response.trusted.unwrap_or(false) {
        (QuoteTrustLevel::Trusted, true)
    } else if response.stale.unwrap_or(false) {
        (QuoteTrustLevel::Stale, true)
    } else {
        (QuoteTrustLevel::Untrusted, false)
    };

    Ok(QuoteVerificationResult {
        trust_level,
        signature_valid: response.signature_valid.unwrap_or(signature_default),
        verification_skipped: false,
        message: response
            .message
            .unwrap_or_else(|| "ita verification completed".to_owned()),
        attestation_token: response.attestation_token.filter(|token| !token.is_empty()),
        parsed_mrtd_hex: None,
        parsed_rtmr0_hex: None,
        parsed_rtmr1_hex: None,
        parsed_rtmr2_hex: None,
        parsed_rtmr3_hex: None,
        parsed_report_data_hex: None,
    })
}

#[derive(Debug, Clone)]
pub struct DcapQuoteVerifier {
    #[cfg(target_os = "linux")]
    library: Arc<dcap_linux::DcapLibrary>,
}

impl DcapQuoteVerifier {
    pub fn new(path_override: Option<String>) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let mut candidates = Vec::new();
            if let Some(path) = path_override {
                candidates.push(path);
            }
            if let Ok(path) = std::env::var(DCAP_LIBRARY_PATH_ENV) {
                if !path.trim().is_empty() {
                    candidates.push(path);
                }
            }
            candidates.extend(
                [
                    "libsgx_dcap_quoteverify.so.1",
                    "libsgx_dcap_quoteverify.so",
                    "libsgx_dcap_quoteverify.dylib",
                ]
                .into_iter()
                .map(std::borrow::ToOwned::to_owned),
            );

            let library = dcap_linux::DcapLibrary::load(candidates.as_slice())?;
            return Ok(Self {
                library: Arc::new(library),
            });
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = path_override;
            Err(ServiceError::Internal(
                "dcap backend is only supported on linux targets".to_owned(),
            ))
        }
    }

    pub fn verify(&self, input: &QuoteBackendInput<'_>) -> Result<QuoteVerificationResult> {
        #[cfg(target_os = "linux")]
        {
            let outcome = self.library.verify_quote(input.quote_bytes)?;
            return Ok(map_dcap_qv_result(
                outcome.qv_result,
                outcome.collateral_expired,
            ));
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = input;
            Err(ServiceError::Internal(
                "dcap backend is only supported on linux targets".to_owned(),
            ))
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn map_dcap_qv_result(qv_result: u32, collateral_expired: bool) -> QuoteVerificationResult {
    const SGX_QL_QV_RESULT_OK: u32 = 0x0000;
    const SGX_QL_QV_RESULT_CONFIG_NEEDED: u32 = 0xA000;
    const SGX_QL_QV_RESULT_OUT_OF_DATE: u32 = 0xA001;
    const SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED: u32 = 0xA002;
    const SGX_QL_QV_RESULT_INVALID_SIGNATURE: u32 = 0xA003;
    const SGX_QL_QV_RESULT_REVOKED: u32 = 0xA004;
    const SGX_QL_QV_RESULT_UNSPECIFIED: u32 = 0xA005;
    const SGX_QL_QV_RESULT_SW_HARDENING_NEEDED: u32 = 0xA006;
    const SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED: u32 = 0xA007;
    const SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED: u32 = 0xA008;
    const SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED: u32 = 0xA009;

    let (trust_level, signature_valid, label) = match qv_result {
        SGX_QL_QV_RESULT_OK => (QuoteTrustLevel::Trusted, true, "OK"),
        SGX_QL_QV_RESULT_CONFIG_NEEDED => (QuoteTrustLevel::Stale, true, "CONFIG_NEEDED"),
        SGX_QL_QV_RESULT_OUT_OF_DATE => (QuoteTrustLevel::Stale, true, "OUT_OF_DATE"),
        SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED => {
            (QuoteTrustLevel::Stale, true, "OUT_OF_DATE_CONFIG_NEEDED")
        }
        SGX_QL_QV_RESULT_SW_HARDENING_NEEDED => {
            (QuoteTrustLevel::Stale, true, "SW_HARDENING_NEEDED")
        }
        SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => (
            QuoteTrustLevel::Stale,
            true,
            "CONFIG_AND_SW_HARDENING_NEEDED",
        ),
        SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED => {
            (QuoteTrustLevel::Stale, true, "TD_RELAUNCH_ADVISED")
        }
        SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED => (
            QuoteTrustLevel::Stale,
            true,
            "TD_RELAUNCH_ADVISED_CONFIG_NEEDED",
        ),
        SGX_QL_QV_RESULT_INVALID_SIGNATURE => {
            (QuoteTrustLevel::Untrusted, false, "INVALID_SIGNATURE")
        }
        SGX_QL_QV_RESULT_REVOKED => (QuoteTrustLevel::Untrusted, false, "REVOKED"),
        SGX_QL_QV_RESULT_UNSPECIFIED => (QuoteTrustLevel::Untrusted, false, "UNSPECIFIED"),
        _ => (QuoteTrustLevel::Untrusted, false, "UNKNOWN"),
    };

    let mut message = format!("dcap quote verification result={label} (0x{qv_result:04x})");
    if collateral_expired {
        if trust_level != QuoteTrustLevel::Untrusted {
            message.push_str("; collateral expired");
        } else {
            message.push_str("; collateral expired (and quote untrusted)");
        }
    }

    QuoteVerificationResult {
        trust_level: if collateral_expired && trust_level == QuoteTrustLevel::Trusted {
            QuoteTrustLevel::Stale
        } else {
            trust_level
        },
        signature_valid,
        verification_skipped: false,
        message,
        attestation_token: None,
        parsed_mrtd_hex: None,
        parsed_rtmr0_hex: None,
        parsed_rtmr1_hex: None,
        parsed_rtmr2_hex: None,
        parsed_rtmr3_hex: None,
        parsed_report_data_hex: None,
    }
}

#[cfg(target_os = "linux")]
mod dcap_linux {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_void};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::error::{Result, ServiceError};

    const RTLD_NOW: c_int = 2;
    const SGX_QL_SUCCESS: u32 = 0x0000;

    #[link(name = "dl")]
    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
        fn dlerror() -> *const c_char;
    }

    type TeeVerifyQuoteFn = unsafe extern "C" fn(
        p_quote: *const u8,
        quote_size: u32,
        p_quote_collateral: *const u8,
        expiration_check_date: i64,
        p_collateral_expiration_status: *mut u32,
        p_quote_verification_result: *mut u32,
        p_qve_report_info: *mut c_void,
        supplemental_data_size: u32,
        p_supplemental_data: *mut u8,
    ) -> u32;

    #[derive(Debug, Clone, Copy)]
    pub struct DcapVerifyOutcome {
        pub qv_result: u32,
        pub collateral_expired: bool,
    }

    #[derive(Debug)]
    pub struct DcapLibrary {
        handle: *mut c_void,
        tee_verify_quote: TeeVerifyQuoteFn,
        call_lock: Mutex<()>,
    }

    // SAFETY: The dynamic library handle and resolved function pointer are immutable after
    // construction and owned by this struct. Calls into the DCAP verifier are serialized by
    // `call_lock`, so sharing/sending `DcapLibrary` across threads does not permit concurrent
    // unsynchronized access to the raw handle.
    unsafe impl Send for DcapLibrary {}
    // SAFETY: See rationale above for `Send`.
    unsafe impl Sync for DcapLibrary {}

    impl DcapLibrary {
        pub fn load(candidates: &[String]) -> Result<Self> {
            if candidates.is_empty() {
                return Err(ServiceError::Internal(
                    "no DCAP quote verify library candidates provided".to_owned(),
                ));
            }

            let mut errors = Vec::new();
            for candidate in candidates {
                match Self::load_one(candidate.as_str()) {
                    Ok(library) => return Ok(library),
                    Err(error) => errors.push(format!("{candidate}: {error}")),
                }
            }

            Err(ServiceError::Internal(format!(
                "failed to load DCAP quote verify library; tried: {}",
                errors.join(", ")
            )))
        }

        fn load_one(path: &str) -> Result<Self> {
            let path_cstr = CString::new(path).map_err(|error| {
                ServiceError::InvalidInput(format!("invalid dcap library path '{path}': {error}"))
            })?;

            // SAFETY: The C string pointer is valid and null-terminated for the duration of the call.
            let handle = unsafe { dlopen(path_cstr.as_ptr(), RTLD_NOW) };
            if handle.is_null() {
                return Err(ServiceError::Internal(format!(
                    "dlopen failed: {}",
                    last_dl_error()
                )));
            }

            let mut symbol_ptr = std::ptr::null_mut();
            for symbol_name in ["tee_verify_quote", "sgx_qv_verify_quote"] {
                let symbol = CString::new(symbol_name).expect("valid static symbol");
                // SAFETY: `handle` comes from a successful `dlopen`, `symbol` is a valid symbol name.
                symbol_ptr = unsafe { dlsym(handle, symbol.as_ptr()) };
                if !symbol_ptr.is_null() {
                    break;
                }
            }
            if symbol_ptr.is_null() {
                // SAFETY: `handle` was returned by `dlopen` and is valid to close here.
                unsafe {
                    let _ = dlclose(handle);
                }
                return Err(ServiceError::Internal(format!(
                    "dlsym(tee_verify_quote|sgx_qv_verify_quote) failed: {}",
                    last_dl_error()
                )));
            }

            // SAFETY: `symbol_ptr` points to `tee_verify_quote` with the exact ABI/signature declared above.
            let tee_verify_quote: TeeVerifyQuoteFn = unsafe { std::mem::transmute(symbol_ptr) };

            Ok(Self {
                handle,
                tee_verify_quote,
                call_lock: Mutex::new(()),
            })
        }

        pub fn verify_quote(&self, quote: &[u8]) -> Result<DcapVerifyOutcome> {
            if quote.is_empty() {
                return Err(ServiceError::InvalidInput(
                    "quote bytes must not be empty".to_owned(),
                ));
            }
            let quote_size = u32::try_from(quote.len()).map_err(|_| {
                ServiceError::InvalidInput(format!("quote too large: {} bytes", quote.len()))
            })?;

            let expiration_check_date = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| {
                    ServiceError::Internal(format!("system time before epoch: {error}"))
                })?
                .as_secs() as i64;

            let mut collateral_expiration_status = 1_u32;
            let mut quote_verification_result = 0_u32;
            let _guard = self.call_lock.lock().expect("dcap verify mutex poisoned");

            // SAFETY: all pointers are valid for the duration of the call; we pass null pointers
            // where optional buffers/collateral are intentionally omitted.
            let ret = unsafe {
                (self.tee_verify_quote)(
                    quote.as_ptr(),
                    quote_size,
                    std::ptr::null(),
                    expiration_check_date,
                    &mut collateral_expiration_status,
                    &mut quote_verification_result,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                )
            };

            if ret != SGX_QL_SUCCESS {
                return Err(ServiceError::Internal(format!(
                    "tee_verify_quote failed with code 0x{ret:04x}"
                )));
            }

            Ok(DcapVerifyOutcome {
                qv_result: quote_verification_result,
                collateral_expired: collateral_expiration_status != 0,
            })
        }
    }

    impl Drop for DcapLibrary {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                // SAFETY: `handle` is owned by this struct and was produced by `dlopen`.
                unsafe {
                    let _ = dlclose(self.handle);
                }
            }
        }
    }

    fn last_dl_error() -> String {
        // SAFETY: `dlerror` returns either null or a valid null-terminated C string owned by libc.
        let ptr = unsafe { dlerror() };
        if ptr.is_null() {
            return "unknown dynamic loader error".to_owned();
        }
        // SAFETY: pointer is guaranteed by `dlerror` to reference a C string.
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ItaCommandResponse, QuoteTrustLevel, QuoteVerifierBackend, map_dcap_qv_result,
        map_ita_response,
    };

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn quote_backend_is_send_sync() {
        assert_send_sync::<QuoteVerifierBackend>();
    }

    #[test]
    fn dcap_ok_is_trusted() {
        let result = map_dcap_qv_result(0x0000, false);
        assert_eq!(result.trust_level, QuoteTrustLevel::Trusted);
        assert!(result.signature_valid);
    }

    #[test]
    fn dcap_invalid_signature_is_untrusted() {
        let result = map_dcap_qv_result(0xA003, false);
        assert_eq!(result.trust_level, QuoteTrustLevel::Untrusted);
        assert!(!result.signature_valid);
    }

    #[test]
    fn ita_status_stale_maps_to_stale() {
        let result = map_ita_response(ItaCommandResponse {
            status: Some("STALE".to_owned()),
            trusted: None,
            stale: None,
            signature_valid: None,
            message: Some("needs patch".to_owned()),
            attestation_token: None,
        })
        .expect("ita response should parse");

        assert_eq!(result.trust_level, QuoteTrustLevel::Stale);
        assert_eq!(result.message, "needs patch");
    }
}
