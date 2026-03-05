use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{Result, ServiceError};

const HMAC_BLOCK_SIZE: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct TokenClaims {
    pub verdict: String,
    pub policy_action: String,
    pub cgroup_path: String,
    pub container_image: String,
    pub vmi_name: String,
    pub vmi_namespace: String,
    pub rtmr3: String,
    pub measurement_count: i32,
    pub matched_count: i32,
    pub unknown_count: i32,
    pub rtmr3_replay_valid: bool,
    pub all_required_present: bool,
    pub quote_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
struct JwtPayload<'a> {
    iss: &'a str,
    iat: i64,
    nbf: i64,
    exp: i64,
    #[serde(flatten)]
    claims: &'a TokenClaims,
}

#[derive(Debug, Clone, Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
}

#[derive(Debug, Clone)]
pub struct TokenIssuer {
    issuer_name: String,
    token_ttl: Duration,
    hmac_secret: Vec<u8>,
}

impl TokenIssuer {
    pub fn from_secret(
        issuer_name: impl Into<String>,
        token_ttl: Duration,
        hmac_secret: Vec<u8>,
    ) -> Result<Self> {
        if hmac_secret.is_empty() {
            return Err(ServiceError::InvalidInput(
                "token secret must not be empty".to_owned(),
            ));
        }

        Ok(Self {
            issuer_name: issuer_name.into(),
            token_ttl,
            hmac_secret,
        })
    }

    pub fn from_secret_file(
        issuer_name: impl Into<String>,
        token_ttl: Duration,
        secret_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let bytes = std::fs::read(secret_path)?;
        Self::from_secret(issuer_name, token_ttl, bytes)
    }

    pub fn random(issuer_name: impl Into<String>, token_ttl: Duration) -> Result<Self> {
        let mut file = File::open("/dev/urandom")?;
        let mut secret = vec![0_u8; 32];
        file.read_exact(&mut secret)?;
        Self::from_secret(issuer_name, token_ttl, secret)
    }

    pub fn issue(&self, claims: &TokenClaims) -> Result<String> {
        let now = unix_seconds(SystemTime::now());
        let payload = JwtPayload {
            iss: &self.issuer_name,
            iat: now,
            nbf: now,
            exp: now + self.token_ttl.as_secs() as i64,
            claims,
        };
        let header = JwtHeader {
            alg: "HS256",
            typ: "JWT",
        };

        let header_json = serde_json::to_vec(&header)
            .map_err(|error| ServiceError::Internal(format!("serialize jwt header: {error}")))?;
        let payload_json = serde_json::to_vec(&payload)
            .map_err(|error| ServiceError::Internal(format!("serialize jwt payload: {error}")))?;

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header_enc = b64.encode(header_json);
        let payload_enc = b64.encode(payload_json);
        let signing_input = format!("{header_enc}.{payload_enc}");
        let signature = hmac_sha256(self.hmac_secret.as_slice(), signing_input.as_bytes());
        let signature_enc = b64.encode(signature);

        Ok(format!("{signing_input}.{signature_enc}"))
    }
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut normalized = [0_u8; HMAC_BLOCK_SIZE];

    if key.len() > HMAC_BLOCK_SIZE {
        let digest = Sha256::digest(key);
        normalized[..digest.len()].copy_from_slice(digest.as_slice());
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36_u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5c_u8; HMAC_BLOCK_SIZE];
    for index in 0..HMAC_BLOCK_SIZE {
        ipad[index] ^= normalized[index];
        opad[index] ^= normalized[index];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let final_digest = outer.finalize();

    let mut out = [0_u8; 32];
    out.copy_from_slice(final_digest.as_slice());
    out
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::{TokenClaims, TokenIssuer};

    #[test]
    fn issue_token_has_three_segments() {
        let issuer =
            TokenIssuer::from_secret("issuer", std::time::Duration::from_secs(60), vec![7_u8; 32])
                .expect("issuer should be created");

        let token = issuer
            .issue(&TokenClaims {
                verdict: "TRUSTED".to_owned(),
                policy_action: "none".to_owned(),
                cgroup_path: "cg1".to_owned(),
                container_image: String::new(),
                vmi_name: String::new(),
                vmi_namespace: String::new(),
                rtmr3: "ab".repeat(48),
                measurement_count: 1,
                matched_count: 1,
                unknown_count: 0,
                rtmr3_replay_valid: true,
                all_required_present: true,
                quote_verified: false,
            })
            .expect("token should be issued");

        let segments: Vec<_> = token.split('.').collect();
        assert_eq!(segments.len(), 3);
    }
}
