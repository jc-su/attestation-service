use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, oneshot};

use crate::proto;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VerifyCacheKey([u8; 32]);

#[derive(Debug)]
struct CachedResponse {
    response: proto::VerifyResponse,
    cached_at: Instant,
}

#[derive(Debug)]
pub enum InFlightTurn {
    Leader,
    Wait(oneshot::Receiver<Result<proto::VerifyResponse, String>>),
}

pub struct VerificationResultCache {
    entries: RwLock<HashMap<VerifyCacheKey, CachedResponse>>,
    in_flight:
        Mutex<HashMap<VerifyCacheKey, Vec<oneshot::Sender<Result<proto::VerifyResponse, String>>>>>,
    ttl: Duration,
    max_entries: usize,
    epoch: AtomicU64,
}

impl VerificationResultCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
            epoch: AtomicU64::new(1),
        }
    }

    pub fn key_for_request(&self, request: &proto::VerifyRequest) -> VerifyCacheKey {
        let mut hasher = Sha256::new();
        hasher.update(self.epoch.load(Ordering::SeqCst).to_be_bytes());
        hash_string_field(&mut hasher, "cgroup_path", request.cgroup_path.as_str());
        hash_string_field(&mut hasher, "vmi_name", request.vmi_name.as_str());
        hash_string_field(&mut hasher, "vmi_namespace", request.vmi_namespace.as_str());
        hash_string_field(&mut hasher, "rtmr3", request.rtmr3.as_str());
        hash_string_field(&mut hasher, "initial_rtmr3", request.initial_rtmr3.as_str());
        hash_string_field(&mut hasher, "nonce", request.nonce.as_str());
        hash_string_field(&mut hasher, "report_data", request.report_data.as_str());
        hash_string_field(
            &mut hasher,
            "container_image",
            request.container_image.as_str(),
        );
        hash_bytes_field(&mut hasher, "td_quote", request.td_quote.as_slice());
        hasher.update((request.measurements.len() as u64).to_be_bytes());
        for measurement in &request.measurements {
            hash_string_field(&mut hasher, "measurement.file", measurement.file.as_str());
            hash_string_field(
                &mut hasher,
                "measurement.digest",
                measurement.digest.as_str(),
            );
        }

        let digest = hasher.finalize();
        let mut key = [0_u8; 32];
        key.copy_from_slice(digest.as_ref());
        VerifyCacheKey(key)
    }

    pub async fn get(&self, key: VerifyCacheKey) -> Option<proto::VerifyResponse> {
        if !self.enabled() {
            return None;
        }

        let entry = self
            .entries
            .read()
            .await
            .get(&key)
            .map(|value| CachedResponse {
                response: value.response.clone(),
                cached_at: value.cached_at,
            })?;

        if entry.cached_at.elapsed() > self.ttl {
            self.entries.write().await.remove(&key);
            return None;
        }
        Some(entry.response)
    }

    pub async fn begin(&self, key: VerifyCacheKey) -> InFlightTurn {
        if !self.enabled() {
            return InFlightTurn::Leader;
        }

        let mut in_flight = self.in_flight.lock().await;
        if let Some(waiters) = in_flight.get_mut(&key) {
            let (tx, rx) = oneshot::channel();
            waiters.push(tx);
            return InFlightTurn::Wait(rx);
        }

        in_flight.insert(key, Vec::new());
        InFlightTurn::Leader
    }

    pub async fn finish(&self, key: VerifyCacheKey, result: Result<proto::VerifyResponse, String>) {
        if !self.enabled() {
            return;
        }

        if let Ok(response) = result.clone() {
            self.insert(key, response).await;
        }

        let waiters = self.in_flight.lock().await.remove(&key).unwrap_or_default();
        for waiter in waiters {
            let _ = waiter.send(result.clone());
        }
    }

    pub async fn invalidate_all(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.entries.write().await.clear();
    }

    async fn insert(&self, key: VerifyCacheKey, response: proto::VerifyResponse) {
        let mut entries = self.entries.write().await;
        entries.retain(|_, value| value.cached_at.elapsed() <= self.ttl);

        if entries.len() >= self.max_entries
            && let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, value)| value.cached_at)
                .map(|(existing_key, _)| *existing_key)
        {
            entries.remove(&oldest_key);
        }

        entries.insert(
            key,
            CachedResponse {
                response,
                cached_at: Instant::now(),
            },
        );
    }

    fn enabled(&self) -> bool {
        !self.ttl.is_zero() && self.max_entries > 0
    }
}

fn hash_string_field(hasher: &mut Sha256, label: &str, value: &str) {
    hash_bytes_field(hasher, label, value.as_bytes());
}

fn hash_bytes_field(hasher: &mut Sha256, label: &str, value: &[u8]) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label.as_bytes());
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::proto;

    use super::{InFlightTurn, VerificationResultCache};

    fn verify_request() -> proto::VerifyRequest {
        proto::VerifyRequest {
            cgroup_path: "cg1".to_owned(),
            rtmr3: "00".repeat(48),
            initial_rtmr3: "00".repeat(48),
            nonce: "11".repeat(32),
            report_data: "22".repeat(64),
            td_quote: vec![1, 2, 3, 4],
            container_image: "cgroup://cg1".to_owned(),
            ..proto::VerifyRequest::default()
        }
    }

    fn verify_response() -> proto::VerifyResponse {
        proto::VerifyResponse {
            verdict: crate::proto::Verdict::Trusted as i32,
            message: "ok".to_owned(),
            attestation_token: String::new(),
            details: None,
            policy_action: "none".to_owned(),
        }
    }

    #[tokio::test]
    async fn cache_hit_within_ttl() {
        let cache = VerificationResultCache::new(Duration::from_secs(60), 64);
        let request = verify_request();
        let key = cache.key_for_request(&request);

        cache.finish(key, Ok(verify_response())).await;
        let cached = cache.get(key).await.expect("entry should be cached");
        assert_eq!(cached.message, "ok");
    }

    #[tokio::test]
    async fn in_flight_waiter_receives_leader_result() {
        let cache = VerificationResultCache::new(Duration::from_secs(60), 64);
        let request = verify_request();
        let key = cache.key_for_request(&request);

        assert!(matches!(cache.begin(key).await, InFlightTurn::Leader));
        let wait = cache.begin(key).await;
        let InFlightTurn::Wait(rx) = wait else {
            panic!("second caller should wait");
        };

        cache.finish(key, Ok(verify_response())).await;

        let result = rx.await.expect("waiter channel should receive result");
        let response = result.expect("leader result should be forwarded");
        assert_eq!(response.message, "ok");
    }

    #[tokio::test]
    async fn invalidate_changes_request_key() {
        let cache = VerificationResultCache::new(Duration::from_secs(60), 64);
        let request = verify_request();
        let before = cache.key_for_request(&request);
        cache.invalidate_all().await;
        let after = cache.key_for_request(&request);
        assert_ne!(before, after);
    }
}
