use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Result, ServiceError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceEntry {
    pub filename: String,
    pub expected_digest: String,
    pub required: bool,
}

/// Reference values for the TCB-level portion of a TD quote.
///
/// Distinct from [`ReferenceValues`] (which describes per-workload file
/// measurements) — these cover TD firmware, kernel cmdline chain, and
/// kernel image. A verifier uses them at step 2 of the attestation flow:
///
/// > *"Check the TD quote's RTMR[0..2] / MRTD against TCB reference
/// >   values — this is what makes the kernel's per-container event log
/// >   trustworthy input (i.e., written by a genuine kernel)."*
///
/// Typically one active TCB reference per deployment (one kernel image,
/// one TD firmware configuration). Multiple entries are allowed for
/// staged rollouts: during a kernel upgrade, both the old and new
/// RTMR[2] values are acceptable until all VMs have rolled over.
///
/// Fields are hex-encoded. `None` for a field means "skip this check"
/// (e.g., if MRTD is not pinned because the TD image is rebuilt
/// frequently). At least `rtmr2_hex` should be set — it is the anchor
/// that binds the kernel to its per-container event log output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcbReferenceValues {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mrtd_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr0_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr1_hex: Option<String>,
    pub rtmr2_hex: String,
    pub created_at: i64,
}

/// Thread-safe store for TCB reference values. A verifier consults this
/// alongside [`ReferenceStore`] on every Verify request: the former
/// certifies "the kernel that produced this evidence is genuine," the
/// latter certifies "this specific workload matches its baseline."
pub trait TcbReferenceStore: Send + Sync {
    fn list(&self) -> Result<Vec<TcbReferenceValues>>;
    fn add(&self, tcb: TcbReferenceValues) -> Result<()>;
    fn remove(&self, label: &str) -> Result<()>;

    /// Convenience: returns `Ok(())` iff `rtmr2_hex` matches any stored
    /// reference's `rtmr2_hex`. This is the fast-path check used in the
    /// Verifier.
    fn contains_rtmr2(&self, rtmr2_hex: &str) -> Result<bool> {
        Ok(self
            .list()?
            .iter()
            .any(|t| t.rtmr2_hex.eq_ignore_ascii_case(rtmr2_hex)))
    }
}

/// In-memory TCB reference store. Suitable for deployments where the
/// TCB reference values are supplied at attestation-service startup
/// (CLI flag / config file) and never mutated at runtime.
#[derive(Debug, Default)]
pub struct MemoryTcbStore {
    values: RwLock<Vec<TcbReferenceValues>>,
}

impl MemoryTcbStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_values(values: Vec<TcbReferenceValues>) -> Self {
        Self {
            values: RwLock::new(values),
        }
    }
}

impl TcbReferenceStore for MemoryTcbStore {
    fn list(&self) -> Result<Vec<TcbReferenceValues>> {
        let guard = self.values.read().map_err(|_| {
            ServiceError::Internal("tcb reference store poisoned".into())
        })?;
        Ok(guard.clone())
    }

    fn add(&self, tcb: TcbReferenceValues) -> Result<()> {
        let mut guard = self.values.write().map_err(|_| {
            ServiceError::Internal("tcb reference store poisoned".into())
        })?;
        // Dedup by label: replace if already present.
        guard.retain(|t| t.label != tcb.label);
        guard.push(tcb);
        Ok(())
    }

    fn remove(&self, label: &str) -> Result<()> {
        let mut guard = self.values.write().map_err(|_| {
            ServiceError::Internal("tcb reference store poisoned".into())
        })?;
        guard.retain(|t| t.label != label);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceValues {
    pub container_image: String,
    pub entries: Vec<ReferenceEntry>,
    pub created_at: i64,
}

pub trait ReferenceStore: Send + Sync {
    fn get(&self, container_image: &str) -> Result<ReferenceValues>;
    fn set(&self, container_image: &str, entries: Vec<ReferenceEntry>) -> Result<()>;
    fn delete(&self, container_image: &str) -> Result<()>;
}

/// PolicyReferenceStore manages policy-derived references separately from manual references.
pub trait PolicyReferenceStore: Send + Sync {
    fn replace_policy(
        &self,
        policy_id: &str,
        selector_entries: HashMap<String, Vec<ReferenceEntry>>,
    ) -> Result<()>;
    fn remove_policy(&self, policy_id: &str) -> Result<()>;
}

#[derive(Debug, Default)]
struct StoreState {
    manual: HashMap<String, ReferenceValues>,
    // policy_id -> selector -> values
    policies: HashMap<String, HashMap<String, ReferenceValues>>,
}

/// In-memory reference value store with support for:
/// - explicit identities (`docker.io/library/nginx:latest`)
/// - glob identities (`docker.io/library/*`)
/// - policy-owned entries managed independently from manual entries.
///
/// # Examples
///
/// ```
/// use attestation_service::refstore::{MemoryStore, ReferenceEntry, ReferenceStore};
///
/// let store = MemoryStore::new();
/// store.set(
///     "docker.io/library/nginx:latest",
///     vec![ReferenceEntry {
///         filename: "/usr/sbin/nginx".to_owned(),
///         expected_digest: "ab".repeat(48),
///         required: true,
///     }],
/// )
/// .expect("set should succeed");
///
/// let values = store
///     .get("docker.io/library/nginx:latest")
///     .expect("values should exist");
/// assert_eq!(values.entries.len(), 1);
/// ```
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: RwLock<StoreState>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(StoreState::default()),
        }
    }
}

impl ReferenceStore for MemoryStore {
    fn get(&self, container_image: &str) -> Result<ReferenceValues> {
        get_from_state(&self.state, container_image)
    }

    fn set(&self, container_image: &str, entries: Vec<ReferenceEntry>) -> Result<()> {
        let values = build_values(container_image, entries)?;
        let mut guard = self.state.write().map_err(|_| {
            ServiceError::Internal("reference store write lock poisoned".to_owned())
        })?;
        guard.manual.insert(container_image.to_owned(), values);
        Ok(())
    }

    fn delete(&self, container_image: &str) -> Result<()> {
        let mut guard = self.state.write().map_err(|_| {
            ServiceError::Internal("reference store write lock poisoned".to_owned())
        })?;
        guard.manual.remove(container_image);
        Ok(())
    }
}

impl PolicyReferenceStore for MemoryStore {
    fn replace_policy(
        &self,
        policy_id: &str,
        selector_entries: HashMap<String, Vec<ReferenceEntry>>,
    ) -> Result<()> {
        validate_policy_id(policy_id)?;

        let mut compiled = HashMap::with_capacity(selector_entries.len());
        for (selector, entries) in selector_entries {
            let values = build_values(&selector, entries)?;
            compiled.insert(selector, values);
        }

        let mut guard = self.state.write().map_err(|_| {
            ServiceError::Internal("reference store write lock poisoned".to_owned())
        })?;
        guard.policies.insert(policy_id.to_owned(), compiled);
        Ok(())
    }

    fn remove_policy(&self, policy_id: &str) -> Result<()> {
        validate_policy_id(policy_id)?;

        let mut guard = self.state.write().map_err(|_| {
            ServiceError::Internal("reference store write lock poisoned".to_owned())
        })?;
        guard.policies.remove(policy_id);
        Ok(())
    }
}

/// PersistentFileStore persists manual reference values to a JSON file while keeping
/// policy-derived references in-memory.
#[derive(Debug)]
pub struct PersistentFileStore {
    path: PathBuf,
    state: RwLock<StoreState>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedStoreV1 {
    version: u8,
    manual: HashMap<String, PersistedReferenceValues>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedReferenceValues {
    entries: Vec<ReferenceEntry>,
    created_at: i64,
}

impl PersistentFileStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let manual = load_manual_values(path.as_path())?;

        Ok(Self {
            path,
            state: RwLock::new(StoreState {
                manual,
                policies: HashMap::new(),
            }),
        })
    }

    fn persist_manual_map(&self, manual: HashMap<String, ReferenceValues>) -> Result<()> {
        let mut persisted = HashMap::with_capacity(manual.len());
        for (identity, values) in manual {
            persisted.insert(
                identity,
                PersistedReferenceValues {
                    entries: values.entries,
                    created_at: values.created_at,
                },
            );
        }

        let payload = serde_json::to_vec_pretty(&PersistedStoreV1 {
            version: 1,
            manual: persisted,
        })
        .map_err(|error| ServiceError::Internal(format!("serialize reference store: {error}")))?;

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let tmp_path = self.path.with_extension("tmp");
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(payload.as_slice())?;
        file.sync_all()?;
        fs::rename(tmp_path, &self.path)?;
        Ok(())
    }
}

impl ReferenceStore for PersistentFileStore {
    fn get(&self, container_image: &str) -> Result<ReferenceValues> {
        get_from_state(&self.state, container_image)
    }

    fn set(&self, container_image: &str, entries: Vec<ReferenceEntry>) -> Result<()> {
        let values = build_values(container_image, entries)?;

        let manual_snapshot = {
            let mut guard = self.state.write().map_err(|_| {
                ServiceError::Internal("reference store write lock poisoned".to_owned())
            })?;
            guard.manual.insert(container_image.to_owned(), values);
            guard.manual.clone()
        };

        self.persist_manual_map(manual_snapshot)
    }

    fn delete(&self, container_image: &str) -> Result<()> {
        let manual_snapshot = {
            let mut guard = self.state.write().map_err(|_| {
                ServiceError::Internal("reference store write lock poisoned".to_owned())
            })?;
            guard.manual.remove(container_image);
            guard.manual.clone()
        };

        self.persist_manual_map(manual_snapshot)
    }
}

impl PolicyReferenceStore for PersistentFileStore {
    fn replace_policy(
        &self,
        policy_id: &str,
        selector_entries: HashMap<String, Vec<ReferenceEntry>>,
    ) -> Result<()> {
        validate_policy_id(policy_id)?;

        let mut compiled = HashMap::with_capacity(selector_entries.len());
        for (selector, entries) in selector_entries {
            let values = build_values(&selector, entries)?;
            compiled.insert(selector, values);
        }

        let mut guard = self.state.write().map_err(|_| {
            ServiceError::Internal("reference store write lock poisoned".to_owned())
        })?;
        guard.policies.insert(policy_id.to_owned(), compiled);
        Ok(())
    }

    fn remove_policy(&self, policy_id: &str) -> Result<()> {
        validate_policy_id(policy_id)?;

        let mut guard = self.state.write().map_err(|_| {
            ServiceError::Internal("reference store write lock poisoned".to_owned())
        })?;
        guard.policies.remove(policy_id);
        Ok(())
    }
}

impl<T> ReferenceStore for std::sync::Arc<T>
where
    T: ReferenceStore + ?Sized,
{
    fn get(&self, container_image: &str) -> Result<ReferenceValues> {
        (**self).get(container_image)
    }

    fn set(&self, container_image: &str, entries: Vec<ReferenceEntry>) -> Result<()> {
        (**self).set(container_image, entries)
    }

    fn delete(&self, container_image: &str) -> Result<()> {
        (**self).delete(container_image)
    }
}

impl<T> PolicyReferenceStore for std::sync::Arc<T>
where
    T: PolicyReferenceStore + ?Sized,
{
    fn replace_policy(
        &self,
        policy_id: &str,
        selector_entries: HashMap<String, Vec<ReferenceEntry>>,
    ) -> Result<()> {
        (**self).replace_policy(policy_id, selector_entries)
    }

    fn remove_policy(&self, policy_id: &str) -> Result<()> {
        (**self).remove_policy(policy_id)
    }
}

fn validate_policy_id(policy_id: &str) -> Result<()> {
    if policy_id.is_empty() {
        return Err(ServiceError::InvalidInput(
            "policy id is required".to_owned(),
        ));
    }
    Ok(())
}

fn build_values(container_image: &str, entries: Vec<ReferenceEntry>) -> Result<ReferenceValues> {
    if container_image.is_empty() {
        return Err(ServiceError::InvalidInput(
            "container_image is required".to_owned(),
        ));
    }
    if entries.is_empty() {
        return Err(ServiceError::InvalidInput(
            "reference entries cannot be empty".to_owned(),
        ));
    }

    Ok(ReferenceValues {
        container_image: container_image.to_owned(),
        entries,
        created_at: unix_seconds(SystemTime::now()),
    })
}

fn get_from_state(state: &RwLock<StoreState>, identity: &str) -> Result<ReferenceValues> {
    if identity.is_empty() {
        return Err(ServiceError::InvalidInput(
            "container_image is required".to_owned(),
        ));
    }

    let guard = state
        .read()
        .map_err(|_| ServiceError::Internal("reference store read lock poisoned".to_owned()))?;

    if let Some(values) = resolve_best_match(guard.manual.iter(), identity) {
        return Ok(values);
    }

    let mut policy_candidates = Vec::new();
    for policy_entries in guard.policies.values() {
        policy_candidates.extend(policy_entries.iter());
    }

    if let Some(values) = resolve_best_match(policy_candidates.into_iter(), identity) {
        return Ok(values);
    }

    Err(ServiceError::NotFound(format!(
        "no reference values for {identity}"
    )))
}

fn resolve_best_match<'a, I>(entries: I, identity: &str) -> Option<ReferenceValues>
where
    I: Iterator<Item = (&'a String, &'a ReferenceValues)>,
{
    let mut best: Option<(&ReferenceValues, usize)> = None;

    for (selector, values) in entries {
        if selector == identity {
            return Some(values.clone());
        }

        if !is_glob_pattern(selector) || !glob_matches(selector, identity) {
            continue;
        }

        let specificity = selector
            .chars()
            .filter(|ch| *ch != '*' && *ch != '?')
            .count();

        match best {
            None => best = Some((values, specificity)),
            Some((current, current_specificity)) => {
                if specificity > current_specificity
                    || (specificity == current_specificity
                        && values.created_at > current.created_at)
                {
                    best = Some((values, specificity));
                }
            }
        }
    }

    best.map(|(values, _)| values.clone())
}

fn is_glob_pattern(selector: &str) -> bool {
    selector.contains('*') || selector.contains('?')
}

fn glob_matches(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();

    let mut p_idx = 0_usize;
    let mut t_idx = 0_usize;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0_usize;

    while t_idx < t.len() {
        if p_idx < p.len() && (p[p_idx] == b'?' || p[p_idx] == t[t_idx]) {
            p_idx += 1;
            t_idx += 1;
            continue;
        }

        if p_idx < p.len() && p[p_idx] == b'*' {
            star_idx = Some(p_idx);
            p_idx += 1;
            match_idx = t_idx;
            continue;
        }

        if let Some(star) = star_idx {
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
            continue;
        }

        return false;
    }

    while p_idx < p.len() && p[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == p.len()
}

fn load_manual_values(path: &Path) -> Result<HashMap<String, ReferenceValues>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let raw = fs::read(path)?;
    if raw.is_empty() {
        return Ok(HashMap::new());
    }

    let persisted: PersistedStoreV1 = serde_json::from_slice(raw.as_slice()).map_err(|error| {
        ServiceError::Parse(format!(
            "parse persisted reference store {}: {error}",
            path.display()
        ))
    })?;

    if persisted.version != 1 {
        return Err(ServiceError::Parse(format!(
            "unsupported persisted reference store version {}",
            persisted.version
        )));
    }

    let mut manual = HashMap::with_capacity(persisted.manual.len());
    for (identity, values) in persisted.manual {
        manual.insert(
            identity.clone(),
            ReferenceValues {
                container_image: identity,
                entries: values.entries,
                created_at: values.created_at,
            },
        );
    }
    Ok(manual)
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        MemoryStore, PersistentFileStore, PolicyReferenceStore, ReferenceEntry, ReferenceStore,
    };

    fn sample_entry() -> ReferenceEntry {
        ReferenceEntry {
            filename: "/bin/a".to_owned(),
            expected_digest: "ab".repeat(48),
            required: true,
        }
    }

    #[test]
    fn set_and_get_roundtrip() {
        let store = MemoryStore::new();
        store
            .set("img", vec![sample_entry()])
            .expect("set should succeed");

        let values = store.get("img").expect("values should exist");
        assert_eq!(values.entries.len(), 1);
        assert_eq!(values.entries[0].filename, "/bin/a");
    }

    #[test]
    fn get_missing_returns_error() {
        let store = MemoryStore::new();
        let err = store.get("missing").expect_err("missing key should fail");
        assert!(format!("{err}").contains("no reference values"));
    }

    #[test]
    fn glob_selector_matches_identity() {
        let store = MemoryStore::new();
        store
            .set("docker.io/library/*", vec![sample_entry()])
            .expect("set should succeed");

        let values = store
            .get("docker.io/library/nginx:latest")
            .expect("glob should match");
        assert_eq!(values.entries.len(), 1);
    }

    #[test]
    fn policy_entries_resolve_without_touching_manual_entries() {
        let store = MemoryStore::new();
        store
            .set("manual-image", vec![sample_entry()])
            .expect("manual set should succeed");

        let mut policy_map = HashMap::new();
        policy_map.insert("cgroup://*".to_owned(), vec![sample_entry()]);

        store
            .replace_policy("default/policy-a", policy_map)
            .expect("policy replace should succeed");

        assert!(store.get("cgroup:///kubepods/x").is_ok());
        assert!(store.get("manual-image").is_ok());

        store
            .remove_policy("default/policy-a")
            .expect("policy remove should succeed");
        assert!(store.get("cgroup:///kubepods/x").is_err());
        assert!(store.get("manual-image").is_ok());
    }

    #[test]
    fn persistent_store_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir should exist");
        let path = dir.path().join("refs.json");

        let store = PersistentFileStore::open(path.clone()).expect("open should succeed");
        store
            .set("img", vec![sample_entry()])
            .expect("set should succeed");
        drop(store);

        let reopened = PersistentFileStore::open(path).expect("reopen should succeed");
        let values = reopened.get("img").expect("value should persist");
        assert_eq!(values.entries.len(), 1);
    }
}
