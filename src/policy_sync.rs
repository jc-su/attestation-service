use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tracing::{info, warn};

use crate::error::{Result, ServiceError};
use crate::policy::load_compiled_policies;
use crate::policy_action_store::PolicyActionStore;
use crate::refstore::PolicyReferenceStore;

pub struct PolicyFileSync {
    store: Arc<dyn PolicyReferenceStore>,
    action_store: Arc<dyn PolicyActionStore>,
    paths: Vec<PathBuf>,
    interval: Duration,
    applied_policy_ids: RwLock<HashSet<String>>,
}

impl PolicyFileSync {
    pub fn new(
        store: Arc<dyn PolicyReferenceStore>,
        action_store: Arc<dyn PolicyActionStore>,
        paths: Vec<PathBuf>,
        interval: Duration,
    ) -> Self {
        Self {
            store,
            action_store,
            paths,
            interval,
            applied_policy_ids: RwLock::new(HashSet::new()),
        }
    }

    pub fn sync_once(&self) -> Result<usize> {
        let compiled = load_compiled_policies(self.paths.as_slice())?;

        let new_ids: HashSet<String> = compiled.keys().cloned().collect();
        for (policy_id, selector_entries) in compiled {
            let mut entries = std::collections::HashMap::with_capacity(selector_entries.len());
            let mut actions = std::collections::HashMap::with_capacity(selector_entries.len());
            for (selector, selector_policy) in selector_entries {
                entries.insert(selector.clone(), selector_policy.entries);
                actions.insert(selector, selector_policy.actions);
            }

            self.store.replace_policy(&policy_id, entries)?;
            self.action_store
                .replace_policy_actions(&policy_id, actions)?;
        }

        let old_ids = self
            .applied_policy_ids
            .read()
            .map_err(|_| ServiceError::Internal("policy sync lock poisoned".to_owned()))?
            .clone();
        for removed_id in old_ids.difference(&new_ids) {
            self.store.remove_policy(removed_id)?;
            self.action_store.remove_policy_actions(removed_id)?;
        }

        let mut guard = self
            .applied_policy_ids
            .write()
            .map_err(|_| ServiceError::Internal("policy sync lock poisoned".to_owned()))?;
        *guard = new_ids;
        Ok(guard.len())
    }

    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(error) = self.sync_once() {
                warn!(error = %error, "initial policy sync failed");
            } else {
                info!("initial policy sync completed");
            }

            let mut ticker = tokio::time::interval(self.interval);
            loop {
                ticker.tick().await;
                match self.sync_once() {
                    Ok(count) => info!(policy_count = count, "policy sync completed"),
                    Err(error) => warn!(error = %error, "policy sync failed"),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::time::Duration;

    use super::PolicyFileSync;
    use crate::policy_action_store::InMemoryPolicyActionStore;
    use crate::refstore::{MemoryStore, ReferenceStore};

    #[test]
    fn sync_once_applies_and_removes_policies() {
        let dir = tempfile::tempdir().expect("temp dir should exist");
        let policy_path = dir.path().join("policy.yaml");

        fs::write(
            &policy_path,
            r#"
apiVersion: trustfncall.io/v1alpha1
kind: AttestationPolicy
metadata:
  name: p1
spec:
  containerSelector:
    cgroupPaths: ["/kubepods/*"]
  referenceValues:
    - filename: "/a"
      expectedDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
        )
        .expect("write should succeed");

        let store = Arc::new(MemoryStore::new());
        let action_store = Arc::new(InMemoryPolicyActionStore::new());
        let sync = PolicyFileSync::new(
            store.clone(),
            action_store,
            vec![policy_path.clone()],
            Duration::from_secs(30),
        );
        sync.sync_once().expect("sync should succeed");
        assert!(store.get("cgroup:///kubepods/pod-x").is_ok());

        fs::write(&policy_path, "").expect("write should succeed");
        sync.sync_once().expect("sync should succeed");
        assert!(store.get("cgroup:///kubepods/pod-x").is_err());
    }
}
