use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{Result, ServiceError};
use crate::policy_action_store::{PolicyAction, SelectorPolicyAction};
use crate::refstore::ReferenceEntry;

pub type CompiledPolicies = HashMap<String, HashMap<String, CompiledPolicySelector>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicySelector {
    pub entries: Vec<ReferenceEntry>,
    pub actions: SelectorPolicyAction,
}

#[derive(Debug, Deserialize)]
struct RawPolicyDocument {
    kind: Option<String>,
    metadata: Option<RawPolicyMetadata>,
    spec: Option<RawPolicySpec>,
}

#[derive(Debug, Deserialize)]
struct RawPolicyMetadata {
    name: String,
    namespace: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawPolicySpec {
    #[serde(rename = "imageSelector")]
    image_selector: Option<RawImageSelector>,
    #[serde(rename = "containerSelector")]
    container_selector: Option<RawContainerSelector>,
    #[serde(rename = "referenceValues", default)]
    reference_values: Vec<RawReferenceValue>,
    #[serde(rename = "heartbeatPolicy")]
    heartbeat_policy: Option<RawHeartbeatPolicy>,
    #[serde(rename = "enforcementAction")]
    enforcement_action: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawImageSelector {
    #[serde(rename = "imageNames", default)]
    image_names: Vec<String>,
    #[serde(rename = "imageDigests", default)]
    image_digests: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawContainerSelector {
    #[serde(rename = "cgroupPaths", default)]
    cgroup_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawReferenceValue {
    filename: String,
    #[serde(rename = "expectedDigest")]
    expected_digest: String,
    #[serde(default)]
    required: bool,
}

#[derive(Debug, Deserialize, Default)]
struct RawHeartbeatPolicy {
    action: Option<String>,
}

pub fn load_compiled_policies(paths: &[PathBuf]) -> Result<CompiledPolicies> {
    let mut compiled = HashMap::new();
    for path in paths {
        let content = fs::read_to_string(path).map_err(|source| {
            ServiceError::Io(std::io::Error::new(
                source.kind(),
                format!("read policy file {}: {source}", path.display()),
            ))
        })?;

        for (doc_index, deserializer) in serde_yaml::Deserializer::from_str(&content).enumerate() {
            let raw_value = serde_yaml::Value::deserialize(deserializer).map_err(|error| {
                ServiceError::Parse(format!(
                    "parse YAML document {} in {}: {error}",
                    doc_index + 1,
                    path.display()
                ))
            })?;
            if raw_value.is_null() {
                continue;
            }

            let document: RawPolicyDocument =
                serde_yaml::from_value(raw_value).map_err(|error| {
                    ServiceError::Parse(format!(
                        "decode policy document {} in {}: {error}",
                        doc_index + 1,
                        path.display()
                    ))
                })?;

            if document.kind.as_deref() != Some("AttestationPolicy") {
                continue;
            }

            let metadata = document.metadata.ok_or_else(|| {
                ServiceError::Parse(format!(
                    "attestation policy in {} missing metadata",
                    path.display()
                ))
            })?;
            let spec = document.spec.ok_or_else(|| {
                ServiceError::Parse(format!(
                    "attestation policy {}/{} missing spec",
                    metadata.namespace.as_deref().unwrap_or("default"),
                    metadata.name
                ))
            })?;

            let policy_id = format!(
                "{}/{}",
                metadata.namespace.unwrap_or_else(|| "default".to_owned()),
                metadata.name
            );
            let selectors = compile_selectors(spec.image_selector, spec.container_selector)?;
            let entries = compile_entries(spec.reference_values)?;
            let actions = compile_actions(spec.enforcement_action, spec.heartbeat_policy)?;

            let mut selector_map = HashMap::with_capacity(selectors.len());
            for selector in selectors {
                selector_map.insert(
                    selector,
                    CompiledPolicySelector {
                        entries: entries.clone(),
                        actions,
                    },
                );
            }
            compiled.insert(policy_id, selector_map);
        }
    }

    Ok(compiled)
}

fn compile_actions(
    enforcement_action: Option<String>,
    heartbeat_policy: Option<RawHeartbeatPolicy>,
) -> Result<SelectorPolicyAction> {
    Ok(SelectorPolicyAction {
        on_untrusted: parse_untrusted_action(enforcement_action.as_deref())?,
        on_stale: parse_stale_action(heartbeat_policy.and_then(|policy| policy.action).as_deref())?,
    })
}

fn parse_untrusted_action(raw: Option<&str>) -> Result<PolicyAction> {
    match raw.map(|value| value.trim().to_ascii_lowercase()) {
        None => Ok(PolicyAction::None),
        Some(value) if value.is_empty() || value == "audit" || value == "disabled" => {
            Ok(PolicyAction::None)
        }
        Some(value) if value == "enforce" => Ok(PolicyAction::Restart),
        Some(value) => Err(ServiceError::InvalidInput(format!(
            "unsupported enforcementAction {value}; expected enforce|audit|disabled"
        ))),
    }
}

fn parse_stale_action(raw: Option<&str>) -> Result<PolicyAction> {
    match raw.map(|value| value.trim().to_ascii_lowercase()) {
        None => Ok(PolicyAction::Alert),
        Some(value) if value.is_empty() || value == "alert" => Ok(PolicyAction::Alert),
        Some(value) if value == "restart" => Ok(PolicyAction::Restart),
        Some(value) if value == "kill" => Ok(PolicyAction::Kill),
        Some(value) => Err(ServiceError::InvalidInput(format!(
            "unsupported heartbeatPolicy.action {value}; expected alert|restart|kill"
        ))),
    }
}

fn compile_entries(values: Vec<RawReferenceValue>) -> Result<Vec<ReferenceEntry>> {
    if values.is_empty() {
        return Err(ServiceError::InvalidInput(
            "policy must provide at least one referenceValues entry".to_owned(),
        ));
    }

    let mut entries = Vec::with_capacity(values.len());
    for value in values {
        if value.filename.trim().is_empty() {
            return Err(ServiceError::InvalidInput(
                "referenceValues.filename cannot be empty".to_owned(),
            ));
        }

        let digest = value.expected_digest.trim().to_ascii_lowercase();
        validate_sha384_hex(digest.as_str())?;

        entries.push(ReferenceEntry {
            filename: value.filename.trim().to_owned(),
            expected_digest: digest,
            required: value.required,
        });
    }
    Ok(entries)
}

fn compile_selectors(
    image_selector: Option<RawImageSelector>,
    container_selector: Option<RawContainerSelector>,
) -> Result<HashSet<String>> {
    let mut selectors = HashSet::new();

    if let Some(image_selector) = image_selector {
        for image_name in image_selector.image_names {
            let normalized = image_name.trim();
            if normalized.is_empty() {
                continue;
            }
            selectors.insert(normalized.to_owned());
        }

        for digest in image_selector.image_digests {
            let normalized = digest.trim().to_ascii_lowercase();
            validate_sha256_digest(normalized.as_str())?;
            selectors.insert(format!("*@{normalized}"));
            selectors.insert(normalized);
        }
    }

    if let Some(container_selector) = container_selector {
        for cgroup_path in container_selector.cgroup_paths {
            let normalized = cgroup_path.trim();
            if normalized.is_empty() {
                continue;
            }
            if normalized.starts_with("cgroup://") {
                selectors.insert(normalized.to_owned());
            } else {
                selectors.insert(format!("cgroup://{normalized}"));
            }
        }
    }

    if selectors.is_empty() {
        selectors.insert("*".to_owned());
    }

    Ok(selectors)
}

fn validate_sha384_hex(value: &str) -> Result<()> {
    let decoded = hex::decode(value)
        .map_err(|error| ServiceError::InvalidInput(format!("invalid SHA-384 digest: {error}")))?;
    if decoded.len() != 48 {
        return Err(ServiceError::InvalidInput(format!(
            "SHA-384 digest must be 48 bytes (96 hex chars), got {} bytes",
            decoded.len()
        )));
    }
    Ok(())
}

fn validate_sha256_digest(value: &str) -> Result<()> {
    let digest = value.strip_prefix("sha256:").ok_or_else(|| {
        ServiceError::InvalidInput(format!(
            "image digest must be in sha256:<hex> format, got {value}"
        ))
    })?;
    let decoded = hex::decode(digest)
        .map_err(|error| ServiceError::InvalidInput(format!("invalid sha256 digest: {error}")))?;
    if decoded.len() != 32 {
        return Err(ServiceError::InvalidInput(format!(
            "sha256 digest must be 32 bytes (64 hex chars), got {} bytes",
            decoded.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::load_compiled_policies;

    #[test]
    fn compile_policy_with_image_and_cgroup_selectors() {
        let dir = tempfile::tempdir().expect("temp dir should exist");
        let policy_path = dir.path().join("policy.yaml");
        fs::write(
            &policy_path,
            r#"
apiVersion: trustfncall.io/v1alpha1
kind: AttestationPolicy
metadata:
  name: p1
  namespace: default
spec:
  imageSelector:
    imageNames:
      - "registry.example.com/mcp-tool-*"
    imageDigests:
      - "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  containerSelector:
    cgroupPaths:
      - "/kubepods/*"
  referenceValues:
    - filename: "/usr/bin/mcp"
      expectedDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      required: true
  heartbeatPolicy:
    action: restart
  enforcementAction: enforce
"#,
        )
        .expect("write should succeed");

        let compiled =
            load_compiled_policies(&[policy_path]).expect("policy compilation should succeed");
        let selectors = compiled
            .get("default/p1")
            .expect("compiled policy should exist");

        assert!(selectors.contains_key("registry.example.com/mcp-tool-*"));
        assert!(selectors.contains_key(
            "*@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(selectors.contains_key(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(selectors.contains_key("cgroup:///kubepods/*"));
        let selector = selectors
            .get("registry.example.com/mcp-tool-*")
            .expect("selector should exist");
        assert_eq!(selector.actions.on_untrusted, super::PolicyAction::Restart);
        assert_eq!(selector.actions.on_stale, super::PolicyAction::Restart);
    }

    #[test]
    fn policy_without_selectors_defaults_to_wildcard() {
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
  referenceValues:
    - filename: "/a"
      expectedDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
"#,
        )
        .expect("write should succeed");

        let compiled =
            load_compiled_policies(&[policy_path]).expect("policy compilation should succeed");
        let selectors = compiled
            .get("default/p1")
            .expect("compiled policy should exist");
        assert!(selectors.contains_key("*"));
    }
}
