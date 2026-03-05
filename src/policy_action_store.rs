use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::{Result, ServiceError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyAction {
    #[default]
    None,
    Alert,
    Restart,
    Kill,
}

impl PolicyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyAction::None => "none",
            PolicyAction::Alert => "alert",
            PolicyAction::Restart => "restart",
            PolicyAction::Kill => "kill",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyCondition {
    Untrusted,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SelectorPolicyAction {
    pub on_untrusted: PolicyAction,
    pub on_stale: PolicyAction,
}

impl SelectorPolicyAction {
    fn for_condition(self, condition: PolicyCondition) -> PolicyAction {
        match condition {
            PolicyCondition::Untrusted => self.on_untrusted,
            PolicyCondition::Stale => self.on_stale,
        }
    }
}

pub trait PolicyActionStore: Send + Sync {
    fn replace_policy_actions(
        &self,
        policy_id: &str,
        selector_actions: HashMap<String, SelectorPolicyAction>,
    ) -> Result<()>;
    fn remove_policy_actions(&self, policy_id: &str) -> Result<()>;
    fn resolve_action(&self, identities: &[String], condition: PolicyCondition) -> PolicyAction;
}

#[derive(Debug, Default)]
struct ActionState {
    policies: HashMap<String, HashMap<String, SelectorPolicyAction>>,
}

#[derive(Debug, Default)]
pub struct InMemoryPolicyActionStore {
    state: RwLock<ActionState>,
}

impl InMemoryPolicyActionStore {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(ActionState::default()),
        }
    }
}

impl PolicyActionStore for InMemoryPolicyActionStore {
    fn replace_policy_actions(
        &self,
        policy_id: &str,
        selector_actions: HashMap<String, SelectorPolicyAction>,
    ) -> Result<()> {
        if policy_id.is_empty() {
            return Err(ServiceError::InvalidInput(
                "policy id is required".to_owned(),
            ));
        }

        let mut guard = self.state.write().map_err(|_| {
            ServiceError::Internal("policy action store write lock poisoned".to_owned())
        })?;
        guard
            .policies
            .insert(policy_id.to_owned(), selector_actions);
        Ok(())
    }

    fn remove_policy_actions(&self, policy_id: &str) -> Result<()> {
        if policy_id.is_empty() {
            return Err(ServiceError::InvalidInput(
                "policy id is required".to_owned(),
            ));
        }

        let mut guard = self.state.write().map_err(|_| {
            ServiceError::Internal("policy action store write lock poisoned".to_owned())
        })?;
        guard.policies.remove(policy_id);
        Ok(())
    }

    fn resolve_action(&self, identities: &[String], condition: PolicyCondition) -> PolicyAction {
        let guard = match self.state.read() {
            Ok(guard) => guard,
            Err(_) => return PolicyAction::None,
        };

        let mut policy_ids = guard.policies.keys().cloned().collect::<Vec<_>>();
        policy_ids.sort_unstable();

        for identity in identities {
            if identity.is_empty() {
                continue;
            }

            let mut best: Option<(SelectorPolicyAction, usize)> = None;
            for policy_id in &policy_ids {
                let Some(selectors) = guard.policies.get(policy_id) else {
                    continue;
                };

                for (selector, action) in selectors {
                    if selector == identity {
                        let chosen = action.for_condition(condition);
                        if chosen != PolicyAction::None {
                            return chosen;
                        }
                        continue;
                    }

                    if !is_glob_pattern(selector) || !glob_matches(selector, identity) {
                        continue;
                    }

                    let specificity = selector
                        .chars()
                        .filter(|ch| *ch != '*' && *ch != '?')
                        .count();
                    match best {
                        None => best = Some((*action, specificity)),
                        Some((_, current_specificity)) if specificity > current_specificity => {
                            best = Some((*action, specificity))
                        }
                        _ => {}
                    }
                }
            }

            if let Some((best_action, _)) = best {
                let chosen = best_action.for_condition(condition);
                if chosen != PolicyAction::None {
                    return chosen;
                }
            }
        }

        PolicyAction::None
    }
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        InMemoryPolicyActionStore, PolicyAction, PolicyActionStore, PolicyCondition,
        SelectorPolicyAction,
    };

    #[test]
    fn exact_match_overrides_glob() {
        let store = InMemoryPolicyActionStore::new();

        store
            .replace_policy_actions(
                "default/policy-a",
                HashMap::from([(
                    "cgroup://*".to_owned(),
                    SelectorPolicyAction {
                        on_untrusted: PolicyAction::Alert,
                        on_stale: PolicyAction::Alert,
                    },
                )]),
            )
            .expect("policy should be stored");
        store
            .replace_policy_actions(
                "default/policy-b",
                HashMap::from([(
                    "cgroup://cg1".to_owned(),
                    SelectorPolicyAction {
                        on_untrusted: PolicyAction::Restart,
                        on_stale: PolicyAction::None,
                    },
                )]),
            )
            .expect("policy should be stored");

        let action = store.resolve_action(&["cgroup://cg1".to_owned()], PolicyCondition::Untrusted);
        assert_eq!(action, PolicyAction::Restart);
    }

    #[test]
    fn none_is_returned_when_no_selector_matches() {
        let store = InMemoryPolicyActionStore::new();
        let action =
            store.resolve_action(&["cgroup://missing".to_owned()], PolicyCondition::Untrusted);
        assert_eq!(action, PolicyAction::None);
    }
}
