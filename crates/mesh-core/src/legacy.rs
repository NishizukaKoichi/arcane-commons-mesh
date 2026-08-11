use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyAction {
    Transfer,
    Publish,
    Delete,
    RetainPrivate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyDirective {
    pub directive_id: String,
    pub subject_cid: String,
    pub action: LegacyAction,
    pub beneficiary_id: Option<String>,
    pub not_before: i64,
    pub required_approvals: u16,
    pub eligible_guardians: Vec<String>,
}

#[derive(Debug, Error)]
pub enum LegacyError {
    #[error("invalid legacy directive")]
    Invalid,
    #[error("legacy directive is time locked")]
    TimeLock,
    #[error("insufficient independent guardian approvals")]
    Approvals,
}

impl LegacyDirective {
    pub fn new(
        subject_cid: impl Into<String>,
        action: LegacyAction,
        beneficiary_id: Option<String>,
        not_before: i64,
        required_approvals: u16,
        mut eligible_guardians: Vec<String>,
    ) -> Result<Self, LegacyError> {
        let subject_cid = subject_cid.into();
        eligible_guardians.sort();
        eligible_guardians.dedup();
        if subject_cid.len() != 64
            || !subject_cid.bytes().all(|b| b.is_ascii_hexdigit())
            || not_before < 0
            || required_approvals == 0
            || usize::from(required_approvals) > eligible_guardians.len()
            || eligible_guardians.iter().any(String::is_empty)
            || (matches!(action, LegacyAction::Transfer)
                && beneficiary_id.as_deref().is_none_or(str::is_empty))
        {
            return Err(LegacyError::Invalid);
        }
        let bytes = serde_json::to_vec(&(
            &subject_cid,
            &action,
            &beneficiary_id,
            not_before,
            required_approvals,
            &eligible_guardians,
        ))
        .expect("serializable");
        Ok(Self {
            directive_id: format!("leg_{}", blake3::hash(&bytes).to_hex()),
            subject_cid,
            action,
            beneficiary_id,
            not_before,
            required_approvals,
            eligible_guardians,
        })
    }
    pub fn authorize(&self, now: i64, approvals: &[String]) -> Result<(), LegacyError> {
        if now < self.not_before {
            return Err(LegacyError::TimeLock);
        }
        let unique: BTreeSet<_> = approvals
            .iter()
            .filter(|id| self.eligible_guardians.contains(id))
            .collect();
        if unique.len() < usize::from(self.required_approvals) {
            return Err(LegacyError::Approvals);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_time_and_distinct_guardians() {
        let d = LegacyDirective::new(
            "ab".repeat(32),
            LegacyAction::Delete,
            None,
            20,
            2,
            vec!["a".into(), "b".into(), "c".into()],
        )
        .unwrap();
        assert!(matches!(
            d.authorize(19, &["a".into(), "b".into()]),
            Err(LegacyError::TimeLock)
        ));
        assert!(matches!(
            d.authorize(20, &["a".into(), "a".into()]),
            Err(LegacyError::Approvals)
        ));
        d.authorize(20, &["a".into(), "b".into()]).unwrap();
    }
}
