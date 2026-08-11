use crate::identity::{verify_signature, Identity, IdentityError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ratification {
    pub ratifier_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrimoireRecord {
    pub record_version: u16,
    pub record_id: String,
    pub community_id: String,
    pub knowledge_cid: String,
    pub rationale_cid: String,
    pub alternative_cids: Vec<String>,
    pub exception_cids: Vec<String>,
    pub contributor_ids: Vec<String>,
    pub supersedes: Option<String>,
    pub ratification_threshold: u16,
    pub ratifications: Vec<Ratification>,
    pub confirmed_at: i64,
}

#[derive(Debug, Error)]
pub enum GrimoireError {
    #[error("invalid grimoire record")]
    Invalid,
    #[error("insufficient independent ratifications")]
    Ratification,
    #[error("grimoire ratification signature failed")]
    Signature(#[from] IdentityError),
}

impl GrimoireRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn confirm(
        community_id: impl Into<String>,
        knowledge_cid: impl Into<String>,
        rationale_cid: impl Into<String>,
        mut alternative_cids: Vec<String>,
        mut exception_cids: Vec<String>,
        mut contributor_ids: Vec<String>,
        supersedes: Option<String>,
        ratification_threshold: u16,
        ratifiers: &[&Identity],
        confirmed_at: i64,
    ) -> Result<Self, GrimoireError> {
        alternative_cids.sort();
        alternative_cids.dedup();
        exception_cids.sort();
        exception_cids.dedup();
        contributor_ids.sort();
        contributor_ids.dedup();
        let mut record = Self {
            record_version: 1,
            record_id: String::new(),
            community_id: community_id.into(),
            knowledge_cid: knowledge_cid.into(),
            rationale_cid: rationale_cid.into(),
            alternative_cids,
            exception_cids,
            contributor_ids,
            supersedes,
            ratification_threshold,
            ratifications: Vec::new(),
            confirmed_at,
        };
        record.validate_shape()?;
        record.record_id = format!("gri_{}", blake3::hash(&record.identity_bytes()).to_hex());
        let message = record.canonical_bytes();
        let mut seen = BTreeSet::new();
        for ratifier in ratifiers {
            let key = ratifier.public_key();
            if seen.insert(key) {
                record.ratifications.push(Ratification {
                    ratifier_public_key: key,
                    signature: ratifier.sign(&message).to_vec(),
                });
            }
        }
        record
            .ratifications
            .sort_by_key(|item| item.ratifier_public_key);
        record.verify()?;
        Ok(record)
    }

    pub fn verify(&self) -> Result<(), GrimoireError> {
        self.validate_shape()?;
        if self.record_id != format!("gri_{}", blake3::hash(&self.identity_bytes()).to_hex()) {
            return Err(GrimoireError::Invalid);
        }
        if self.ratifications.len() < usize::from(self.ratification_threshold)
            || self
                .ratifications
                .windows(2)
                .any(|pair| pair[0].ratifier_public_key >= pair[1].ratifier_public_key)
        {
            return Err(GrimoireError::Ratification);
        }
        let message = self.canonical_bytes();
        for ratification in &self.ratifications {
            verify_signature(
                &ratification.ratifier_public_key,
                &message,
                &ratification.signature,
            )?;
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), GrimoireError> {
        if self.record_version != 1
            || self.community_id.is_empty()
            || !is_cid(&self.knowledge_cid)
            || !is_cid(&self.rationale_cid)
            || self.alternative_cids.iter().any(|cid| !is_cid(cid))
            || self.exception_cids.iter().any(|cid| !is_cid(cid))
            || self
                .alternative_cids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .exception_cids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.contributor_ids.is_empty()
            || self.contributor_ids.iter().any(String::is_empty)
            || self
                .contributor_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.ratification_threshold == 0
            || self.confirmed_at < 0
        {
            return Err(GrimoireError::Invalid);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "acm.grimoire-record.v1",
            self.record_version,
            &self.community_id,
            &self.knowledge_cid,
            &self.rationale_cid,
            &self.alternative_cids,
            &self.exception_cids,
            &self.contributor_ids,
            &self.supersedes,
            self.ratification_threshold,
            self.confirmed_at,
        ))
        .expect("grimoire record is serializable")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.identity_bytes();
        bytes.extend_from_slice(self.record_id.as_bytes());
        bytes
    }
}

fn is_cid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn community_knowledge_preserves_reason_exceptions_contributors_and_quorum() {
        let a = Identity::from_seed([91; 32]);
        let b = Identity::from_seed([92; 32]);
        let record = GrimoireRecord::confirm(
            "workshop-a",
            "11".repeat(32),
            "22".repeat(32),
            vec!["33".repeat(32)],
            vec!["44".repeat(32)],
            vec!["contributor-b".into(), "contributor-a".into()],
            None,
            2,
            &[&a, &b],
            100,
        )
        .unwrap();
        record.verify().unwrap();
        assert_eq!(record.ratifications.len(), 2);
        assert_eq!(record.contributor_ids[0], "contributor-a");
    }

    #[test]
    fn duplicate_ratifier_cannot_satisfy_quorum() {
        let a = Identity::from_seed([93; 32]);
        assert!(matches!(
            GrimoireRecord::confirm(
                "workshop-a",
                "11".repeat(32),
                "22".repeat(32),
                vec![],
                vec![],
                vec!["contributor".into()],
                None,
                2,
                &[&a, &a],
                100,
            ),
            Err(GrimoireError::Ratification)
        ));
    }
}
