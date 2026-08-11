use crate::identity::{verify_signature, Identity, IdentityError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchRecordKind {
    Hypothesis,
    Dataset,
    Experiment,
    Analysis,
    Failure,
    Decision,
    Claim,
    Reproduction,
    Correction,
    Retraction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchRecord {
    pub record_version: u16,
    pub record_id: String,
    pub project_id: String,
    pub kind: ResearchRecordKind,
    pub parent_ids: Vec<String>,
    pub content_cid: String,
    pub author_public_key: [u8; 32],
    pub created_at: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ResearchError {
    #[error("invalid research record")]
    Invalid,
    #[error("duplicate or unordered parent reference")]
    ParentOrder,
    #[error("correction and retraction records require a parent")]
    MissingTarget,
    #[error("research signature verification failed")]
    Signature(#[from] IdentityError),
}

impl ResearchRecord {
    pub fn issue(
        project_id: impl Into<String>,
        kind: ResearchRecordKind,
        mut parent_ids: Vec<String>,
        content_cid: impl Into<String>,
        created_at: i64,
        author: &Identity,
    ) -> Result<Self, ResearchError> {
        parent_ids.sort();
        parent_ids.dedup();
        let mut record = Self {
            record_version: 1,
            record_id: String::new(),
            project_id: project_id.into(),
            kind,
            parent_ids,
            content_cid: content_cid.into(),
            author_public_key: author.public_key(),
            created_at,
            signature: Vec::new(),
        };
        record.validate_shape()?;
        record.record_id = format!("res_{}", blake3::hash(&record.identity_bytes()).to_hex());
        record.signature = author.sign(&record.canonical_bytes()).to_vec();
        Ok(record)
    }

    pub fn verify(&self) -> Result<(), ResearchError> {
        self.validate_shape()?;
        if self.record_id != format!("res_{}", blake3::hash(&self.identity_bytes()).to_hex()) {
            return Err(ResearchError::Invalid);
        }
        verify_signature(
            &self.author_public_key,
            &self.canonical_bytes(),
            &self.signature,
        )?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ResearchError> {
        if self.record_version != 1
            || self.project_id.is_empty()
            || self.created_at < 0
            || !is_cid(&self.content_cid)
        {
            return Err(ResearchError::Invalid);
        }
        if self.parent_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ResearchError::ParentOrder);
        }
        if matches!(
            self.kind,
            ResearchRecordKind::Correction | ResearchRecordKind::Retraction
        ) && self.parent_ids.is_empty()
        {
            return Err(ResearchError::MissingTarget);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        field(&mut output, b"acm.research-record.v1");
        output.extend_from_slice(&self.record_version.to_be_bytes());
        field(&mut output, self.project_id.as_bytes());
        field(&mut output, format!("{:?}", self.kind).as_bytes());
        output.extend_from_slice(&(self.parent_ids.len() as u32).to_be_bytes());
        for parent in &self.parent_ids {
            field(&mut output, parent.as_bytes());
        }
        field(&mut output, self.content_cid.as_bytes());
        field(&mut output, &self.author_public_key);
        output.extend_from_slice(&self.created_at.to_be_bytes());
        output
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = self.identity_bytes();
        field(&mut output, self.record_id.as_bytes());
        output
    }
}

fn is_cid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_causal_records_are_tamper_evident_and_append_only() {
        let researcher = Identity::from_seed([41; 32]);
        let hypothesis = ResearchRecord::issue(
            "project-a",
            ResearchRecordKind::Hypothesis,
            vec![],
            "ab".repeat(32),
            10,
            &researcher,
        )
        .unwrap();
        hypothesis.verify().unwrap();

        let correction = ResearchRecord::issue(
            "project-a",
            ResearchRecordKind::Correction,
            vec![hypothesis.record_id.clone()],
            "cd".repeat(32),
            20,
            &researcher,
        )
        .unwrap();
        correction.verify().unwrap();
        assert_eq!(correction.parent_ids, vec![hypothesis.record_id]);

        let mut tampered = correction;
        tampered.content_cid = "ef".repeat(32);
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn correction_requires_an_explicit_target() {
        let researcher = Identity::from_seed([42; 32]);
        assert!(matches!(
            ResearchRecord::issue(
                "project-a",
                ResearchRecordKind::Retraction,
                vec![],
                "ab".repeat(32),
                10,
                &researcher,
            ),
            Err(ResearchError::MissingTarget)
        ));
    }
}
