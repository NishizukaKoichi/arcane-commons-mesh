use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryProvenance {
    HumanStatement,
    AiInference,
    ExternalDocument,
    CommunityDecision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatus {
    Active,
    Disputed,
    Superseded,
    Withdrawn,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub entry_id: String,
    pub domain: String,
    pub content_cid: String,
    pub provenance: MemoryProvenance,
    pub confidence_basis_points: u16,
    pub status: MemoryStatus,
    pub supersedes: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGrant {
    pub grantee_id: String,
    pub domains: Vec<String>,
    pub purpose: String,
    pub max_reads: u32,
    pub writes_allowed: bool,
    pub expires_at: i64,
}

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("invalid memory entry or grant")]
    Invalid,
    #[error("memory access denied")]
    Denied,
}

impl MemoryGrant {
    pub fn authorize(
        &self,
        domain: &str,
        purpose: &str,
        reads: u32,
        write: bool,
        now: i64,
    ) -> Result<(), MemoryError> {
        if self.grantee_id.is_empty()
            || self.domains.is_empty()
            || self.max_reads == 0
            || self.expires_at < 0
        {
            return Err(MemoryError::Invalid);
        }
        if !self.domains.iter().any(|value| value == domain)
            || self.purpose != purpose
            || reads >= self.max_reads
            || (write && !self.writes_allowed)
            || now > self.expires_at
        {
            return Err(MemoryError::Denied);
        }
        Ok(())
    }
}

impl MemoryEntry {
    pub fn new(
        domain: impl Into<String>,
        content_cid: impl Into<String>,
        provenance: MemoryProvenance,
        confidence_basis_points: u16,
        status: MemoryStatus,
        supersedes: Option<String>,
        created_at: i64,
    ) -> Result<Self, MemoryError> {
        let domain = domain.into();
        let content_cid = content_cid.into();
        if domain.is_empty()
            || content_cid.len() != 64
            || !content_cid.bytes().all(|b| b.is_ascii_hexdigit())
            || confidence_basis_points > 10_000
            || created_at < 0
        {
            return Err(MemoryError::Invalid);
        }
        let id_bytes = serde_json::to_vec(&(
            &domain,
            &content_cid,
            &provenance,
            confidence_basis_points,
            &status,
            &supersedes,
            created_at,
        ))
        .expect("serializable");
        Ok(Self {
            entry_id: format!("memr_{}", blake3::hash(&id_bytes).to_hex()),
            domain,
            content_cid,
            provenance,
            confidence_basis_points,
            status,
            supersedes,
            created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grants_are_domain_purpose_count_write_and_time_bounded() {
        let grant = MemoryGrant {
            grantee_id: "ai-a".into(),
            domains: vec!["cooking".into()],
            purpose: "meal-plan".into(),
            max_reads: 2,
            writes_allowed: false,
            expires_at: 20,
        };
        grant
            .authorize("cooking", "meal-plan", 0, false, 10)
            .unwrap();
        assert!(grant
            .authorize("health", "meal-plan", 0, false, 10)
            .is_err());
        assert!(grant
            .authorize("cooking", "meal-plan", 0, true, 10)
            .is_err());
    }
}
