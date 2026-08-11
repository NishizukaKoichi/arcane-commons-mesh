use crate::identity::{verify_signature, Identity, IdentityError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionAttestation {
    pub attestation_version: u16,
    pub execution_id: String,
    pub capability_id: String,
    pub spell_contract_id: String,
    pub runtime_measurement: String,
    pub input_cids: Vec<String>,
    pub output_cid: String,
    pub executor_public_key: [u8; 32],
    pub started_at: i64,
    pub completed_at: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ComputeError {
    #[error("invalid execution attestation")]
    Invalid,
    #[error("runtime measurement is not approved")]
    Measurement,
    #[error("execution signature verification failed")]
    Signature(#[from] IdentityError),
    #[error("confidential runtime evidence is expired or not yet valid")]
    EvidenceTime,
    #[error("confidential runtime evidence issuer is not trusted")]
    EvidenceIssuer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRuntimeEvidence {
    pub evidence_version: u16,
    pub evidence_id: String,
    pub execution_id: String,
    pub provider: String,
    pub quote_cid: String,
    pub runtime_measurement: String,
    pub nonce_cid: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub issuer_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialRuntimePolicy {
    pub trusted_issuer_public_keys: Vec<[u8; 32]>,
    pub approved_measurements: Vec<String>,
    pub now: i64,
}

impl ExecutionAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        capability_id: impl Into<String>,
        spell_contract_id: impl Into<String>,
        runtime_measurement: impl Into<String>,
        mut input_cids: Vec<String>,
        output_cid: impl Into<String>,
        started_at: i64,
        completed_at: i64,
        executor: &Identity,
    ) -> Result<Self, ComputeError> {
        input_cids.sort();
        input_cids.dedup();
        let mut attestation = Self {
            attestation_version: 1,
            execution_id: String::new(),
            capability_id: capability_id.into(),
            spell_contract_id: spell_contract_id.into(),
            runtime_measurement: runtime_measurement.into(),
            input_cids,
            output_cid: output_cid.into(),
            executor_public_key: executor.public_key(),
            started_at,
            completed_at,
            signature: Vec::new(),
        };
        attestation.validate_shape()?;
        attestation.execution_id = format!(
            "exe_{}",
            blake3::hash(&attestation.identity_bytes()).to_hex()
        );
        attestation.signature = executor.sign(&attestation.canonical_bytes()).to_vec();
        Ok(attestation)
    }

    pub fn verify(&self, approved_measurements: &[String]) -> Result<(), ComputeError> {
        self.validate_shape()?;
        if self.execution_id != format!("exe_{}", blake3::hash(&self.identity_bytes()).to_hex()) {
            return Err(ComputeError::Invalid);
        }
        if !approved_measurements
            .iter()
            .any(|value| value == &self.runtime_measurement)
        {
            return Err(ComputeError::Measurement);
        }
        verify_signature(
            &self.executor_public_key,
            &self.canonical_bytes(),
            &self.signature,
        )?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ComputeError> {
        if self.attestation_version != 1
            || !self.capability_id.starts_with("cap_")
            || !self.spell_contract_id.starts_with("spl_")
            || !is_cid(&self.runtime_measurement)
            || self.input_cids.is_empty()
            || self.input_cids.iter().any(|cid| !is_cid(cid))
            || self.input_cids.windows(2).any(|pair| pair[0] >= pair[1])
            || !is_cid(&self.output_cid)
            || self.started_at < 0
            || self.completed_at < self.started_at
        {
            return Err(ComputeError::Invalid);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "acm.execution-attestation.v1",
            self.attestation_version,
            &self.capability_id,
            &self.spell_contract_id,
            &self.runtime_measurement,
            &self.input_cids,
            &self.output_cid,
            self.executor_public_key,
            self.started_at,
            self.completed_at,
        ))
        .expect("serializable")
    }
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.identity_bytes();
        bytes.extend_from_slice(self.execution_id.as_bytes());
        bytes
    }
}

impl ConfidentialRuntimeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        execution: &ExecutionAttestation,
        provider: impl Into<String>,
        quote_cid: impl Into<String>,
        nonce_cid: impl Into<String>,
        issued_at: i64,
        expires_at: i64,
        issuer: &Identity,
    ) -> Result<Self, ComputeError> {
        let mut evidence = Self {
            evidence_version: 1,
            evidence_id: String::new(),
            execution_id: execution.execution_id.clone(),
            provider: provider.into(),
            quote_cid: quote_cid.into(),
            runtime_measurement: execution.runtime_measurement.clone(),
            nonce_cid: nonce_cid.into(),
            issued_at,
            expires_at,
            issuer_public_key: issuer.public_key(),
            signature: Vec::new(),
        };
        evidence.validate_shape()?;
        evidence.evidence_id =
            format!("atee_{}", blake3::hash(&evidence.identity_bytes()).to_hex());
        evidence.signature = issuer.sign(&evidence.canonical_bytes()).to_vec();
        Ok(evidence)
    }

    pub fn verify(
        &self,
        execution: &ExecutionAttestation,
        policy: &ConfidentialRuntimePolicy,
    ) -> Result<(), ComputeError> {
        self.validate_shape()?;
        if self.evidence_id != format!("atee_{}", blake3::hash(&self.identity_bytes()).to_hex())
            || self.execution_id != execution.execution_id
            || self.runtime_measurement != execution.runtime_measurement
        {
            return Err(ComputeError::Invalid);
        }
        if policy.now < self.issued_at || policy.now > self.expires_at {
            return Err(ComputeError::EvidenceTime);
        }
        if !policy
            .trusted_issuer_public_keys
            .contains(&self.issuer_public_key)
        {
            return Err(ComputeError::EvidenceIssuer);
        }
        execution.verify(&policy.approved_measurements)?;
        verify_signature(
            &self.issuer_public_key,
            &self.canonical_bytes(),
            &self.signature,
        )?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ComputeError> {
        if self.evidence_version != 1
            || !self.execution_id.starts_with("exe_")
            || self.provider.trim().is_empty()
            || !is_cid(&self.quote_cid)
            || !is_cid(&self.runtime_measurement)
            || !is_cid(&self.nonce_cid)
            || self.issued_at < 0
            || self.expires_at <= self.issued_at
        {
            return Err(ComputeError::Invalid);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "acm.confidential-runtime-evidence.v1",
            self.evidence_version,
            &self.execution_id,
            &self.provider,
            &self.quote_cid,
            &self.runtime_measurement,
            &self.nonce_cid,
            self.issued_at,
            self.expires_at,
            self.issuer_public_key,
        ))
        .expect("serializable")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.identity_bytes();
        bytes.extend_from_slice(self.evidence_id.as_bytes());
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
    fn only_approved_measured_runtime_attestations_verify() {
        let executor = Identity::from_seed([71; 32]);
        let measurement = "ab".repeat(32);
        let attestation = ExecutionAttestation::issue(
            "cap_x",
            "spl_x",
            &measurement,
            vec!["cd".repeat(32)],
            "ef".repeat(32),
            10,
            11,
            &executor,
        )
        .unwrap();
        attestation
            .verify(std::slice::from_ref(&measurement))
            .unwrap();
        assert!(matches!(
            attestation.verify(&["00".repeat(32)]),
            Err(ComputeError::Measurement)
        ));
    }

    #[test]
    fn confidential_evidence_binds_execution_issuer_measurement_and_time() {
        let executor = Identity::from_seed([72; 32]);
        let issuer = Identity::from_seed([73; 32]);
        let measurement = "12".repeat(32);
        let execution = ExecutionAttestation::issue(
            "cap_x",
            "spl_x",
            &measurement,
            vec!["34".repeat(32)],
            "56".repeat(32),
            10,
            11,
            &executor,
        )
        .unwrap();
        let evidence = ConfidentialRuntimeEvidence::issue(
            &execution,
            "operator.example/tee-adapter",
            "78".repeat(32),
            "90".repeat(32),
            9,
            20,
            &issuer,
        )
        .unwrap();
        let policy = ConfidentialRuntimePolicy {
            trusted_issuer_public_keys: vec![issuer.public_key()],
            approved_measurements: vec![measurement],
            now: 12,
        };
        evidence.verify(&execution, &policy).unwrap();
        let mut untrusted = policy.clone();
        untrusted.trusted_issuer_public_keys = vec![[0; 32]];
        assert!(matches!(
            evidence.verify(&execution, &untrusted),
            Err(ComputeError::EvidenceIssuer)
        ));
        let mut expired = policy;
        expired.now = 21;
        assert!(matches!(
            evidence.verify(&execution, &expired),
            Err(ComputeError::EvidenceTime)
        ));
    }
}
