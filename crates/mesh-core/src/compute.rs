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
}
