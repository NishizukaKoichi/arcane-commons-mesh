use crate::{
    capability::{CapabilityError, CapabilityManifest},
    identity::{verify_signature, Identity, IdentityError},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAllocation {
    pub recipient_id: String,
    pub amount_minor: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementInstruction {
    pub instruction_version: u16,
    pub instruction_id: String,
    pub capability_id: String,
    pub execution_id: String,
    pub currency: String,
    pub total_minor: u64,
    pub allocations: Vec<SettlementAllocation>,
    pub idempotency_key: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub payer_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Settled,
    Failed,
    Reversed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_version: u16,
    pub receipt_id: String,
    pub instruction_id: String,
    pub rail: String,
    pub rail_reference_hash: String,
    pub status: SettlementStatus,
    pub amount_minor: u64,
    pub currency: String,
    pub occurred_at: i64,
    pub operator_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum SettlementError {
    #[error("invalid settlement record")]
    Invalid,
    #[error("settlement allocation does not conserve the manifest price")]
    Allocation,
    #[error("settlement record is expired or premature")]
    Time,
    #[error("settlement operator is not trusted")]
    Operator,
    #[error("settlement signature verification failed")]
    Signature(#[from] IdentityError),
    #[error("capability manifest verification failed")]
    Capability(#[from] CapabilityError),
}

impl SettlementInstruction {
    pub fn issue(
        manifest: &CapabilityManifest,
        execution_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        issued_at: i64,
        expires_at: i64,
        payer: &Identity,
    ) -> Result<Self, SettlementError> {
        manifest.verify()?;
        let mut allocations = manifest
            .allocations()?
            .into_iter()
            .map(|(recipient_id, amount_minor)| SettlementAllocation {
                recipient_id,
                amount_minor,
            })
            .collect::<Vec<_>>();
        allocations.sort_by(|a, b| a.recipient_id.cmp(&b.recipient_id));
        let mut instruction = Self {
            instruction_version: 1,
            instruction_id: String::new(),
            capability_id: manifest.capability_id.clone(),
            execution_id: execution_id.into(),
            currency: manifest.currency.clone(),
            total_minor: manifest.price_minor,
            allocations,
            idempotency_key: idempotency_key.into(),
            issued_at,
            expires_at,
            payer_public_key: payer.public_key(),
            signature: Vec::new(),
        };
        instruction.validate(manifest)?;
        instruction.instruction_id = format!(
            "seti_{}",
            blake3::hash(&instruction.identity_bytes()).to_hex()
        );
        instruction.signature = payer.sign(&instruction.canonical_bytes()).to_vec();
        Ok(instruction)
    }

    pub fn verify(&self, manifest: &CapabilityManifest, now: i64) -> Result<(), SettlementError> {
        self.validate(manifest)?;
        if now < self.issued_at || now > self.expires_at {
            return Err(SettlementError::Time);
        }
        if self.instruction_id != format!("seti_{}", blake3::hash(&self.identity_bytes()).to_hex())
        {
            return Err(SettlementError::Invalid);
        }
        verify_signature(
            &self.payer_public_key,
            &self.canonical_bytes(),
            &self.signature,
        )?;
        Ok(())
    }

    fn validate(&self, manifest: &CapabilityManifest) -> Result<(), SettlementError> {
        manifest.verify()?;
        let ordered = !self.allocations.is_empty()
            && self
                .allocations
                .windows(2)
                .all(|pair| pair[0].recipient_id < pair[1].recipient_id)
            && self
                .allocations
                .iter()
                .all(|item| !item.recipient_id.is_empty() && item.amount_minor > 0);
        let total = self
            .allocations
            .iter()
            .try_fold(0_u64, |sum, item| sum.checked_add(item.amount_minor))
            .ok_or(SettlementError::Allocation)?;
        if self.instruction_version != 1
            || self.capability_id != manifest.capability_id
            || !self.execution_id.starts_with("exe_")
            || self.currency != manifest.currency
            || self.total_minor != manifest.price_minor
            || total != self.total_minor
            || !ordered
            || self.idempotency_key.len() < 16
            || self.issued_at < 0
            || self.expires_at <= self.issued_at
        {
            return Err(SettlementError::Allocation);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "acm.settlement-instruction.v1",
            self.instruction_version,
            &self.capability_id,
            &self.execution_id,
            &self.currency,
            self.total_minor,
            &self.allocations,
            &self.idempotency_key,
            self.issued_at,
            self.expires_at,
            self.payer_public_key,
        ))
        .expect("serializable")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.identity_bytes();
        bytes.extend_from_slice(self.instruction_id.as_bytes());
        bytes
    }
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        instruction: &SettlementInstruction,
        rail: impl Into<String>,
        rail_reference_hash: impl Into<String>,
        status: SettlementStatus,
        amount_minor: u64,
        occurred_at: i64,
        operator: &Identity,
    ) -> Result<Self, SettlementError> {
        let mut receipt = Self {
            receipt_version: 1,
            receipt_id: String::new(),
            instruction_id: instruction.instruction_id.clone(),
            rail: rail.into(),
            rail_reference_hash: rail_reference_hash.into(),
            status,
            amount_minor,
            currency: instruction.currency.clone(),
            occurred_at,
            operator_public_key: operator.public_key(),
            signature: Vec::new(),
        };
        receipt.validate_shape(instruction)?;
        receipt.receipt_id = format!("setr_{}", blake3::hash(&receipt.identity_bytes()).to_hex());
        receipt.signature = operator.sign(&receipt.canonical_bytes()).to_vec();
        Ok(receipt)
    }

    pub fn verify(
        &self,
        instruction: &SettlementInstruction,
        trusted_operator_public_keys: &[[u8; 32]],
    ) -> Result<(), SettlementError> {
        self.validate_shape(instruction)?;
        if self.receipt_id != format!("setr_{}", blake3::hash(&self.identity_bytes()).to_hex()) {
            return Err(SettlementError::Invalid);
        }
        if !trusted_operator_public_keys.contains(&self.operator_public_key) {
            return Err(SettlementError::Operator);
        }
        verify_signature(
            &self.operator_public_key,
            &self.canonical_bytes(),
            &self.signature,
        )?;
        Ok(())
    }

    fn validate_shape(&self, instruction: &SettlementInstruction) -> Result<(), SettlementError> {
        let amount_valid = match self.status {
            SettlementStatus::Settled | SettlementStatus::Reversed => {
                self.amount_minor == instruction.total_minor
            }
            SettlementStatus::Failed => self.amount_minor == 0,
        };
        if self.receipt_version != 1
            || self.instruction_id != instruction.instruction_id
            || self.rail.trim().is_empty()
            || !is_cid(&self.rail_reference_hash)
            || self.currency != instruction.currency
            || self.occurred_at < instruction.issued_at
            || !amount_valid
        {
            return Err(SettlementError::Invalid);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "acm.settlement-receipt.v1",
            self.receipt_version,
            &self.instruction_id,
            &self.rail,
            &self.rail_reference_hash,
            &self.status,
            self.amount_minor,
            &self.currency,
            self.occurred_at,
            self.operator_public_key,
        ))
        .expect("serializable")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.identity_bytes();
        bytes.extend_from_slice(self.receipt_id.as_bytes());
        bytes
    }
}

fn is_cid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{OfferingKind, RevenueSplit};

    fn manifest() -> CapabilityManifest {
        CapabilityManifest::issue(
            OfferingKind::AttestedResult,
            "verified result",
            "11".repeat(32),
            "22".repeat(32),
            "AUD",
            101,
            vec![
                RevenueSplit {
                    recipient_id: "creator".into(),
                    role: "creator".into(),
                    basis_points: 9_000,
                },
                RevenueSplit {
                    recipient_id: "operator".into(),
                    role: "compute".into(),
                    basis_points: 1_000,
                },
            ],
            10,
            40,
            &Identity::from_seed([91; 32]),
        )
        .unwrap()
    }

    #[test]
    fn instruction_and_receipt_are_exact_idempotent_and_operator_signed() {
        let manifest = manifest();
        let payer = Identity::from_seed([92; 32]);
        let operator = Identity::from_seed([93; 32]);
        let instruction = SettlementInstruction::issue(
            &manifest,
            format!("exe_{}", "33".repeat(32)),
            "order-2026-00000001",
            12,
            30,
            &payer,
        )
        .unwrap();
        instruction.verify(&manifest, 20).unwrap();
        assert_eq!(
            instruction
                .allocations
                .iter()
                .map(|item| item.amount_minor)
                .sum::<u64>(),
            101
        );
        let receipt = SettlementReceipt::issue(
            &instruction,
            "test-signed-rail",
            "44".repeat(32),
            SettlementStatus::Settled,
            101,
            21,
            &operator,
        )
        .unwrap();
        receipt
            .verify(&instruction, &[operator.public_key()])
            .unwrap();
        assert!(matches!(
            receipt.verify(&instruction, &[[0; 32]]),
            Err(SettlementError::Operator)
        ));
    }

    #[test]
    fn failed_receipt_cannot_claim_transferred_value() {
        let manifest = manifest();
        let instruction = SettlementInstruction::issue(
            &manifest,
            format!("exe_{}", "55".repeat(32)),
            "order-2026-00000002",
            12,
            30,
            &Identity::from_seed([94; 32]),
        )
        .unwrap();
        assert!(SettlementReceipt::issue(
            &instruction,
            "test-signed-rail",
            "66".repeat(32),
            SettlementStatus::Failed,
            1,
            21,
            &Identity::from_seed([95; 32]),
        )
        .is_err());
    }
}
