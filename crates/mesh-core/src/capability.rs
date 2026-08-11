use crate::identity::{verify_signature, Identity, IdentityError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferingKind {
    Release,
    Access,
    Query,
    CapabilityInvocation,
    ContinuousFeed,
    AttestedResult,
    OutcomeContract,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenueSplit {
    pub recipient_id: String,
    pub role: String,
    pub basis_points: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub manifest_version: u16,
    pub capability_id: String,
    pub creator_public_key: [u8; 32],
    pub kind: OfferingKind,
    pub title: String,
    pub package_cid: String,
    pub execution_policy_cid: String,
    pub currency: String,
    pub price_minor: u64,
    pub splits: Vec<RevenueSplit>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("invalid capability manifest")]
    Invalid,
    #[error("revenue splits must be unique and total 10000 basis points")]
    Splits,
    #[error("capability signature verification failed")]
    Signature(#[from] IdentityError),
}

impl CapabilityManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        kind: OfferingKind,
        title: impl Into<String>,
        package_cid: impl Into<String>,
        execution_policy_cid: impl Into<String>,
        currency: impl Into<String>,
        price_minor: u64,
        mut splits: Vec<RevenueSplit>,
        issued_at: i64,
        expires_at: i64,
        creator: &Identity,
    ) -> Result<Self, CapabilityError> {
        splits.sort_by(|a, b| {
            a.recipient_id
                .cmp(&b.recipient_id)
                .then(a.role.cmp(&b.role))
        });
        let mut manifest = Self {
            manifest_version: 1,
            capability_id: String::new(),
            creator_public_key: creator.public_key(),
            kind,
            title: title.into(),
            package_cid: package_cid.into(),
            execution_policy_cid: execution_policy_cid.into(),
            currency: currency.into(),
            price_minor,
            splits,
            issued_at,
            expires_at,
            signature: Vec::new(),
        };
        manifest.validate_shape()?;
        manifest.capability_id =
            format!("cap_{}", blake3::hash(&manifest.identity_bytes()).to_hex());
        manifest.signature = creator.sign(&manifest.canonical_bytes()).to_vec();
        Ok(manifest)
    }

    pub fn verify(&self) -> Result<(), CapabilityError> {
        self.validate_shape()?;
        if self.capability_id != format!("cap_{}", blake3::hash(&self.identity_bytes()).to_hex()) {
            return Err(CapabilityError::Invalid);
        }
        verify_signature(
            &self.creator_public_key,
            &self.canonical_bytes(),
            &self.signature,
        )?;
        Ok(())
    }

    pub fn allocations(&self) -> Result<Vec<(String, u64)>, CapabilityError> {
        self.verify()?;
        let mut allocated = 0_u64;
        let mut values = Vec::with_capacity(self.splits.len());
        for (index, split) in self.splits.iter().enumerate() {
            let amount = if index + 1 == self.splits.len() {
                self.price_minor - allocated
            } else {
                self.price_minor
                    .saturating_mul(u64::from(split.basis_points))
                    / 10_000
            };
            allocated += amount;
            values.push((split.recipient_id.clone(), amount));
        }
        Ok(values)
    }

    fn validate_shape(&self) -> Result<(), CapabilityError> {
        if self.manifest_version != 1
            || self.title.is_empty()
            || self.currency.len() != 3
            || self.price_minor == 0
            || self.issued_at < 0
            || self.expires_at <= self.issued_at
            || !is_cid(&self.package_cid)
            || !is_cid(&self.execution_policy_cid)
        {
            return Err(CapabilityError::Invalid);
        }
        let ordered = !self.splits.is_empty()
            && self.splits.iter().all(|split| {
                !split.recipient_id.is_empty() && !split.role.is_empty() && split.basis_points > 0
            })
            && self.splits.windows(2).all(|pair| {
                (&pair[0].recipient_id, &pair[0].role) < (&pair[1].recipient_id, &pair[1].role)
            });
        let total: u32 = self
            .splits
            .iter()
            .map(|split| u32::from(split.basis_points))
            .sum();
        if !ordered || total != 10_000 {
            return Err(CapabilityError::Splits);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "acm.capability-manifest.v1",
            self.manifest_version,
            self.creator_public_key,
            &self.kind,
            &self.title,
            &self.package_cid,
            &self.execution_policy_cid,
            &self.currency,
            self.price_minor,
            &self.splits,
            self.issued_at,
            self.expires_at,
        ))
        .expect("capability manifest contains serializable values")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = self.identity_bytes();
        output.extend_from_slice(self.capability_id.as_bytes());
        output
    }
}

fn is_cid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_portable_signed_and_split_exactly() {
        let creator = Identity::from_seed([61; 32]);
        let manifest = CapabilityManifest::issue(
            OfferingKind::CapabilityInvocation,
            "one analysis",
            "ab".repeat(32),
            "cd".repeat(32),
            "AUD",
            101,
            vec![
                RevenueSplit {
                    recipient_id: "storage".into(),
                    role: "storage".into(),
                    basis_points: 1_000,
                },
                RevenueSplit {
                    recipient_id: "creator".into(),
                    role: "creator".into(),
                    basis_points: 9_000,
                },
            ],
            10,
            30,
            &creator,
        )
        .unwrap();
        manifest.verify().unwrap();
        assert_eq!(
            manifest
                .allocations()
                .unwrap()
                .iter()
                .map(|item| item.1)
                .sum::<u64>(),
            101
        );
    }

    #[test]
    fn money_does_not_create_an_invalid_split() {
        let creator = Identity::from_seed([62; 32]);
        assert!(matches!(
            CapabilityManifest::issue(
                OfferingKind::Query,
                "query",
                "ab".repeat(32),
                "cd".repeat(32),
                "AUD",
                10,
                vec![RevenueSplit {
                    recipient_id: "buyer".into(),
                    role: "voter".into(),
                    basis_points: 9_999
                }],
                10,
                30,
                &creator
            ),
            Err(CapabilityError::Splits)
        ));
    }
}
