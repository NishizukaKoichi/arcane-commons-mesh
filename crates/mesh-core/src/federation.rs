use crate::identity::{verify_signature, Identity, IdentityError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportItem {
    pub category: String,
    pub item_id: String,
    pub content_cid: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationBundle {
    pub bundle_version: u16,
    pub bundle_id: String,
    pub source_community_id: String,
    pub target_community_id: Option<String>,
    pub owner_public_key: [u8; 32],
    pub items: Vec<ExportItem>,
    pub created_at: i64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReceipt {
    pub receipt_version: u16,
    pub bundle_id: String,
    pub target_community_id: String,
    pub imported_root: String,
    pub operator_public_key: [u8; 32],
    pub imported_at: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("invalid federation bundle or receipt")]
    Invalid,
    #[error("duplicate or unordered export item")]
    ItemOrder,
    #[error("federation signature verification failed")]
    Signature(#[from] IdentityError),
}

impl FederationBundle {
    pub fn export(
        source_community_id: impl Into<String>,
        target_community_id: Option<String>,
        mut items: Vec<ExportItem>,
        created_at: i64,
        owner: &Identity,
    ) -> Result<Self, FederationError> {
        items.sort_by(|a, b| (&a.category, &a.item_id).cmp(&(&b.category, &b.item_id)));
        let mut bundle = Self {
            bundle_version: 1,
            bundle_id: String::new(),
            source_community_id: source_community_id.into(),
            target_community_id,
            owner_public_key: owner.public_key(),
            items,
            created_at,
            signature: Vec::new(),
        };
        bundle.validate_shape()?;
        bundle.bundle_id = format!("exp_{}", blake3::hash(&bundle.identity_bytes()).to_hex());
        bundle.signature = owner.sign(&bundle.canonical_bytes()).to_vec();
        Ok(bundle)
    }

    pub fn verify(&self) -> Result<(), FederationError> {
        self.validate_shape()?;
        if self.bundle_id != format!("exp_{}", blake3::hash(&self.identity_bytes()).to_hex()) {
            return Err(FederationError::Invalid);
        }
        verify_signature(
            &self.owner_public_key,
            &self.canonical_bytes(),
            &self.signature,
        )?;
        Ok(())
    }

    pub fn merkle_root(&self) -> String {
        let mut hashes: Vec<[u8; 32]> = self
            .items
            .iter()
            .map(|item| {
                *blake3::hash(
                    serde_json::to_vec(item)
                        .expect("export item is serializable")
                        .as_slice(),
                )
                .as_bytes()
            })
            .collect();
        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                hashes.push(*hashes.last().expect("non-empty hash level"));
            }
            hashes = hashes
                .chunks_exact(2)
                .map(|pair| {
                    let mut bytes = [0_u8; 64];
                    bytes[..32].copy_from_slice(&pair[0]);
                    bytes[32..].copy_from_slice(&pair[1]);
                    *blake3::hash(&bytes).as_bytes()
                })
                .collect();
        }
        blake3::Hash::from_bytes(hashes[0]).to_hex().to_string()
    }

    fn validate_shape(&self) -> Result<(), FederationError> {
        if self.bundle_version != 1
            || self.source_community_id.is_empty()
            || self
                .target_community_id
                .as_deref()
                .is_some_and(str::is_empty)
            || self.items.is_empty()
            || self.created_at < 0
            || self.items.iter().any(|item| {
                item.category.is_empty() || item.item_id.is_empty() || !is_cid(&item.content_cid)
            })
        {
            return Err(FederationError::Invalid);
        }
        if self.items.windows(2).any(|pair| {
            (&pair[0].category, &pair[0].item_id) >= (&pair[1].category, &pair[1].item_id)
        }) {
            return Err(FederationError::ItemOrder);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "acm.federation-bundle.v1",
            self.bundle_version,
            &self.source_community_id,
            &self.target_community_id,
            self.owner_public_key,
            &self.items,
            self.created_at,
        ))
        .expect("federation bundle is serializable")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.identity_bytes();
        bytes.extend_from_slice(self.bundle_id.as_bytes());
        bytes
    }
}

impl MigrationReceipt {
    pub fn issue(
        bundle: &FederationBundle,
        target_community_id: impl Into<String>,
        imported_at: i64,
        operator: &Identity,
    ) -> Result<Self, FederationError> {
        bundle.verify()?;
        let target_community_id = target_community_id.into();
        if bundle.target_community_id.as_deref() != Some(&target_community_id) {
            return Err(FederationError::Invalid);
        }
        let mut receipt = Self {
            receipt_version: 1,
            bundle_id: bundle.bundle_id.clone(),
            target_community_id,
            imported_root: bundle.merkle_root(),
            operator_public_key: operator.public_key(),
            imported_at,
            signature: Vec::new(),
        };
        receipt.validate_shape()?;
        receipt.signature = operator.sign(&receipt.canonical_bytes()).to_vec();
        Ok(receipt)
    }

    pub fn verify(&self, bundle: &FederationBundle) -> Result<(), FederationError> {
        self.validate_shape()?;
        bundle.verify()?;
        if self.bundle_id != bundle.bundle_id || self.imported_root != bundle.merkle_root() {
            return Err(FederationError::Invalid);
        }
        verify_signature(
            &self.operator_public_key,
            &self.canonical_bytes(),
            &self.signature,
        )?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), FederationError> {
        if self.receipt_version != 1
            || !self.bundle_id.starts_with("exp_")
            || self.target_community_id.is_empty()
            || !is_cid(&self.imported_root)
            || self.imported_at < 0
        {
            return Err(FederationError::Invalid);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            "acm.migration-receipt.v1",
            self.receipt_version,
            &self.bundle_id,
            &self.target_community_id,
            &self.imported_root,
            self.operator_public_key,
            self.imported_at,
        ))
        .expect("migration receipt is serializable")
    }
}

fn is_cid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_export_is_signed_tamper_evident_and_receipted_by_target() {
        let owner = Identity::from_seed([101; 32]);
        let target = Identity::from_seed([102; 32]);
        let bundle = FederationBundle::export(
            "community-a",
            Some("community-b".into()),
            vec![
                ExportItem {
                    category: "memory".into(),
                    item_id: "m1".into(),
                    content_cid: "11".repeat(32),
                },
                ExportItem {
                    category: "identity".into(),
                    item_id: "i1".into(),
                    content_cid: "22".repeat(32),
                },
            ],
            100,
            &owner,
        )
        .unwrap();
        bundle.verify().unwrap();
        let receipt = MigrationReceipt::issue(&bundle, "community-b", 101, &target).unwrap();
        receipt.verify(&bundle).unwrap();
    }
}
