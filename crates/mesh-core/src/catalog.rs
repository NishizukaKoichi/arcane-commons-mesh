use crate::{
    crypto::{decrypt, encrypt, CryptoError, Envelope, SecretKey},
    identity::Identity,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MANIFEST_KEY_CONTEXT: &str = "arcane-commons-mesh manifest key v1";
const CATALOG_KEY_CONTEXT: &str = "arcane-commons-mesh catalog key v1";

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("catalog or manifest encoding failed")]
    Encoding(#[from] serde_json::Error),
    #[error("catalog owner signature is invalid")]
    Signature,
    #[error("catalog or manifest domain mismatch")]
    Domain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileManifest {
    pub manifest_version: u16,
    pub file_id: String,
    pub file_version_id: String,
    pub relative_path: String,
    pub file_name: String,
    pub mime_type: String,
    pub plaintext_size: u64,
    pub plaintext_hash: String,
    pub modified_at: i64,
    pub created_at: i64,
    pub file_key: [u8; 32],
    pub ordered_chunk_cids: Vec<String>,
    pub chunk_plaintext_lengths: Vec<u32>,
    pub padding_lengths: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogFileVersion {
    pub file_id: String,
    pub file_version_id: String,
    pub encrypted_manifest_cid: String,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
    pub retention_until: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultCatalog {
    pub catalog_version: u64,
    pub vault_id: String,
    pub owner_member_id: String,
    pub previous_catalog_cid: Option<String>,
    pub created_at: i64,
    pub files: Vec<CatalogFileVersion>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVaultCatalog {
    pub catalog: VaultCatalog,
    pub owner_public_key: [u8; 32],
    pub owner_signature: Vec<u8>,
}

pub fn encrypt_manifest(
    vault_master_key: &SecretKey,
    vault_id: &str,
    manifest: &FileManifest,
) -> Result<Envelope, CatalogError> {
    if manifest.manifest_version != 1
        || manifest.ordered_chunk_cids.len() != manifest.chunk_plaintext_lengths.len()
        || manifest.ordered_chunk_cids.len() != manifest.padding_lengths.len()
    {
        return Err(CatalogError::Domain);
    }
    let key = vault_master_key.derive(MANIFEST_KEY_CONTEXT);
    Ok(encrypt(
        &key,
        &serde_json::to_vec(manifest)?,
        manifest_aad(vault_id, &manifest.file_id, &manifest.file_version_id).as_bytes(),
    )?)
}

pub fn decrypt_manifest(
    vault_master_key: &SecretKey,
    vault_id: &str,
    file_id: &str,
    file_version_id: &str,
    envelope: &Envelope,
) -> Result<FileManifest, CatalogError> {
    let key = vault_master_key.derive(MANIFEST_KEY_CONTEXT);
    let manifest: FileManifest = serde_json::from_slice(&decrypt(
        &key,
        envelope,
        manifest_aad(vault_id, file_id, file_version_id).as_bytes(),
    )?)?;
    if manifest.manifest_version != 1
        || manifest.file_id != file_id
        || manifest.file_version_id != file_version_id
        || manifest.ordered_chunk_cids.len() != manifest.chunk_plaintext_lengths.len()
        || manifest.ordered_chunk_cids.len() != manifest.padding_lengths.len()
    {
        return Err(CatalogError::Domain);
    }
    Ok(manifest)
}

pub fn sign_and_encrypt_catalog(
    vault_master_key: &SecretKey,
    owner: &Identity,
    catalog: VaultCatalog,
) -> Result<Envelope, CatalogError> {
    if catalog.catalog_version == 0 || catalog.owner_member_id != owner.member_id() {
        return Err(CatalogError::Domain);
    }
    let canonical = catalog_signing_bytes(&catalog)?;
    let signed = SignedVaultCatalog {
        catalog,
        owner_public_key: owner.public_key(),
        owner_signature: owner.sign(&canonical).to_vec(),
    };
    let key = vault_master_key.derive(CATALOG_KEY_CONTEXT);
    Ok(encrypt(
        &key,
        &serde_json::to_vec(&signed)?,
        catalog_aad(&signed.catalog.vault_id, signed.catalog.catalog_version).as_bytes(),
    )?)
}

pub fn decrypt_and_verify_catalog(
    vault_master_key: &SecretKey,
    vault_id: &str,
    catalog_version: u64,
    expected_owner_public_key: &[u8; 32],
    envelope: &Envelope,
) -> Result<SignedVaultCatalog, CatalogError> {
    let key = vault_master_key.derive(CATALOG_KEY_CONTEXT);
    let signed: SignedVaultCatalog = serde_json::from_slice(&decrypt(
        &key,
        envelope,
        catalog_aad(vault_id, catalog_version).as_bytes(),
    )?)?;
    if signed.catalog.catalog_version != catalog_version
        || signed.catalog.vault_id != vault_id
        || &signed.owner_public_key != expected_owner_public_key
        || signed.catalog.owner_member_id
            != format!("mem_{}", blake3::hash(expected_owner_public_key).to_hex())
    {
        return Err(CatalogError::Domain);
    }
    let key =
        VerifyingKey::from_bytes(expected_owner_public_key).map_err(|_| CatalogError::Signature)?;
    let signature =
        Signature::from_slice(&signed.owner_signature).map_err(|_| CatalogError::Signature)?;
    key.verify(&catalog_signing_bytes(&signed.catalog)?, &signature)
        .map_err(|_| CatalogError::Signature)?;
    Ok(signed)
}

fn manifest_aad(vault_id: &str, file_id: &str, file_version_id: &str) -> String {
    format!("acm.manifest.v1|{vault_id}|{file_id}|{file_version_id}")
}

fn catalog_aad(vault_id: &str, version: u64) -> String {
    format!("acm.catalog.v1|{vault_id}|{version}")
}

fn catalog_signing_bytes(catalog: &VaultCatalog) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = b"acm.catalog-signature.v1|".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(catalog)?);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> FileManifest {
        FileManifest {
            manifest_version: 1,
            file_id: "file-a".into(),
            file_version_id: "file-a-v1".into(),
            relative_path: "private".into(),
            file_name: "secret.txt".into(),
            mime_type: "text/plain".into(),
            plaintext_size: 6,
            plaintext_hash: "a".repeat(64),
            modified_at: 100,
            created_at: 100,
            file_key: [7; 32],
            ordered_chunk_cids: vec!["b".repeat(64)],
            chunk_plaintext_lengths: vec![6],
            padding_lengths: vec![0],
        }
    }

    #[test]
    fn encrypts_manifest_metadata_and_binds_its_identity() {
        let master = SecretKey::random();
        let manifest = manifest();
        let envelope = encrypt_manifest(&master, "vault-a", &manifest).unwrap();
        let encoded = serde_json::to_vec(&envelope).unwrap();
        assert!(!encoded
            .windows(manifest.file_name.len())
            .any(|window| window == manifest.file_name.as_bytes()));
        assert_eq!(
            decrypt_manifest(&master, "vault-a", "file-a", "file-a-v1", &envelope).unwrap(),
            manifest
        );
        assert!(decrypt_manifest(&master, "vault-b", "file-a", "file-a-v1", &envelope).is_err());
    }

    #[test]
    fn catalog_is_encrypted_signed_and_tamper_evident() {
        let master = SecretKey::random();
        let owner = Identity::from_seed([3; 32]);
        let catalog = VaultCatalog {
            catalog_version: 1,
            vault_id: "vault-a".into(),
            owner_member_id: owner.member_id(),
            previous_catalog_cid: None,
            created_at: 100,
            files: vec![CatalogFileVersion {
                file_id: "file-a".into(),
                file_version_id: "file-a-v1".into(),
                encrypted_manifest_cid: "c".repeat(64),
                created_at: 100,
                deleted_at: None,
                retention_until: None,
            }],
        };
        let envelope = sign_and_encrypt_catalog(&master, &owner, catalog.clone()).unwrap();
        let decoded =
            decrypt_and_verify_catalog(&master, "vault-a", 1, &owner.public_key(), &envelope)
                .unwrap();
        assert_eq!(decoded.catalog, catalog);
        let mut tampered = decoded;
        tampered.catalog.created_at += 1;
        let key = master.derive(CATALOG_KEY_CONTEXT);
        let forged = encrypt(
            &key,
            &serde_json::to_vec(&tampered).unwrap(),
            catalog_aad("vault-a", 1).as_bytes(),
        )
        .unwrap();
        assert!(
            decrypt_and_verify_catalog(&master, "vault-a", 1, &owner.public_key(), &forged)
                .is_err()
        );
    }
}
