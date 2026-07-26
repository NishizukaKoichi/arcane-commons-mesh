use crate::crypto::{decrypt, encrypt, CryptoError, Envelope, SecretKey};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

const MIN_MEMORY_KIB: u32 = 64 * 1024;
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const DEFAULT_MEMORY_KIB: u32 = 256 * 1024;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("invalid recovery parameters")]
    Parameters,
    #[error("invalid recovery file")]
    Invalid,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryPayload {
    pub identity_seed: [u8; 32],
    pub vault_master_key: [u8; 32],
    pub community_ids: Vec<String>,
    pub control_plane_urls: Vec<String>,
    #[serde(default)]
    pub vaults: Vec<RecoveryVaultPointer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryVaultPointer {
    pub vault_id: String,
    pub catalog_cid: String,
    pub catalog_version: u64,
    pub owner_public_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryFile {
    pub format_version: u16,
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub salt: [u8; 16],
    pub envelope: Envelope,
}

fn aad(file: &RecoveryFile) -> Vec<u8> {
    format!(
        "acm.recovery.v1|{}|{}|{}|{}|{}",
        file.format_version, file.algorithm, file.memory_kib, file.iterations, file.lanes
    )
    .into_bytes()
}

fn derive(
    passphrase: &[u8],
    salt: &[u8; 16],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<SecretKey, RecoveryError> {
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory_kib)
        || !(3..=10).contains(&iterations)
        || !(1..=4).contains(&lanes)
    {
        return Err(RecoveryError::Parameters);
    }
    let params = Params::new(memory_kib, iterations, lanes, Some(32))
        .map_err(|_| RecoveryError::Parameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(passphrase, salt, output.as_mut())
        .map_err(|_| RecoveryError::Parameters)?;
    Ok(SecretKey(*output))
}

pub fn export(payload: &RecoveryPayload, passphrase: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    let mut salt = [0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive(passphrase, &salt, DEFAULT_MEMORY_KIB, 3, 1)?;
    let mut file = RecoveryFile {
        format_version: 1,
        algorithm: "Argon2id+XChaCha20-Poly1305".into(),
        memory_kib: DEFAULT_MEMORY_KIB,
        iterations: 3,
        lanes: 1,
        salt,
        envelope: Envelope {
            version: 1,
            algorithm: "XChaCha20-Poly1305".into(),
            nonce: [0; 24],
            ciphertext: vec![],
        },
    };
    let plaintext =
        Zeroizing::new(serde_json::to_vec(payload).map_err(|_| RecoveryError::Invalid)?);
    file.envelope = encrypt(&key, plaintext.as_ref(), &aad(&file))?;
    serde_json::to_vec(&file).map_err(|_| RecoveryError::Invalid)
}

pub fn import(bytes: &[u8], passphrase: &[u8]) -> Result<RecoveryPayload, RecoveryError> {
    let file: RecoveryFile = serde_json::from_slice(bytes).map_err(|_| RecoveryError::Invalid)?;
    if file.format_version != 1 || file.algorithm != "Argon2id+XChaCha20-Poly1305" {
        return Err(RecoveryError::Invalid);
    }
    let key = derive(
        passphrase,
        &file.salt,
        file.memory_kib,
        file.iterations,
        file.lanes,
    )?;
    let plaintext = Zeroizing::new(decrypt(&key, &file.envelope, &aad(&file))?);
    serde_json::from_slice(plaintext.as_ref()).map_err(|_| RecoveryError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> RecoveryPayload {
        RecoveryPayload {
            identity_seed: [7; 32],
            vault_master_key: [9; 32],
            community_ids: vec!["community-test".into()],
            control_plane_urls: vec!["http://127.0.0.1:8787".into()],
            vaults: vec![RecoveryVaultPointer {
                vault_id: "vault-test".into(),
                catalog_cid: "b3:test".into(),
                catalog_version: 7,
                owner_public_key: [3; 32],
            }],
        }
    }

    #[test]
    fn recovery_round_trip_and_rejections() {
        let encoded = export(&fixture(), b"correct horse battery staple").unwrap();
        let decoded = import(&encoded, b"correct horse battery staple").unwrap();
        assert_eq!(decoded.identity_seed, [7; 32]);
        assert_eq!(decoded.vaults[0].catalog_version, 7);
        assert!(import(&encoded, b"wrong passphrase").is_err());

        let mut corrupt = encoded;
        let index = corrupt.len() - 2;
        corrupt[index] ^= 1;
        assert!(import(&corrupt, b"correct horse battery staple").is_err());
    }

    #[test]
    fn rejects_malicious_kdf_parameters_before_allocation() {
        let bytes = export(&fixture(), b"passphrase long enough").unwrap();
        let mut file: RecoveryFile = serde_json::from_slice(&bytes).unwrap();
        file.memory_kib = u32::MAX;
        let malicious = serde_json::to_vec(&file).unwrap();
        assert!(matches!(
            import(&malicious, b"passphrase long enough"),
            Err(RecoveryError::Parameters)
        ));
    }
}
