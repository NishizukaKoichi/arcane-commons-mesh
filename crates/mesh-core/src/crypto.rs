use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("authentication failed")]
    Authenticate,
    #[error("unsupported envelope version")]
    Version,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    pub fn random() -> Self {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn derive(&self, context: &'static str) -> Self {
        Self(blake3::derive_key(context, &self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u16,
    pub algorithm: String,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Envelope, CryptoError> {
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(Envelope {
        version: 1,
        algorithm: "XChaCha20-Poly1305".into(),
        nonce,
        ciphertext,
    })
}

pub fn decrypt(key: &SecretKey, envelope: &Envelope, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if envelope.version != 1 || envelope.algorithm != "XChaCha20-Poly1305" {
        return Err(CryptoError::Version);
    }
    XChaCha20Poly1305::new((&key.0).into())
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Authenticate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_nonce_uniqueness() {
        let key = SecretKey::random();
        let first = encrypt(&key, b"private payload", b"acm.chunk.v1").unwrap();
        let second = encrypt(&key, b"private payload", b"acm.chunk.v1").unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_eq!(
            decrypt(&key, &first, b"acm.chunk.v1").unwrap(),
            b"private payload"
        );
    }

    #[test]
    fn rejects_wrong_key_ciphertext_and_aad() {
        let key = SecretKey::random();
        let envelope = encrypt(&key, b"payload", b"correct").unwrap();
        assert!(decrypt(&SecretKey::random(), &envelope, b"correct").is_err());
        assert!(decrypt(&key, &envelope, b"wrong").is_err());

        let mut modified = envelope;
        modified.ciphertext[0] ^= 1;
        assert!(decrypt(&key, &modified, b"correct").is_err());
    }
}
