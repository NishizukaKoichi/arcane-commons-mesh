use crate::{
    cid,
    crypto::{decrypt, encrypt, CryptoError, Envelope, SecretKey},
    DEFAULT_CHUNK_SIZE,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("chunk integrity failure")]
    Integrity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedChunk {
    pub index: u64,
    pub plaintext_length: u32,
    pub cid: String,
    pub envelope: Envelope,
}

fn chunk_aad(vault_id: &str, file_version_id: &str, index: u64, length: u32) -> Vec<u8> {
    format!("acm.chunk.v1|{vault_id}|{file_version_id}|{index}|{length}").into_bytes()
}

pub fn encrypt_stream(
    reader: &mut impl Read,
    key: &SecretKey,
    vault_id: &str,
    file_version_id: &str,
) -> Result<Vec<EncryptedChunk>, VaultError> {
    let mut chunks = Vec::new();
    let mut buffer = Zeroizing::new(vec![0_u8; DEFAULT_CHUNK_SIZE]);
    loop {
        let mut length = 0;
        while length < buffer.len() {
            let read = reader.read(&mut buffer[length..])?;
            if read == 0 {
                break;
            }
            length += read;
        }
        if length == 0 {
            break;
        }
        let index = chunks.len() as u64;
        let plaintext_length = u32::try_from(length).map_err(|_| VaultError::Integrity)?;
        let envelope = encrypt(
            key,
            &buffer[..length],
            &chunk_aad(vault_id, file_version_id, index, plaintext_length),
        )?;
        let encoded = serde_json::to_vec(&envelope).map_err(io::Error::other)?;
        chunks.push(EncryptedChunk {
            index,
            plaintext_length,
            cid: cid(&encoded),
            envelope,
        });
        if length < buffer.len() {
            break;
        }
    }
    Ok(chunks)
}

pub fn decrypt_stream(
    chunks: &[EncryptedChunk],
    writer: &mut impl Write,
    key: &SecretKey,
    vault_id: &str,
    file_version_id: &str,
) -> Result<(), VaultError> {
    for (expected_index, chunk) in chunks.iter().enumerate() {
        if chunk.index != expected_index as u64 {
            return Err(VaultError::Integrity);
        }
        let encoded = serde_json::to_vec(&chunk.envelope).map_err(io::Error::other)?;
        if cid(&encoded) != chunk.cid {
            return Err(VaultError::Integrity);
        }
        let plaintext = Zeroizing::new(decrypt(
            key,
            &chunk.envelope,
            &chunk_aad(
                vault_id,
                file_version_id,
                chunk.index,
                chunk.plaintext_length,
            ),
        )?);
        if plaintext.len() != chunk.plaintext_length as usize {
            return Err(VaultError::Integrity);
        }
        writer.write_all(&plaintext)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn streams_across_boundaries_and_rejects_reordering() {
        for size in [
            0,
            1,
            64 * 1024,
            DEFAULT_CHUNK_SIZE - 1,
            DEFAULT_CHUNK_SIZE,
            DEFAULT_CHUNK_SIZE + 1,
        ] {
            let input = vec![42_u8; size];
            let key = SecretKey::random();
            let mut reader = Cursor::new(&input);
            let chunks = encrypt_stream(&mut reader, &key, "vault", "file-v1").unwrap();
            let mut output = Vec::new();
            decrypt_stream(&chunks, &mut output, &key, "vault", "file-v1").unwrap();
            assert_eq!(output, input);
        }

        let key = SecretKey::random();
        let mut reader = Cursor::new(vec![1_u8; DEFAULT_CHUNK_SIZE + 1]);
        let mut chunks = encrypt_stream(&mut reader, &key, "vault", "file-v1").unwrap();
        chunks.swap(0, 1);
        assert!(matches!(
            decrypt_stream(&chunks, &mut Vec::new(), &key, "vault", "file-v1"),
            Err(VaultError::Integrity)
        ));
    }
}
