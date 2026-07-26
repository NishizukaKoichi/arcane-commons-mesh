use crate::cid;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("invalid CID")]
    InvalidCid,
    #[error("CID mismatch")]
    CidMismatch,
    #[error("quota exceeded")]
    Quota,
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct ObjectStore {
    root: PathBuf,
    quota: u64,
}

impl ObjectStore {
    pub fn new(root: impl AsRef<Path>, quota: u64) -> Result<Self, StoreError> {
        fs::create_dir_all(root.as_ref())?;
        Ok(Self {
            root: root.as_ref().canonicalize()?,
            quota,
        })
    }

    fn path(&self, object_cid: &str) -> Result<PathBuf, StoreError> {
        if object_cid.len() != 64 || !object_cid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(StoreError::InvalidCid);
        }
        Ok(self
            .root
            .join("objects")
            .join(&object_cid[..2])
            .join(format!("{object_cid}.blob")))
    }

    pub fn put(&self, expected_cid: &str, bytes: &[u8]) -> Result<PathBuf, StoreError> {
        if cid(bytes) != expected_cid {
            return Err(StoreError::CidMismatch);
        }
        if bytes.len() as u64 > self.quota {
            return Err(StoreError::Quota);
        }
        let destination = self.path(expected_cid)?;
        let parent = destination.parent().ok_or(StoreError::InvalidCid)?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".{expected_cid}.partial"));
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        fs::rename(&temporary, &destination)?;
        Ok(destination)
    }

    pub fn get(&self, object_cid: &str) -> Result<Vec<u8>, StoreError> {
        let bytes = fs::read(self.path(object_cid)?)?;
        if cid(&bytes) != object_cid {
            return Err(StoreError::CidMismatch);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_cid_quota_and_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let store = ObjectStore::new(temp.path(), 64).unwrap();
        let bytes = b"opaque ciphertext";
        let object_cid = cid(bytes);
        let path = store.put(&object_cid, bytes).unwrap();
        assert_eq!(store.get(&object_cid).unwrap(), bytes);
        fs::write(path, b"tampered").unwrap();
        assert!(matches!(
            store.get(&object_cid),
            Err(StoreError::CidMismatch)
        ));
        assert!(matches!(
            store.put(&cid(&[0; 65]), &[0; 65]),
            Err(StoreError::Quota)
        ));
    }

    #[test]
    fn rejects_path_traversal_as_cid() {
        let temp = tempfile::tempdir().unwrap();
        let store = ObjectStore::new(temp.path(), 64).unwrap();
        assert!(matches!(
            store.get("../../secret"),
            Err(StoreError::InvalidCid)
        ));
    }
}
