use crate::cid;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
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
    #[error("symbolic links are not allowed in node storage")]
    Symlink,
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct ObjectStore {
    root: PathBuf,
    quota: u64,
}

impl ObjectStore {
    pub fn new(root: impl AsRef<Path>, quota: u64) -> Result<Self, StoreError> {
        if fs::symlink_metadata(root.as_ref())
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(StoreError::Symlink);
        }
        fs::create_dir_all(root.as_ref())?;
        let store = Self {
            root: root.as_ref().canonicalize()?,
            quota,
        };
        store.initialize()?;
        Ok(store)
    }

    fn database_path(&self) -> PathBuf {
        self.root.join("metadata.sqlite3")
    }

    fn connection(&self) -> Result<Connection, StoreError> {
        Ok(Connection::open(self.database_path())?)
    }

    fn initialize(&self) -> Result<(), StoreError> {
        let connection = self.connection()?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS objects (
               cid TEXT PRIMARY KEY NOT NULL,
               size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
               stored_at INTEGER NOT NULL DEFAULT (unixepoch())
             );",
        )?;
        drop(connection);
        self.reconcile()
    }

    fn validate_cid(object_cid: &str) -> Result<(), StoreError> {
        if object_cid.len() != 64
            || !object_cid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(StoreError::InvalidCid);
        }
        Ok(())
    }

    fn path(&self, object_cid: &str) -> Result<PathBuf, StoreError> {
        Self::validate_cid(object_cid)?;
        Ok(self
            .root
            .join("objects")
            .join(&object_cid[..2])
            .join(format!("{object_cid}.blob")))
    }

    fn reject_symlink_components(&self, path: &Path) -> Result<(), StoreError> {
        let mut current = self.root.clone();
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| StoreError::InvalidCid)?;
        for component in relative.components() {
            current.push(component);
            if fs::symlink_metadata(&current)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err(StoreError::Symlink);
            }
        }
        Ok(())
    }

    fn reconcile(&self) -> Result<(), StoreError> {
        let objects_root = self.root.join("objects");
        if fs::symlink_metadata(&objects_root)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(StoreError::Symlink);
        }
        fs::create_dir_all(&objects_root)?;
        let connection = self.connection()?;
        connection.execute("DELETE FROM objects", [])?;
        for prefix in fs::read_dir(&objects_root)? {
            let prefix = prefix?;
            if prefix.file_type()?.is_symlink() {
                return Err(StoreError::Symlink);
            }
            if !prefix.file_type()?.is_dir() {
                continue;
            }
            for entry in fs::read_dir(prefix.path())? {
                let entry = entry?;
                if entry.file_type()?.is_symlink() {
                    return Err(StoreError::Symlink);
                }
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) == Some("partial") {
                    fs::remove_file(path)?;
                    continue;
                }
                let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                let Some(object_cid) = file_name.strip_suffix(".blob") else {
                    continue;
                };
                if Self::validate_cid(object_cid).is_err() {
                    continue;
                }
                let bytes = fs::read(&path)?;
                if cid(&bytes) != object_cid {
                    continue;
                }
                connection.execute(
                    "INSERT INTO objects (cid, size_bytes) VALUES (?1, ?2)",
                    params![object_cid, i64::try_from(bytes.len()).unwrap_or(i64::MAX)],
                )?;
            }
        }
        Ok(())
    }

    pub fn used_bytes(&self) -> Result<u64, StoreError> {
        let total: i64 = self.connection()?.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM objects",
            [],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(total).unwrap_or(u64::MAX))
    }

    pub fn list_cids(&self) -> Result<Vec<String>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT cid FROM objects ORDER BY cid")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn put(&self, expected_cid: &str, bytes: &[u8]) -> Result<PathBuf, StoreError> {
        if cid(bytes) != expected_cid {
            return Err(StoreError::CidMismatch);
        }
        let destination = self.path(expected_cid)?;
        self.reject_symlink_components(&destination)?;
        if destination.exists() {
            if self.get(expected_cid).is_ok_and(|stored| stored == bytes) {
                return Ok(destination);
            }
            fs::remove_file(&destination)?;
            self.connection()?
                .execute("DELETE FROM objects WHERE cid = ?1", [expected_cid])?;
        }
        let parent = destination.parent().ok_or(StoreError::InvalidCid)?;
        fs::create_dir_all(parent)?;
        self.reject_symlink_components(parent)?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let used: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM objects",
            [],
            |row| row.get(0),
        )?;
        let new_total = u64::try_from(used)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if new_total > self.quota {
            return Err(StoreError::Quota);
        }

        let temporary = parent.join(format!(".{expected_cid}.partial"));
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        fs::rename(&temporary, &destination)?;
        if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
            directory.sync_all()?;
        }
        if let Err(error) = transaction.execute(
            "INSERT INTO objects (cid, size_bytes) VALUES (?1, ?2)",
            params![expected_cid, i64::try_from(bytes.len()).unwrap_or(i64::MAX)],
        ) {
            drop(transaction);
            let _ = fs::remove_file(&destination);
            return Err(StoreError::Database(error));
        }
        if let Err(error) = transaction.commit() {
            let _ = fs::remove_file(&destination);
            self.reconcile()?;
            return Err(StoreError::Database(error));
        }
        Ok(destination)
    }

    pub fn delete(&self, object_cid: &str) -> Result<bool, StoreError> {
        let destination = self.path(object_cid)?;
        self.reject_symlink_components(&destination)?;
        if !destination.exists() {
            self.connection()?
                .execute("DELETE FROM objects WHERE cid = ?1", [object_cid])?;
            return Ok(false);
        }
        let tombstone = destination.with_extension("gc");
        fs::rename(&destination, &tombstone)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Err(error) = transaction.execute("DELETE FROM objects WHERE cid = ?1", [object_cid])
        {
            drop(transaction);
            fs::rename(&tombstone, &destination)?;
            return Err(StoreError::Database(error));
        }
        if let Err(error) = transaction.commit() {
            fs::rename(&tombstone, &destination)?;
            return Err(StoreError::Database(error));
        }
        fs::remove_file(tombstone)?;
        if let Some(parent) = destination.parent() {
            if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
                directory.sync_all()?;
            }
        }
        Ok(true)
    }

    pub fn get(&self, object_cid: &str) -> Result<Vec<u8>, StoreError> {
        let path = self.path(object_cid)?;
        self.reject_symlink_components(&path)?;
        let known = self
            .connection()?
            .query_row(
                "SELECT size_bytes FROM objects WHERE cid = ?1",
                [object_cid],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let bytes = fs::read(path)?;
        if cid(&bytes) != object_cid
            || known != Some(i64::try_from(bytes.len()).unwrap_or(i64::MAX))
        {
            return Err(StoreError::CidMismatch);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_cid_cumulative_quota_and_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let store = ObjectStore::new(temp.path(), 24).unwrap();
        let first = b"opaque ciphertext";
        let first_cid = cid(first);
        let path = store.put(&first_cid, first).unwrap();
        assert_eq!(store.used_bytes().unwrap(), first.len() as u64);
        assert_eq!(store.get(&first_cid).unwrap(), first);
        let second = b"another object";
        assert!(matches!(
            store.put(&cid(second), second),
            Err(StoreError::Quota)
        ));
        fs::write(path, b"tampered").unwrap();
        assert!(matches!(
            store.get(&first_cid),
            Err(StoreError::CidMismatch)
        ));
        store.put(&first_cid, first).unwrap();
        assert_eq!(store.get(&first_cid).unwrap(), first);
        assert_eq!(store.used_bytes().unwrap(), first.len() as u64);
    }

    #[test]
    fn rejects_path_traversal_and_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let store = ObjectStore::new(temp.path(), 64).unwrap();
        assert!(matches!(
            store.get("../../secret"),
            Err(StoreError::InvalidCid)
        ));
        let bytes = b"opaque ciphertext";
        let object_cid = cid(bytes);
        let prefix = temp.path().join("objects").join(&object_cid[..2]);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(temp.path(), &prefix).unwrap();
            assert!(matches!(
                store.put(&object_cid, bytes),
                Err(StoreError::Symlink)
            ));
        }
    }

    #[test]
    fn reconciles_atomic_write_artifacts_and_metadata_on_restart() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"opaque ciphertext";
        let object_cid = cid(bytes);
        let stored_path = {
            let store = ObjectStore::new(temp.path(), 64).unwrap();
            store.put(&object_cid, bytes).unwrap()
        };
        let partial = stored_path
            .parent()
            .unwrap()
            .join(format!(".{object_cid}.partial"));
        fs::write(&partial, b"incomplete").unwrap();
        fs::remove_file(temp.path().join("metadata.sqlite3")).unwrap();
        let recovered = ObjectStore::new(temp.path(), 64).unwrap();
        assert!(!partial.exists());
        assert_eq!(recovered.get(&object_cid).unwrap(), bytes);
        assert_eq!(recovered.used_bytes().unwrap(), bytes.len() as u64);
    }

    #[test]
    fn delete_removes_blob_and_quota_accounting() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"opaque ciphertext";
        let object_cid = cid(bytes);
        let store = ObjectStore::new(temp.path(), 64).unwrap();
        store.put(&object_cid, bytes).unwrap();
        assert!(store.delete(&object_cid).unwrap());
        assert_eq!(store.used_bytes().unwrap(), 0);
        assert!(store.get(&object_cid).is_err());
        assert!(!store.delete(&object_cid).unwrap());
    }
}
