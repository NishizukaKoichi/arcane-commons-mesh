#![forbid(unsafe_code)]

use arcane_mesh_core::{cid, store::ObjectStore};
use arcane_mesh_protocol::MAX_OBJECT_BYTES;
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("storage node is offline")]
    Offline,
    #[error("object exceeds protocol limit")]
    Oversized,
    #[error("storage failure: {0}")]
    Storage(#[from] arcane_mesh_core::store::StoreError),
}

pub struct StorageNode {
    node_id: String,
    failure_domain: String,
    root: PathBuf,
    store: ObjectStore,
    active: AtomicBool,
}

impl StorageNode {
    pub fn new(
        node_id: impl Into<String>,
        failure_domain: impl Into<String>,
        root: impl AsRef<Path>,
        quota: u64,
    ) -> Result<Self, NodeError> {
        let store = ObjectStore::new(&root, quota)?;
        Ok(Self {
            node_id: node_id.into(),
            failure_domain: failure_domain.into(),
            root: root.as_ref().to_path_buf(),
            store,
            active: AtomicBool::new(true),
        })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn failure_domain(&self) -> &str {
        &self.failure_domain
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::SeqCst);
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    pub fn put(&self, object_cid: &str, bytes: &[u8]) -> Result<(), NodeError> {
        self.ensure_active()?;
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(NodeError::Oversized);
        }
        self.store.put(object_cid, bytes)?;
        Ok(())
    }

    pub fn has(&self, object_cid: &str) -> bool {
        self.is_active() && self.store.get(object_cid).is_ok()
    }

    pub fn get(&self, object_cid: &str) -> Result<Vec<u8>, NodeError> {
        self.ensure_active()?;
        Ok(self.store.get(object_cid)?)
    }

    pub fn audit(&self, object_cid: &str) -> Result<bool, NodeError> {
        self.ensure_active()?;
        Ok(self
            .store
            .get(object_cid)
            .is_ok_and(|bytes| cid(&bytes) == object_cid))
    }

    pub fn delete(&self, object_cid: &str) -> Result<bool, NodeError> {
        self.ensure_active()?;
        Ok(self.store.delete(object_cid)?)
    }

    pub fn list_cids(&self) -> Result<Vec<String>, NodeError> {
        self.ensure_active()?;
        Ok(self.store.list_cids()?)
    }

    fn ensure_active(&self) -> Result<(), NodeError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(NodeError::Offline)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_node_refuses_operations() {
        let temporary = tempfile::tempdir().unwrap();
        let node = StorageNode::new("node", "domain", temporary.path(), 1024).unwrap();
        let bytes = b"ciphertext";
        let object_cid = cid(bytes);
        node.put(&object_cid, bytes).unwrap();
        node.set_active(false);
        assert!(matches!(node.get(&object_cid), Err(NodeError::Offline)));
        assert!(!node.has(&object_cid));
    }
}
