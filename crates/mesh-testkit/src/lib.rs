#![forbid(unsafe_code)]

use arcane_mesh_core::cid;
use arcane_mesh_node::{NodeError, StorageNode};
use std::sync::Arc;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pub object_cid: String,
    pub node_id: String,
    pub failure_domain: String,
    pub healthy: bool,
}

#[derive(Debug, Error)]
pub enum MeshError {
    #[error("not enough independent storage nodes")]
    InsufficientNodes,
    #[error("no healthy replica")]
    NoHealthyReplica,
    #[error("node failure: {0}")]
    Node(#[from] NodeError),
}

pub struct InMemoryMesh {
    nodes: Vec<Arc<StorageNode>>,
    placements: Vec<Placement>,
}

impl InMemoryMesh {
    pub fn new(nodes: Vec<Arc<StorageNode>>) -> Self {
        Self {
            nodes,
            placements: Vec::new(),
        }
    }

    pub fn nodes(&self) -> &[Arc<StorageNode>] {
        &self.nodes
    }

    pub fn placements(&self) -> &[Placement] {
        &self.placements
    }

    pub fn replicate(&mut self, bytes: &[u8], target: usize) -> Result<String, MeshError> {
        let object_cid = cid(bytes);
        let mut domains = Vec::<String>::new();
        for node in self.nodes.iter().filter(|node| node.is_active()) {
            if domains.iter().any(|domain| domain == node.failure_domain()) {
                continue;
            }
            node.put(&object_cid, bytes)?;
            domains.push(node.failure_domain().into());
            self.placements.push(Placement {
                object_cid: object_cid.clone(),
                node_id: node.node_id().into(),
                failure_domain: node.failure_domain().into(),
                healthy: true,
            });
            if domains.len() == target {
                return Ok(object_cid);
            }
        }
        Err(MeshError::InsufficientNodes)
    }

    pub fn restore(&mut self, object_cid: &str) -> Result<Vec<u8>, MeshError> {
        for placement in self
            .placements
            .iter_mut()
            .filter(|placement| placement.object_cid == object_cid && placement.healthy)
        {
            let Some(node) = self
                .nodes
                .iter()
                .find(|node| node.node_id() == placement.node_id)
            else {
                placement.healthy = false;
                continue;
            };
            match node.get(object_cid) {
                Ok(bytes) if cid(&bytes) == object_cid => return Ok(bytes),
                _ => placement.healthy = false,
            }
        }
        Err(MeshError::NoHealthyReplica)
    }

    pub fn audit_all(&mut self, object_cid: &str) -> usize {
        let mut successes = 0;
        for placement in self
            .placements
            .iter_mut()
            .filter(|placement| placement.object_cid == object_cid)
        {
            placement.healthy = self
                .nodes
                .iter()
                .find(|node| node.node_id() == placement.node_id)
                .is_some_and(|node| node.audit(object_cid).unwrap_or(false));
            successes += usize::from(placement.healthy);
        }
        successes
    }

    pub fn repair(&mut self, object_cid: &str, target: usize) -> Result<usize, MeshError> {
        let source = self.restore(object_cid)?;
        let mut healthy_nodes: Vec<String> = self
            .placements
            .iter()
            .filter(|placement| placement.object_cid == object_cid && placement.healthy)
            .map(|placement| placement.node_id.clone())
            .collect();
        for node in self.nodes.iter().filter(|node| node.is_active()) {
            if healthy_nodes.len() >= target {
                break;
            }
            if healthy_nodes.iter().any(|id| id == node.node_id()) {
                continue;
            }
            node.put(object_cid, &source)?;
            healthy_nodes.push(node.node_id().into());
            self.placements.push(Placement {
                object_cid: object_cid.into(),
                node_id: node.node_id().into(),
                failure_domain: node.failure_domain().into(),
                healthy: true,
            });
        }
        if healthy_nodes.len() < target {
            return Err(MeshError::InsufficientNodes);
        }
        Ok(healthy_nodes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn node(parent: &std::path::Path, name: &str) -> Arc<StorageNode> {
        Arc::new(
            StorageNode::new(
                name,
                format!("domain-{name}"),
                parent.join(name),
                1024 * 1024,
            )
            .unwrap(),
        )
    }

    #[test]
    fn replication_outage_corruption_and_repair() {
        let temporary = tempfile::tempdir().unwrap();
        let nodes = vec![
            node(temporary.path(), "a"),
            node(temporary.path(), "b"),
            node(temporary.path(), "c"),
            node(temporary.path(), "d"),
        ];
        let mut mesh = InMemoryMesh::new(nodes.clone());
        let blob = b"opaque encrypted object";
        let object_cid = mesh.replicate(blob, 3).unwrap();
        assert_eq!(mesh.audit_all(&object_cid), 3);

        nodes[1].set_active(false);
        assert_eq!(mesh.restore(&object_cid).unwrap(), blob);

        let corrupt_path = nodes[2]
            .root()
            .join("objects")
            .join(&object_cid[..2])
            .join(format!("{object_cid}.blob"));
        fs::write(corrupt_path, b"corrupt").unwrap();
        assert_eq!(mesh.audit_all(&object_cid), 1);
        assert_eq!(mesh.restore(&object_cid).unwrap(), blob);

        nodes[1].set_active(true);
        assert_eq!(mesh.repair(&object_cid, 3).unwrap(), 3);
        assert!(mesh.audit_all(&object_cid) >= 3);
    }

    #[test]
    fn requires_independent_failure_domains() {
        let temporary = tempfile::tempdir().unwrap();
        let nodes = vec![
            Arc::new(StorageNode::new("a", "same", temporary.path().join("a"), 1024).unwrap()),
            Arc::new(StorageNode::new("b", "same", temporary.path().join("b"), 1024).unwrap()),
        ];
        assert!(matches!(
            InMemoryMesh::new(nodes).replicate(b"blob", 2),
            Err(MeshError::InsufficientNodes)
        ));
    }
}
