#![forbid(unsafe_code)]

use arcane_mesh_core::identity::MembershipCredential;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_ID: &str = "arcane-commons-mesh/1";
pub const MAX_OBJECT_BYTES: usize = 4 * 1024 * 1024 + 128 * 1024;
pub const MAX_FRAME_BYTES: usize = MAX_OBJECT_BYTES + 16 * 1024;
pub const REQUEST_TTL_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Hello,
    HasObject,
    PutObject,
    GetObject,
    AuditObject,
    DeleteAfter,
    ReplicateObject,
    Ping,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub protocol_version: u16,
    pub request_id: String,
    pub community_id: String,
    pub node_id: String,
    pub operation: Operation,
    pub object_cid: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub credential: MembershipCredential,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version")]
    Version,
    #[error("invalid request lifetime")]
    Lifetime,
    #[error("missing or malformed request identifier")]
    RequestId,
    #[error("missing object CID")]
    ObjectCid,
    #[error("invalid credential")]
    Credential,
    #[error("operation is not authorized for this role")]
    Unauthorized,
    #[error("frame is too large")]
    Oversized,
}

impl Request {
    pub fn validate(&self, now: i64, frame_size: usize) -> Result<(), ProtocolError> {
        if self.protocol_version != 1 {
            return Err(ProtocolError::Version);
        }
        if frame_size > MAX_FRAME_BYTES {
            return Err(ProtocolError::Oversized);
        }
        if self.request_id.len() < 16 || self.request_id.len() > 128 {
            return Err(ProtocolError::RequestId);
        }
        if self.issued_at > now + REQUEST_TTL_SECONDS
            || self.expires_at < now
            || self.expires_at - self.issued_at > REQUEST_TTL_SECONDS
        {
            return Err(ProtocolError::Lifetime);
        }
        if !matches!(self.operation, Operation::Hello | Operation::Ping)
            && self.object_cid.as_deref().is_none_or(|cid| {
                cid.len() != 64 || !cid.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(ProtocolError::ObjectCid);
        }
        self.credential
            .verify(&self.community_id, now, REQUEST_TTL_SECONDS)
            .map_err(|_| ProtocolError::Credential)?;
        let roles = &self.credential.claims.roles;
        let allowed = match self.operation {
            Operation::Hello | Operation::Ping | Operation::HasObject | Operation::GetObject => {
                roles.iter().any(|role| role == "member" || role == "node")
            }
            Operation::PutObject | Operation::ReplicateObject => {
                roles.iter().any(|role| role == "node")
            }
            Operation::AuditObject => roles.iter().any(|role| role == "auditor"),
            Operation::DeleteAfter => roles.iter().any(|role| role == "admin"),
        };
        if !allowed {
            return Err(ProtocolError::Unauthorized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcane_mesh_core::identity::{Identity, MembershipClaims};

    fn request(operation: Operation, roles: &[&str]) -> Request {
        let root = Identity::from_seed([1; 32]);
        let node = Identity::from_seed([2; 32]);
        let credential = MembershipClaims {
            credential_version: 1,
            community_id: "community".into(),
            member_public_key: node.public_key(),
            member_id: node.member_id(),
            roles: roles.iter().map(|role| (*role).into()).collect(),
            issued_at: 100,
            expires_at: 200,
            serial: 1,
            issuer_public_key: root.public_key(),
        }
        .issue(&root);
        Request {
            protocol_version: 1,
            request_id: "request-00000001".into(),
            community_id: "community".into(),
            node_id: "node-a".into(),
            operation,
            object_cid: Some("a".repeat(64)),
            issued_at: 100,
            expires_at: 200,
            credential,
        }
    }

    #[test]
    fn enforces_operation_roles_and_limits() {
        assert!(request(Operation::PutObject, &["node"])
            .validate(150, 1024)
            .is_ok());
        assert!(matches!(
            request(Operation::PutObject, &["member"]).validate(150, 1024),
            Err(ProtocolError::Unauthorized)
        ));
        assert!(matches!(
            request(Operation::AuditObject, &["node"]).validate(150, 1024),
            Err(ProtocolError::Unauthorized)
        ));
        assert!(matches!(
            request(Operation::GetObject, &["member"]).validate(150, MAX_FRAME_BYTES + 1),
            Err(ProtocolError::Oversized)
        ));
    }
}
