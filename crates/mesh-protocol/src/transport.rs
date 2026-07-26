use crate::{Request, MAX_FRAME_BYTES, PROTOCOL_ID};
use arcane_mesh_core::identity::NodeCertificate;
use iroh::{endpoint::presets, Endpoint, EndpointAddr};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireFrame {
    pub request: Request,
    pub request_signature: Vec<u8>,
    pub node_certificate: NodeCertificate,
    pub node_owner_public_key: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport operation timed out")]
    Timeout,
    #[error("iroh transport failed: {0}")]
    Iroh(String),
    #[error("wire frame encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("wire frame exceeds protocol limit")]
    Oversized,
    #[error("endpoint closed before accepting a connection")]
    Closed,
}

/// Native QUIC transport endpoint for Arcane Commons Mesh.
///
/// `bind_local` is deliberately relay- and discovery-free for deterministic
/// tests. Every constructor requires a durable replay database.
pub struct IrohTransport {
    endpoint: Endpoint,
    replay_database: PathBuf,
}

impl IrohTransport {
    pub fn from_endpoint(
        endpoint: Endpoint,
        replay_database: impl AsRef<Path>,
    ) -> Result<Self, TransportError> {
        let transport = Self {
            endpoint,
            replay_database: replay_database.as_ref().to_path_buf(),
        };
        transport.initialize_replay_database()?;
        Ok(transport)
    }

    pub async fn bind_local(replay_database: impl AsRef<Path>) -> Result<Self, TransportError> {
        let endpoint = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .map_err(|error| TransportError::Iroh(error.to_string()))?
            .alpns(vec![PROTOCOL_ID.as_bytes().to_vec()])
            .bind()
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let transport = Self {
            endpoint,
            replay_database: replay_database.as_ref().to_path_buf(),
        };
        transport.initialize_replay_database()?;
        Ok(transport)
    }

    /// Binds the normal iroh endpoint: direct paths are preferred and encrypted
    /// relay transport remains available when direct dialing cannot succeed.
    pub async fn bind_network(replay_database: impl AsRef<Path>) -> Result<Self, TransportError> {
        let endpoint = Endpoint::bind(presets::N0)
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        endpoint.set_alpns(vec![PROTOCOL_ID.as_bytes().to_vec()]);
        let transport = Self {
            endpoint,
            replay_database: replay_database.as_ref().to_path_buf(),
        };
        transport.initialize_replay_database()?;
        Ok(transport)
    }

    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    pub async fn send(&self, peer: EndpointAddr, frame: &WireFrame) -> Result<(), TransportError> {
        let encoded = serde_json::to_vec(frame)?;
        if encoded.len() > MAX_FRAME_BYTES {
            return Err(TransportError::Oversized);
        }
        let connection = timeout(
            CONNECT_TIMEOUT,
            self.endpoint.connect(peer, PROTOCOL_ID.as_bytes()),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
        .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let mut stream = connection
            .open_uni()
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        stream
            .write_all(&encoded)
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        stream
            .finish()
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        stream
            .stopped()
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        Ok(())
    }

    pub async fn accept(
        &self,
        expected_community_root: &[u8; 32],
        now: i64,
    ) -> Result<WireFrame, TransportError> {
        let incoming = timeout(CONNECT_TIMEOUT, self.endpoint.accept())
            .await
            .map_err(|_| TransportError::Timeout)?
            .ok_or(TransportError::Closed)?;
        let connection = incoming
            .accept()
            .map_err(|error| TransportError::Iroh(error.to_string()))?
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let remote_endpoint_id = connection.remote_id().to_string();
        let mut stream = connection
            .accept_uni()
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let encoded = stream
            .read_to_end(MAX_FRAME_BYTES)
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let frame: WireFrame = serde_json::from_slice(&encoded)?;
        frame
            .node_certificate
            .verify(
                &frame.node_owner_public_key,
                &frame.request.community_id,
                &remote_endpoint_id,
                now,
                crate::REQUEST_TTL_SECONDS,
            )
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        if frame.request.node_id != frame.node_certificate.claims.node_id {
            return Err(TransportError::Iroh(
                "request node does not match endpoint certificate".into(),
            ));
        }
        if frame.node_certificate.claims.owner_member_id
            != frame.request.credential.claims.member_id
            || frame.node_owner_public_key != frame.request.credential.claims.member_public_key
        {
            return Err(TransportError::Iroh(
                "node certificate owner does not match membership credential".into(),
            ));
        }
        frame
            .request
            .validate(expected_community_root, now, encoded.len())
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let payload_cid = arcane_mesh_core::cid(&frame.payload);
        frame
            .request
            .credential
            .verify_member_signature(
                &frame.request.signing_bytes(&payload_cid),
                &frame.request_signature,
            )
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let replay_key = format!(
            "{}|{}|{}",
            frame.request.community_id,
            frame.request.credential.claims.member_id,
            frame.request.request_id
        );
        if !self.claim_replay(&replay_key, frame.request.expires_at, now)? {
            return Err(TransportError::Iroh("replayed request identifier".into()));
        }
        connection.close(0_u8.into(), b"frame received");
        Ok(frame)
    }

    pub async fn close(self) {
        self.endpoint.close().await;
    }

    fn initialize_replay_database(&self) -> Result<(), TransportError> {
        let path = &self.replay_database;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| TransportError::Iroh(error.to_string()))?;
        }
        let connection = rusqlite::Connection::open(path)
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS replay_requests (
                   replay_key TEXT PRIMARY KEY NOT NULL,
                   expires_at INTEGER NOT NULL
                 );",
            )
            .map_err(|error| TransportError::Iroh(error.to_string()))
    }

    fn claim_replay(
        &self,
        replay_key: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, TransportError> {
        let mut connection = rusqlite::Connection::open(&self.replay_database)
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        transaction
            .execute("DELETE FROM replay_requests WHERE expires_at < ?1", [now])
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO replay_requests (replay_key, expires_at) VALUES (?1, ?2)",
                rusqlite::params![replay_key, expires_at],
            )
            .map_err(|error| TransportError::Iroh(error.to_string()))?
            == 1;
        transaction
            .commit()
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        Ok(inserted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Operation;
    use arcane_mesh_core::identity::{Identity, MembershipClaims, NodeCertificateClaims};

    fn request() -> Request {
        let root = Identity::from_seed([1; 32]);
        let member = Identity::from_seed([2; 32]);
        let credential = MembershipClaims {
            credential_version: 1,
            community_id: "community".into(),
            member_public_key: member.public_key(),
            member_id: member.member_id(),
            roles: vec!["member".into()],
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
            operation: Operation::GetObject,
            object_cid: Some("ab".repeat(32)),
            issued_at: 100,
            expires_at: 200,
            credential,
        }
    }

    #[tokio::test]
    async fn exchanges_an_authenticated_frame_over_offline_loopback_quic() {
        let directory = tempfile::tempdir().unwrap();
        let server = IrohTransport::bind_local(directory.path().join("server.sqlite3"))
            .await
            .unwrap();
        let client = IrohTransport::bind_local(directory.path().join("client.sqlite3"))
            .await
            .unwrap();
        let server_addr = server.addr();
        assert!(server_addr.relay_urls().next().is_none());
        let owner = Identity::from_seed([2; 32]);
        let certificate = NodeCertificateClaims {
            certificate_version: 1,
            node_id: "node-a".into(),
            community_id: "community".into(),
            owner_member_id: owner.member_id(),
            endpoint_public_key: client.endpoint.id().to_string(),
            allowed_roles: vec!["node".into()],
            max_storage_bytes: 1024,
            issued_at: 100,
            expires_at: 200,
        }
        .issue(&owner);

        let request = request();
        let payload = b"encrypted-object".to_vec();
        let request_signature = Identity::from_seed([2; 32])
            .sign(&request.signing_bytes(&arcane_mesh_core::cid(&payload)))
            .to_vec();
        let expected = WireFrame {
            request,
            request_signature,
            node_certificate: certificate,
            node_owner_public_key: owner.public_key(),
            payload,
        };
        let sent = expected.clone();
        let community_root = Identity::from_seed([1; 32]).public_key();
        let (received, send_result) = tokio::join!(
            server.accept(&community_root, 150),
            client.send(server_addr, &sent)
        );
        send_result.unwrap();
        let received = received.unwrap();
        assert_eq!(received.payload, expected.payload);

        server.close().await;
        client.close().await;
    }

    #[tokio::test]
    async fn durable_replay_cache_survives_transport_restart() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("replay.sqlite3");
        let first = IrohTransport::bind_local(&database).await.unwrap();
        assert!(first
            .claim_replay("community|member|request", 200, 150)
            .unwrap());
        first.close().await;
        let second = IrohTransport::bind_local(&database).await.unwrap();
        assert!(!second
            .claim_replay("community|member|request", 200, 150)
            .unwrap());
        assert!(second
            .claim_replay("community|member|request", 300, 201)
            .unwrap());
        second.close().await;
    }
}
