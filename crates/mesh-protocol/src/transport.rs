use crate::{Request, MAX_FRAME_BYTES, PROTOCOL_ID};
use arcane_mesh_core::identity::NodeCertificate;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use iroh::{endpoint::presets, Endpoint, EndpointAddr};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
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
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireResponse {
    pub protocol_version: u16,
    pub request_id: String,
    pub ok: bool,
    pub error_code: Option<String>,
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub payload: Vec<u8>,
    pub payload_cid: String,
}

pub struct AcceptedRpc {
    pub frame: WireFrame,
    send: iroh::endpoint::SendStream,
    connection: iroh::endpoint::Connection,
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

    pub async fn call(
        &self,
        peer: EndpointAddr,
        frame: &WireFrame,
    ) -> Result<WireResponse, TransportError> {
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
        let (mut send, mut receive) = timeout(CONNECT_TIMEOUT, connection.open_bi())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        timeout(CONNECT_TIMEOUT, send.write_all(&encoded))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        send.finish()
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let response_bytes = timeout(CONNECT_TIMEOUT, receive.read_to_end(MAX_FRAME_BYTES))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let response: WireResponse = serde_json::from_slice(&response_bytes)?;
        if response.protocol_version != 1
            || response.request_id != frame.request.request_id
            || response.payload_cid != arcane_mesh_core::cid(&response.payload)
        {
            return Err(TransportError::Iroh(
                "response was not bound to the request or payload".into(),
            ));
        }
        connection.close(0_u8.into(), b"rpc complete");
        Ok(response)
    }

    pub async fn accept_rpc(
        &self,
        expected_community_root: &[u8; 32],
        now: i64,
    ) -> Result<AcceptedRpc, TransportError> {
        let incoming = timeout(CONNECT_TIMEOUT, self.endpoint.accept())
            .await
            .map_err(|_| TransportError::Timeout)?
            .ok_or(TransportError::Closed)?;
        let accepting = incoming
            .accept()
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let connection = timeout(CONNECT_TIMEOUT, accepting)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let remote_endpoint_id = connection.remote_id().to_string();
        let (send, mut receive) = timeout(CONNECT_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let encoded = timeout(CONNECT_TIMEOUT, receive.read_to_end(MAX_FRAME_BYTES))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let frame: WireFrame = serde_json::from_slice(&encoded)?;
        self.validate_frame(
            &frame,
            encoded.len(),
            &remote_endpoint_id,
            expected_community_root,
            now,
        )?;
        Ok(AcceptedRpc {
            frame,
            send,
            connection,
        })
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
        let mut stream = timeout(CONNECT_TIMEOUT, connection.open_uni())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        timeout(CONNECT_TIMEOUT, stream.write_all(&encoded))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        stream
            .finish()
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        timeout(CONNECT_TIMEOUT, stream.stopped())
            .await
            .map_err(|_| TransportError::Timeout)?
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
        let accepting = incoming
            .accept()
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let connection = timeout(CONNECT_TIMEOUT, accepting)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let remote_endpoint_id = connection.remote_id().to_string();
        let mut stream = timeout(CONNECT_TIMEOUT, connection.accept_uni())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let encoded = timeout(CONNECT_TIMEOUT, stream.read_to_end(MAX_FRAME_BYTES))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        let frame: WireFrame = serde_json::from_slice(&encoded)?;
        self.validate_frame(
            &frame,
            encoded.len(),
            &remote_endpoint_id,
            expected_community_root,
            now,
        )?;
        connection.close(0_u8.into(), b"frame received");
        Ok(frame)
    }

    fn validate_frame(
        &self,
        frame: &WireFrame,
        encoded_len: usize,
        remote_endpoint_id: &str,
        expected_community_root: &[u8; 32],
        now: i64,
    ) -> Result<(), TransportError> {
        frame
            .node_certificate
            .verify(
                &frame.node_owner_public_key,
                &frame.request.community_id,
                remote_endpoint_id,
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
            .validate(expected_community_root, now, encoded_len)
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
        Ok(())
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

impl AcceptedRpc {
    pub async fn respond(mut self, response: &WireResponse) -> Result<(), TransportError> {
        if response.request_id != self.frame.request.request_id
            || response.payload_cid != arcane_mesh_core::cid(&response.payload)
        {
            return Err(TransportError::Iroh(
                "response was not bound to the accepted request".into(),
            ));
        }
        let encoded = serde_json::to_vec(response)?;
        if encoded.len() > MAX_FRAME_BYTES {
            return Err(TransportError::Oversized);
        }
        timeout(CONNECT_TIMEOUT, self.send.write_all(&encoded))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        self.send
            .finish()
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        timeout(CONNECT_TIMEOUT, self.send.stopped())
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        self.connection.close(0_u8.into(), b"rpc response complete");
        Ok(())
    }
}

fn serialize_bytes<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
}

fn deserialize_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    URL_SAFE_NO_PAD.decode(encoded).map_err(D::Error::custom)
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
    async fn round_trips_authenticated_request_response_over_loopback_quic() {
        let directory = tempfile::tempdir().unwrap();
        let server = IrohTransport::bind_local(directory.path().join("rpc-server.sqlite3"))
            .await
            .unwrap();
        let client = IrohTransport::bind_local(directory.path().join("rpc-client.sqlite3"))
            .await
            .unwrap();
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
        let payload = Vec::new();
        let frame = WireFrame {
            request_signature: owner
                .sign(&request.signing_bytes(&arcane_mesh_core::cid(&payload)))
                .to_vec(),
            request,
            node_certificate: certificate,
            node_owner_public_key: owner.public_key(),
            payload,
        };
        let server_addr = server.addr();
        let community_root = Identity::from_seed([1; 32]).public_key();
        let expected_request_id = frame.request.request_id.clone();
        let (server_result, client_result) = tokio::join!(
            async {
                let accepted = server.accept_rpc(&community_root, 150).await.unwrap();
                let response_payload = b"encrypted-object-response".to_vec();
                accepted
                    .respond(&WireResponse {
                        protocol_version: 1,
                        request_id: expected_request_id,
                        ok: true,
                        error_code: None,
                        payload_cid: arcane_mesh_core::cid(&response_payload),
                        payload: response_payload,
                    })
                    .await
            },
            client.call(server_addr, &frame)
        );
        server_result.unwrap();
        let response = client_result.unwrap();
        assert!(response.ok);
        assert_eq!(response.payload, b"encrypted-object-response");

        server.close().await;
        client.close().await;
    }

    #[test]
    fn maximum_object_payload_fits_the_bounded_json_wire_frame() {
        let owner = Identity::from_seed([2; 32]);
        let frame = WireFrame {
            request: request(),
            request_signature: vec![0; 64],
            node_certificate: NodeCertificateClaims {
                certificate_version: 1,
                node_id: "node-a".into(),
                community_id: "community".into(),
                owner_member_id: owner.member_id(),
                endpoint_public_key: "endpoint".into(),
                allowed_roles: vec!["node".into()],
                max_storage_bytes: crate::MAX_OBJECT_BYTES as u64,
                issued_at: 100,
                expires_at: 200,
            }
            .issue(&owner),
            node_owner_public_key: owner.public_key(),
            payload: vec![255; crate::MAX_OBJECT_BYTES],
        };
        assert!(serde_json::to_vec(&frame).unwrap().len() <= MAX_FRAME_BYTES);
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
