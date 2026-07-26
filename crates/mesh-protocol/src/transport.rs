use crate::{Request, MAX_FRAME_BYTES, PROTOCOL_ID};
use arcane_mesh_core::identity::NodeCertificate;
use iroh::{endpoint::presets, Endpoint, EndpointAddr};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Mutex;
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
/// tests. Production callers may construct an endpoint with `presets::N0` to
/// enable direct dialing with encrypted relay fallback.
pub struct IrohTransport {
    endpoint: Endpoint,
    seen_request_ids: Mutex<BTreeSet<String>>,
}

impl IrohTransport {
    pub fn from_endpoint(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            seen_request_ids: Mutex::new(BTreeSet::new()),
        }
    }

    pub async fn bind_local() -> Result<Self, TransportError> {
        let endpoint = Endpoint::builder(presets::N0DisableRelay)
            .clear_address_lookup()
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .map_err(|error| TransportError::Iroh(error.to_string()))?
            .alpns(vec![PROTOCOL_ID.as_bytes().to_vec()])
            .bind()
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        Ok(Self {
            endpoint,
            seen_request_ids: Mutex::new(BTreeSet::new()),
        })
    }

    /// Binds the normal iroh endpoint: direct paths are preferred and encrypted
    /// relay transport remains available when direct dialing cannot succeed.
    pub async fn bind_network() -> Result<Self, TransportError> {
        let endpoint = Endpoint::bind(presets::N0)
            .await
            .map_err(|error| TransportError::Iroh(error.to_string()))?;
        endpoint.set_alpns(vec![PROTOCOL_ID.as_bytes().to_vec()]);
        Ok(Self {
            endpoint,
            seen_request_ids: Mutex::new(BTreeSet::new()),
        })
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
        let inserted = self
            .seen_request_ids
            .lock()
            .map_err(|_| TransportError::Iroh("request replay cache unavailable".into()))?
            .insert(frame.request.request_id.clone());
        if !inserted {
            return Err(TransportError::Iroh("replayed request identifier".into()));
        }
        connection.close(0_u8.into(), b"frame received");
        Ok(frame)
    }

    pub async fn close(self) {
        self.endpoint.close().await;
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
        let server = IrohTransport::bind_local().await.unwrap();
        let client = IrohTransport::bind_local().await.unwrap();
        let server_addr = server.addr();
        assert!(server_addr.relay_urls().next().is_none());
        let owner = Identity::from_seed([9; 32]);
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
}
