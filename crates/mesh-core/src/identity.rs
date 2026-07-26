use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid public key")]
    PublicKey,
    #[error("invalid signature")]
    Signature,
    #[error("credential expired or not yet valid")]
    Time,
    #[error("credential belongs to another community")]
    Community,
    #[error("credential domain mismatch")]
    Domain,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    secret: [u8; 32],
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            secret: SigningKey::generate(&mut OsRng).to_bytes(),
        }
    }

    pub fn from_seed(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    pub fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.secret)
            .verifying_key()
            .to_bytes()
    }

    pub fn member_id(&self) -> String {
        format!("mem_{}", blake3::hash(&self.public_key()).to_hex())
    }

    pub fn sign(&self, bytes: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.secret).sign(bytes).to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipClaims {
    pub credential_version: u16,
    pub community_id: String,
    pub member_public_key: [u8; 32],
    pub member_id: String,
    pub roles: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub serial: u64,
    pub issuer_public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCredential {
    pub claims: MembershipClaims,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCertificateClaims {
    pub certificate_version: u16,
    pub node_id: String,
    pub community_id: String,
    pub owner_member_id: String,
    pub endpoint_public_key: String,
    pub allowed_roles: Vec<String>,
    pub max_storage_bytes: u64,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCertificate {
    pub claims: NodeCertificateClaims,
    pub signature: Vec<u8>,
}

impl MembershipClaims {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut roles = self.roles.clone();
        roles.sort();
        let mut out = Vec::new();
        field(&mut out, b"acm.membership.v1");
        out.extend_from_slice(&self.credential_version.to_be_bytes());
        field(&mut out, self.community_id.as_bytes());
        field(&mut out, &self.member_public_key);
        field(&mut out, self.member_id.as_bytes());
        out.extend_from_slice(&(roles.len() as u32).to_be_bytes());
        for role in roles {
            field(&mut out, role.as_bytes());
        }
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.serial.to_be_bytes());
        field(&mut out, &self.issuer_public_key);
        out
    }

    pub fn issue(self, issuer: &Identity) -> MembershipCredential {
        let signature = issuer.sign(&self.canonical_bytes()).to_vec();
        MembershipCredential {
            claims: self,
            signature,
        }
    }
}

impl MembershipCredential {
    pub fn verify(
        &self,
        community_id: &str,
        now: i64,
        clock_skew_seconds: i64,
    ) -> Result<(), IdentityError> {
        if self.claims.credential_version != 1 {
            return Err(IdentityError::Domain);
        }
        if self.claims.community_id != community_id {
            return Err(IdentityError::Community);
        }
        if now + clock_skew_seconds < self.claims.issued_at
            || now - clock_skew_seconds > self.claims.expires_at
        {
            return Err(IdentityError::Time);
        }
        let key = VerifyingKey::from_bytes(&self.claims.issuer_public_key)
            .map_err(|_| IdentityError::PublicKey)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| IdentityError::Signature)?;
        key.verify(&self.claims.canonical_bytes(), &signature)
            .map_err(|_| IdentityError::Signature)
    }

    pub fn verify_trusted(
        &self,
        community_id: &str,
        expected_issuer_public_key: &[u8; 32],
        now: i64,
        clock_skew_seconds: i64,
    ) -> Result<(), IdentityError> {
        if &self.claims.issuer_public_key != expected_issuer_public_key {
            return Err(IdentityError::Signature);
        }
        let expected_member_id = format!(
            "mem_{}",
            blake3::hash(&self.claims.member_public_key).to_hex()
        );
        if self.claims.member_id != expected_member_id {
            return Err(IdentityError::Domain);
        }
        self.verify(community_id, now, clock_skew_seconds)
    }

    pub fn verify_member_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), IdentityError> {
        let key = VerifyingKey::from_bytes(&self.claims.member_public_key)
            .map_err(|_| IdentityError::PublicKey)?;
        let signature = Signature::from_slice(signature).map_err(|_| IdentityError::Signature)?;
        key.verify(message, &signature)
            .map_err(|_| IdentityError::Signature)
    }
}

impl NodeCertificateClaims {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut roles = self.allowed_roles.clone();
        roles.sort();
        let mut out = Vec::new();
        field(&mut out, b"acm.node-certificate.v1");
        out.extend_from_slice(&self.certificate_version.to_be_bytes());
        field(&mut out, self.node_id.as_bytes());
        field(&mut out, self.community_id.as_bytes());
        field(&mut out, self.owner_member_id.as_bytes());
        field(&mut out, self.endpoint_public_key.as_bytes());
        out.extend_from_slice(&(roles.len() as u32).to_be_bytes());
        for role in roles {
            field(&mut out, role.as_bytes());
        }
        out.extend_from_slice(&self.max_storage_bytes.to_be_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    pub fn issue(self, owner: &Identity) -> NodeCertificate {
        let signature = owner.sign(&self.canonical_bytes()).to_vec();
        NodeCertificate {
            claims: self,
            signature,
        }
    }
}

impl NodeCertificate {
    pub fn verify(
        &self,
        owner_public_key: &[u8; 32],
        expected_community_id: &str,
        expected_endpoint_public_key: &str,
        now: i64,
        clock_skew_seconds: i64,
    ) -> Result<(), IdentityError> {
        if self.claims.certificate_version != 1
            || self.claims.endpoint_public_key != expected_endpoint_public_key
            || !self.claims.allowed_roles.iter().any(|role| role == "node")
            || self.claims.max_storage_bytes == 0
        {
            return Err(IdentityError::Domain);
        }
        if self.claims.community_id != expected_community_id {
            return Err(IdentityError::Community);
        }
        let expected_owner_id = format!("mem_{}", blake3::hash(owner_public_key).to_hex());
        if self.claims.owner_member_id != expected_owner_id {
            return Err(IdentityError::Domain);
        }
        if now + clock_skew_seconds < self.claims.issued_at
            || now - clock_skew_seconds > self.claims.expires_at
        {
            return Err(IdentityError::Time);
        }
        let key =
            VerifyingKey::from_bytes(owner_public_key).map_err(|_| IdentityError::PublicKey)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| IdentityError::Signature)?;
        key.verify(&self.claims.canonical_bytes(), &signature)
            .map_err(|_| IdentityError::Signature)
    }
}

fn field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoding_matches_shared_cross_language_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/protocol-fixtures/canonical-v1.json"
        ))
        .unwrap();
        let claims = MembershipClaims {
            credential_version: 1,
            community_id: "community-fixture".into(),
            member_public_key: [2; 32],
            member_id: fixture["member_id"].as_str().unwrap().into(),
            roles: vec!["member".into(), "admin".into()],
            issued_at: 100,
            expires_at: 200,
            serial: 7,
            issuer_public_key: [1; 32],
        };
        let certificate = NodeCertificateClaims {
            certificate_version: 1,
            node_id: "node-fixture".into(),
            community_id: "community-fixture".into(),
            owner_member_id: claims.member_id.clone(),
            endpoint_public_key: "endpoint-fixture".into(),
            allowed_roles: vec!["node".into()],
            max_storage_bytes: 4096,
            issued_at: 100,
            expires_at: 200,
        };
        let encode = |bytes: Vec<u8>| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            encode(claims.canonical_bytes()),
            fixture["membership_hex"].as_str().unwrap()
        );
        assert_eq!(
            encode(certificate.canonical_bytes()),
            fixture["node_hex"].as_str().unwrap()
        );
        assert_eq!(
            crate::cid(fixture["object_fixture"].as_str().unwrap().as_bytes()),
            fixture["object_cid"].as_str().unwrap()
        );
    }

    fn credential() -> MembershipCredential {
        let root = Identity::from_seed([1; 32]);
        let member = Identity::from_seed([2; 32]);
        MembershipClaims {
            credential_version: 1,
            community_id: "community-a".into(),
            member_public_key: member.public_key(),
            member_id: member.member_id(),
            roles: vec!["member".into(), "admin".into()],
            issued_at: 100,
            expires_at: 200,
            serial: 1,
            issuer_public_key: root.public_key(),
        }
        .issue(&root)
    }

    #[test]
    fn verifies_scope_time_and_tampering() {
        let valid = credential();
        assert!(valid.verify("community-a", 150, 5).is_ok());
        assert!(matches!(
            valid.verify("community-b", 150, 5),
            Err(IdentityError::Community)
        ));
        assert!(matches!(
            valid.verify("community-a", 300, 5),
            Err(IdentityError::Time)
        ));
        assert!(valid
            .verify_trusted("community-a", &[1; 32], 150, 5)
            .is_err());
        let mut changed = valid;
        changed.claims.roles.push("auditor".into());
        assert!(matches!(
            changed.verify("community-a", 150, 5),
            Err(IdentityError::Signature)
        ));
    }

    #[test]
    fn canonical_role_order_is_stable() {
        let root = Identity::from_seed([1; 32]);
        let member = Identity::from_seed([2; 32]);
        let base = MembershipClaims {
            credential_version: 1,
            community_id: "community-a".into(),
            member_public_key: member.public_key(),
            member_id: member.member_id(),
            roles: vec!["admin".into(), "member".into()],
            issued_at: 100,
            expires_at: 200,
            serial: 1,
            issuer_public_key: root.public_key(),
        };
        let mut reversed = base.clone();
        reversed.roles.reverse();
        assert_eq!(base.canonical_bytes(), reversed.canonical_bytes());
    }

    #[test]
    fn node_certificate_binds_a_separate_endpoint_key_to_its_owner() {
        let owner = Identity::from_seed([9; 32]);
        let certificate = NodeCertificateClaims {
            certificate_version: 1,
            node_id: "node-a".into(),
            community_id: "community-a".into(),
            owner_member_id: owner.member_id(),
            endpoint_public_key: "endpoint-public-key".into(),
            allowed_roles: vec!["node".into()],
            max_storage_bytes: 1024,
            issued_at: 100,
            expires_at: 200,
        }
        .issue(&owner);
        assert!(certificate
            .verify(
                &owner.public_key(),
                "community-a",
                "endpoint-public-key",
                150,
                5
            )
            .is_ok());
        assert!(matches!(
            certificate.verify(&owner.public_key(), "community-a", "other-endpoint", 150, 5),
            Err(IdentityError::Domain)
        ));
    }
}
