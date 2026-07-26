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

impl MembershipClaims {
    fn canonical_bytes(&self) -> Vec<u8> {
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
}

fn field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
