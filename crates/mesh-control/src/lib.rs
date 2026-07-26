#![forbid(unsafe_code)]

use arcane_mesh_core::{
    audit::{merkle_root, verify_chain, AuditEvent},
    credit::{CreditEntry, CreditLedger},
    identity::MembershipCredential,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("record already exists")]
    Conflict,
    #[error("record was not found")]
    NotFound,
    #[error("operation is not authorized")]
    Unauthorized,
    #[error("invalid signed record")]
    InvalidSignature,
    #[error("expired or replayed challenge")]
    Replay,
    #[error("invalid state transition")]
    State,
    #[error("invalid snapshot")]
    Snapshot,
    #[error("credit error: {0}")]
    Credit(#[from] arcane_mesh_core::credit::CreditError),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Community {
    pub community_id: String,
    pub name: String,
    pub root_public_key: [u8; 32],
    pub created_at: i64,
    pub policy_version: u32,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub member_id: String,
    pub public_key: [u8; 32],
    pub roles: Vec<String>,
    pub status: String,
    pub credential: MembershipCredential,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub owner_member_id: String,
    pub failure_domain: String,
    pub region: String,
    pub max_storage_bytes: u64,
    pub used_storage_bytes: u64,
    pub last_heartbeat_at: i64,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectKind {
    DataChunk,
    EncryptedManifest,
    EncryptedCatalog,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRecord {
    pub object_cid: String,
    pub ciphertext_size: u64,
    pub object_kind: ObjectKind,
    pub replica_target: u8,
    pub created_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    pub placement_id: String,
    pub object_cid: String,
    pub node_id: String,
    pub status: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogPointer {
    pub vault_id: String,
    pub catalog_cid: String,
    pub version: u64,
    pub previous_cid: Option<String>,
    pub signed_at: i64,
    pub owner_signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub proposal_id: String,
    pub title: String,
    pub body: String,
    pub created_by_member_id: String,
    pub opens_at: i64,
    pub closes_at: i64,
    pub quorum_percent: u8,
    pub threshold_percent: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub proposal_id: String,
    pub member_id: String,
    pub choice: VoteChoice,
    pub cast_at: i64,
    pub member_signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteResult {
    pub yes: u64,
    pub no: u64,
    pub abstain: u64,
    pub eligible_members: u64,
}

impl CatalogPointer {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "acm.catalog-pointer.v1|{}|{}|{}|{}|{}",
            self.vault_id,
            self.catalog_cid,
            self.version,
            self.previous_cid.as_deref().unwrap_or(""),
            self.signed_at
        )
        .into_bytes()
    }
}

impl Vote {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "acm.vote.v1|{}|{}|{:?}|{}",
            self.proposal_id, self.member_id, self.choice, self.cast_at
        )
        .into_bytes()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommunitySnapshot {
    pub format_version: u16,
    pub community: Community,
    pub members: Vec<Member>,
    pub nodes: Vec<NodeRecord>,
    pub catalog_pointers: Vec<CatalogPointer>,
    pub audit_events: Vec<AuditEvent>,
    pub audit_root: String,
    pub snapshot_hash: String,
}

#[derive(Clone, Debug)]
struct Challenge {
    expires_at: i64,
    consumed: bool,
}

pub struct LocalControlPlane {
    community: Community,
    members: BTreeMap<String, Member>,
    nodes: BTreeMap<String, NodeRecord>,
    objects: BTreeMap<String, ObjectRecord>,
    placements: BTreeMap<String, Placement>,
    catalog_pointers: BTreeMap<String, CatalogPointer>,
    proposals: BTreeMap<String, Proposal>,
    votes: BTreeMap<(String, String), Vote>,
    vote_history: Vec<Vote>,
    challenges: BTreeMap<String, Challenge>,
    replay_nonces: BTreeSet<String>,
    audit_events: Vec<AuditEvent>,
    credits: BTreeMap<String, CreditLedger>,
}

impl LocalControlPlane {
    pub fn bootstrap(community: Community, founder: Member) -> Result<Self, ControlError> {
        founder
            .credential
            .verify_trusted(
                &community.community_id,
                &community.root_public_key,
                community.created_at,
                300,
            )
            .map_err(|_| ControlError::InvalidSignature)?;
        if founder.public_key != founder.credential.claims.member_public_key
            || founder.member_id != founder.credential.claims.member_id
            || founder.credential.claims.issuer_public_key != community.root_public_key
        {
            return Err(ControlError::InvalidSignature);
        }
        let first = AuditEvent::append(
            None,
            community.created_at,
            "community_created",
            &founder.member_id,
            &community.community_id,
        );
        let mut members = BTreeMap::new();
        members.insert(founder.member_id.clone(), founder);
        Ok(Self {
            community,
            members,
            nodes: BTreeMap::new(),
            objects: BTreeMap::new(),
            placements: BTreeMap::new(),
            catalog_pointers: BTreeMap::new(),
            proposals: BTreeMap::new(),
            votes: BTreeMap::new(),
            vote_history: Vec::new(),
            challenges: BTreeMap::new(),
            replay_nonces: BTreeSet::new(),
            audit_events: vec![first],
            credits: BTreeMap::new(),
        })
    }

    pub fn issue_challenge(&mut self, now: i64) -> String {
        let mut random = [0_u8; 32];
        OsRng.fill_bytes(&mut random);
        let value = blake3::hash(&random).to_hex().to_string();
        self.challenges.insert(
            value.clone(),
            Challenge {
                expires_at: now + 300,
                consumed: false,
            },
        );
        value
    }

    pub fn consume_challenge(
        &mut self,
        challenge: &str,
        replay_nonce: &str,
        now: i64,
    ) -> Result<(), ControlError> {
        if replay_nonce.len() < 16 || !self.replay_nonces.insert(replay_nonce.into()) {
            return Err(ControlError::Replay);
        }
        let item = self
            .challenges
            .get_mut(challenge)
            .ok_or(ControlError::Replay)?;
        if item.consumed || item.expires_at < now {
            return Err(ControlError::Replay);
        }
        item.consumed = true;
        Ok(())
    }

    pub fn add_member(&mut self, member: Member, now: i64) -> Result<(), ControlError> {
        member
            .credential
            .verify_trusted(
                &self.community.community_id,
                &self.community.root_public_key,
                now,
                300,
            )
            .map_err(|_| ControlError::InvalidSignature)?;
        if member.public_key != member.credential.claims.member_public_key
            || member.member_id != member.credential.claims.member_id
            || self.members.contains_key(&member.member_id)
        {
            return Err(ControlError::Conflict);
        }
        self.append_audit(
            now,
            "membership_approved",
            &member.member_id,
            &member.member_id,
        );
        self.members.insert(member.member_id.clone(), member);
        Ok(())
    }

    pub fn register_node(
        &mut self,
        actor_member_id: &str,
        node: NodeRecord,
        now: i64,
    ) -> Result<(), ControlError> {
        self.require_active_member(actor_member_id)?;
        if node.owner_member_id != actor_member_id
            || node.max_storage_bytes == 0
            || self.nodes.contains_key(&node.node_id)
        {
            return Err(ControlError::State);
        }
        self.append_audit(now, "node_registered", actor_member_id, &node.node_id);
        self.nodes.insert(node.node_id.clone(), node);
        Ok(())
    }

    pub fn register_object(
        &mut self,
        actor_member_id: &str,
        object: ObjectRecord,
        now: i64,
    ) -> Result<(), ControlError> {
        self.require_active_member(actor_member_id)?;
        if object.object_cid.len() != 64
            || !object
                .object_cid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || object.ciphertext_size == 0
            || self.objects.contains_key(&object.object_cid)
        {
            return Err(ControlError::State);
        }
        self.append_audit(
            now,
            "object_registered",
            actor_member_id,
            &object.object_cid,
        );
        self.objects.insert(object.object_cid.clone(), object);
        Ok(())
    }

    pub fn add_placement(
        &mut self,
        actor_member_id: &str,
        placement: Placement,
        now: i64,
    ) -> Result<(), ControlError> {
        self.require_active_member(actor_member_id)?;
        if !self.objects.contains_key(&placement.object_cid)
            || !self.nodes.contains_key(&placement.node_id)
            || self.placements.contains_key(&placement.placement_id)
            || self.placements.values().any(|existing| {
                existing.object_cid == placement.object_cid
                    && existing.node_id == placement.node_id
                    && existing.status == "healthy"
            })
        {
            return Err(ControlError::State);
        }
        self.append_audit(
            now,
            "placement_created",
            actor_member_id,
            &placement.placement_id,
        );
        self.placements
            .insert(placement.placement_id.clone(), placement);
        Ok(())
    }

    pub fn update_catalog_pointer(
        &mut self,
        actor_member_id: &str,
        pointer: CatalogPointer,
    ) -> Result<(), ControlError> {
        self.require_active_member(actor_member_id)?;
        let member = self
            .members
            .get(actor_member_id)
            .ok_or(ControlError::Unauthorized)?;
        member
            .credential
            .verify_member_signature(&pointer.signing_bytes(), &pointer.owner_signature)
            .map_err(|_| ControlError::InvalidSignature)?;
        if let Some(previous) = self.catalog_pointers.get(&pointer.vault_id) {
            if pointer.version != previous.version + 1
                || pointer.previous_cid.as_deref() != Some(previous.catalog_cid.as_str())
            {
                return Err(ControlError::State);
            }
        } else if pointer.version != 1 || pointer.previous_cid.is_some() {
            return Err(ControlError::State);
        }
        self.append_audit(
            pointer.signed_at,
            "catalog_pointer_updated",
            actor_member_id,
            &pointer.vault_id,
        );
        self.catalog_pointers
            .insert(pointer.vault_id.clone(), pointer);
        Ok(())
    }

    pub fn record_credit(
        &mut self,
        member_id: &str,
        entry: CreditEntry,
    ) -> Result<(), ControlError> {
        self.require_active_member(member_id)?;
        let occurred_at = entry.occurred_at;
        let reason = format!("{:?}", entry.reason);
        self.credits
            .entry(member_id.into())
            .or_default()
            .record(entry)?;
        self.append_audit(occurred_at, "credit_entry_recorded", member_id, &reason);
        Ok(())
    }

    pub fn credit_balance(&self, member_id: &str, now: i64) -> Result<i64, ControlError> {
        self.require_active_member(member_id)?;
        self.credits
            .get(member_id)
            .map_or(Ok(0), |ledger| ledger.balance_at(now).map_err(Into::into))
    }

    pub fn create_proposal(&mut self, proposal: Proposal, now: i64) -> Result<(), ControlError> {
        self.require_active_member(&proposal.created_by_member_id)?;
        if proposal.opens_at >= proposal.closes_at
            || proposal.quorum_percent > 100
            || proposal.threshold_percent > 100
            || self.proposals.contains_key(&proposal.proposal_id)
        {
            return Err(ControlError::State);
        }
        self.append_audit(
            now,
            "proposal_created",
            &proposal.created_by_member_id,
            &proposal.proposal_id,
        );
        self.proposals
            .insert(proposal.proposal_id.clone(), proposal);
        Ok(())
    }

    pub fn cast_vote(&mut self, vote: Vote) -> Result<(), ControlError> {
        self.require_active_member(&vote.member_id)?;
        let proposal = self
            .proposals
            .get(&vote.proposal_id)
            .ok_or(ControlError::NotFound)?;
        if vote.cast_at < proposal.opens_at || vote.cast_at > proposal.closes_at {
            return Err(ControlError::State);
        }
        let member = self
            .members
            .get(&vote.member_id)
            .ok_or(ControlError::Unauthorized)?;
        member
            .credential
            .verify_member_signature(&vote.signing_bytes(), &vote.member_signature)
            .map_err(|_| ControlError::InvalidSignature)?;
        self.append_audit(
            vote.cast_at,
            "vote_cast",
            &vote.member_id,
            &vote.proposal_id,
        );
        self.vote_history.push(vote.clone());
        self.votes
            .insert((vote.proposal_id.clone(), vote.member_id.clone()), vote);
        Ok(())
    }

    pub fn vote_result(&self, proposal_id: &str) -> Result<VoteResult, ControlError> {
        if !self.proposals.contains_key(proposal_id) {
            return Err(ControlError::NotFound);
        }
        let mut result = VoteResult {
            yes: 0,
            no: 0,
            abstain: 0,
            eligible_members: self
                .members
                .values()
                .filter(|member| member.status == "active")
                .count() as u64,
        };
        for vote in self
            .votes
            .values()
            .filter(|vote| vote.proposal_id == proposal_id)
        {
            match vote.choice {
                VoteChoice::Yes => result.yes += 1,
                VoteChoice::No => result.no += 1,
                VoteChoice::Abstain => result.abstain += 1,
            }
        }
        Ok(result)
    }

    pub fn vote_history_len(&self) -> usize {
        self.vote_history.len()
    }

    pub fn export_snapshot(&self) -> Result<Vec<u8>, ControlError> {
        verify_chain(&self.audit_events).map_err(|_| ControlError::Snapshot)?;
        let mut snapshot = CommunitySnapshot {
            format_version: 1,
            community: self.community.clone(),
            members: self.members.values().cloned().collect(),
            nodes: self.nodes.values().cloned().collect(),
            catalog_pointers: self.catalog_pointers.values().cloned().collect(),
            audit_events: self.audit_events.clone(),
            audit_root: merkle_root(&self.audit_events),
            snapshot_hash: String::new(),
        };
        let canonical = serde_json::to_vec(&snapshot).map_err(|_| ControlError::Snapshot)?;
        snapshot.snapshot_hash = blake3::hash(&canonical).to_hex().to_string();
        serde_json::to_vec_pretty(&snapshot).map_err(|_| ControlError::Snapshot)
    }

    pub fn verify_snapshot(bytes: &[u8]) -> Result<CommunitySnapshot, ControlError> {
        let mut snapshot: CommunitySnapshot =
            serde_json::from_slice(bytes).map_err(|_| ControlError::Snapshot)?;
        if snapshot.format_version != 1
            || verify_chain(&snapshot.audit_events).is_err()
            || snapshot.audit_root != merkle_root(&snapshot.audit_events)
        {
            return Err(ControlError::Snapshot);
        }
        let claimed = std::mem::take(&mut snapshot.snapshot_hash);
        let canonical = serde_json::to_vec(&snapshot).map_err(|_| ControlError::Snapshot)?;
        snapshot.snapshot_hash = claimed.clone();
        if claimed != blake3::hash(&canonical).to_hex().to_string() {
            return Err(ControlError::Snapshot);
        }
        Ok(snapshot)
    }

    pub fn audit_events(&self) -> &[AuditEvent] {
        &self.audit_events
    }

    fn require_active_member(&self, member_id: &str) -> Result<&Member, ControlError> {
        self.members
            .get(member_id)
            .filter(|member| member.status == "active")
            .ok_or(ControlError::Unauthorized)
    }

    fn append_audit(&mut self, now: i64, kind: &str, actor: &str, subject: &str) {
        let event = AuditEvent::append(self.audit_events.last(), now, kind, actor, subject);
        self.audit_events.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcane_mesh_core::{
        credit::{CreditReason, MILLI_PER_GIB_HOUR},
        identity::{Identity, MembershipClaims},
    };

    fn member(root: &Identity, identity: &Identity, serial: u64, roles: &[&str]) -> Member {
        let claims = MembershipClaims {
            credential_version: 1,
            community_id: "community".into(),
            member_public_key: identity.public_key(),
            member_id: identity.member_id(),
            roles: roles.iter().map(|role| (*role).into()).collect(),
            issued_at: 100,
            expires_at: 1000,
            serial,
            issuer_public_key: root.public_key(),
        };
        Member {
            member_id: identity.member_id(),
            public_key: identity.public_key(),
            roles: claims.roles.clone(),
            status: "active".into(),
            credential: claims.issue(root),
        }
    }

    fn control() -> (LocalControlPlane, Identity, Identity) {
        let root = Identity::from_seed([1; 32]);
        let founder = Identity::from_seed([2; 32]);
        let community = Community {
            community_id: "community".into(),
            name: "Test Commons".into(),
            root_public_key: root.public_key(),
            created_at: 100,
            policy_version: 1,
            status: "active".into(),
        };
        (
            LocalControlPlane::bootstrap(
                community,
                member(&root, &founder, 1, &["member", "admin"]),
            )
            .unwrap(),
            root,
            founder,
        )
    }

    #[test]
    fn challenges_are_single_use_and_nonce_replay_is_rejected() {
        let (mut control, _, _) = control();
        let challenge = control.issue_challenge(100);
        control
            .consume_challenge(&challenge, "nonce-0000000001", 101)
            .unwrap();
        assert!(matches!(
            control.consume_challenge(&challenge, "nonce-0000000002", 102),
            Err(ControlError::Replay)
        ));
    }

    #[test]
    fn rejects_self_issued_membership_for_an_existing_community() {
        let (mut control, _, _) = control();
        let attacker = Identity::from_seed([8; 32]);
        let forged = member(&attacker, &attacker, 99, &["member", "admin"]);
        assert!(matches!(
            control.add_member(forged, 150),
            Err(ControlError::InvalidSignature)
        ));
    }

    #[test]
    fn catalog_rejects_rollback_and_fork() {
        let (mut control, _, founder) = control();
        let mut first = CatalogPointer {
            vault_id: "vault".into(),
            catalog_cid: "a".repeat(64),
            version: 1,
            previous_cid: None,
            signed_at: 110,
            owner_signature: Vec::new(),
        };
        first.owner_signature = founder.sign(&first.signing_bytes()).to_vec();
        control
            .update_catalog_pointer(&founder.member_id(), first)
            .unwrap();
        let mut tampered = CatalogPointer {
            vault_id: "vault".into(),
            catalog_cid: "b".repeat(64),
            version: 2,
            previous_cid: Some("a".repeat(64)),
            signed_at: 111,
            owner_signature: vec![0; 64],
        };
        assert!(matches!(
            control.update_catalog_pointer(&founder.member_id(), tampered.clone()),
            Err(ControlError::InvalidSignature)
        ));
        tampered.owner_signature = founder.sign(&tampered.signing_bytes()).to_vec();
        control
            .update_catalog_pointer(&founder.member_id(), tampered)
            .unwrap();
        let mut fork = CatalogPointer {
            vault_id: "vault".into(),
            catalog_cid: "c".repeat(64),
            version: 2,
            previous_cid: Some("a".repeat(64)),
            signed_at: 112,
            owner_signature: Vec::new(),
        };
        fork.owner_signature = founder.sign(&fork.signing_bytes()).to_vec();
        assert!(matches!(
            control.update_catalog_pointer(&founder.member_id(), fork),
            Err(ControlError::State)
        ));
    }

    #[test]
    fn duplicate_vote_updates_one_person_one_vote_and_keeps_history() {
        let (mut control, root, founder) = control();
        let bob = Identity::from_seed([3; 32]);
        control
            .add_member(member(&root, &bob, 2, &["member"]), 150)
            .unwrap();
        control
            .create_proposal(
                Proposal {
                    proposal_id: "proposal".into(),
                    title: "Policy".into(),
                    body: "Test policy".into(),
                    created_by_member_id: founder.member_id(),
                    opens_at: 160,
                    closes_at: 300,
                    quorum_percent: 20,
                    threshold_percent: 50,
                },
                150,
            )
            .unwrap();
        for (choice, time) in [(VoteChoice::Yes, 170), (VoteChoice::No, 180)] {
            let mut vote = Vote {
                proposal_id: "proposal".into(),
                member_id: bob.member_id(),
                choice,
                cast_at: time,
                member_signature: Vec::new(),
            };
            vote.member_signature = bob.sign(&vote.signing_bytes()).to_vec();
            control.cast_vote(vote).unwrap();
        }
        let result = control.vote_result("proposal").unwrap();
        assert_eq!((result.yes, result.no, result.abstain), (0, 1, 0));
        assert_eq!(result.eligible_members, 2);
        assert_eq!(control.vote_history_len(), 2);
    }

    #[test]
    fn credit_has_no_transfer_and_snapshot_is_tamper_evident() {
        let (mut control, _, founder) = control();
        control
            .record_credit(
                &founder.member_id(),
                CreditEntry {
                    idempotency_key: "base-2026-07".into(),
                    milli_gib_hour: 100 * MILLI_PER_GIB_HOUR,
                    reason: CreditReason::MonthlyBaseGrant,
                    occurred_at: 120,
                    expires_at: Some(200),
                },
            )
            .unwrap();
        assert_eq!(
            control.credit_balance(&founder.member_id(), 150).unwrap(),
            100_000
        );
        let snapshot = control.export_snapshot().unwrap();
        LocalControlPlane::verify_snapshot(&snapshot).unwrap();
        let mut changed = snapshot;
        let index = changed.len() - 2;
        changed[index] ^= 1;
        assert!(matches!(
            LocalControlPlane::verify_snapshot(&changed),
            Err(ControlError::Snapshot)
        ));
    }
}
