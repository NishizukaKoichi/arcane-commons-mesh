use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub occurred_at: i64,
    pub kind: String,
    pub actor_id: String,
    pub subject_id: String,
    pub previous_hash: String,
    pub event_hash: String,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("invalid audit sequence")]
    Sequence,
    #[error("broken audit hash chain")]
    Chain,
}

impl AuditEvent {
    pub fn append(
        previous: Option<&AuditEvent>,
        occurred_at: i64,
        kind: impl Into<String>,
        actor_id: impl Into<String>,
        subject_id: impl Into<String>,
    ) -> Self {
        let sequence = previous.map_or(0, |event| event.sequence + 1);
        let previous_hash =
            previous.map_or_else(|| "0".repeat(64), |event| event.event_hash.clone());
        let mut event = Self {
            sequence,
            occurred_at,
            kind: kind.into(),
            actor_id: actor_id.into(),
            subject_id: subject_id.into(),
            previous_hash,
            event_hash: String::new(),
        };
        event.event_hash = event.calculate_hash();
        event
    }

    fn calculate_hash(&self) -> String {
        let canonical = format!(
            "acm.audit-event.v1|{}|{}|{}|{}|{}|{}",
            self.sequence,
            self.occurred_at,
            self.kind,
            self.actor_id,
            self.subject_id,
            self.previous_hash
        );
        blake3::hash(canonical.as_bytes()).to_hex().to_string()
    }
}

pub fn verify_chain(events: &[AuditEvent]) -> Result<(), AuditError> {
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64 {
            return Err(AuditError::Sequence);
        }
        let expected_previous = if index == 0 {
            "0".repeat(64)
        } else {
            events[index - 1].event_hash.clone()
        };
        if event.previous_hash != expected_previous || event.event_hash != event.calculate_hash() {
            return Err(AuditError::Chain);
        }
    }
    Ok(())
}

pub fn merkle_root(events: &[AuditEvent]) -> String {
    if events.is_empty() {
        return blake3::hash(b"acm.audit.empty.v1").to_hex().to_string();
    }
    let mut level: Vec<[u8; 32]> = events
        .iter()
        .map(|event| *blake3::hash(event.event_hash.as_bytes()).as_bytes())
        .collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty merkle level"));
        }
        level = level
            .chunks_exact(2)
            .map(|pair| {
                let mut input = [0_u8; 64];
                input[..32].copy_from_slice(&pair[0]);
                input[32..].copy_from_slice(&pair[1]);
                *blake3::hash(&input).as_bytes()
            })
            .collect();
    }
    blake3::Hash::from_bytes(level[0]).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_and_merkle_are_deterministic_and_tamper_evident() {
        let first = AuditEvent::append(None, 10, "community_created", "a", "c");
        let second = AuditEvent::append(Some(&first), 11, "node_registered", "a", "n");
        let events = vec![first, second];
        verify_chain(&events).unwrap();
        assert_eq!(merkle_root(&events), merkle_root(&events));
        let mut changed = events;
        changed[0].subject_id = "changed".into();
        assert!(verify_chain(&changed).is_err());
    }
}
