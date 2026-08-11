use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
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
    #[error("invalid audit anchor")]
    InvalidAnchor,
    #[error("duplicate audit anchor")]
    DuplicateAnchor,
    #[error("audit anchor I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit anchor encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchor {
    pub community_id: String,
    pub period: String,
    pub merkle_root: String,
    pub anchored_at: i64,
}

impl AuditAnchor {
    pub fn validate(&self) -> Result<(), AuditError> {
        let root_is_hex = self.merkle_root.len() == 64
            && self
                .merkle_root
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit());
        if self.community_id.is_empty()
            || self.period.is_empty()
            || self.anchored_at < 0
            || !root_is_hex
        {
            return Err(AuditError::InvalidAnchor);
        }
        Ok(())
    }
}

pub trait AuditAnchorAdapter {
    fn kind(&self) -> &'static str;
    fn anchor(&mut self, anchor: &AuditAnchor) -> Result<(), AuditError>;
}

pub struct LocalFileAnchor {
    path: PathBuf,
}

impl LocalFileAnchor {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn contains(&self, anchor: &AuditAnchor) -> Result<bool, AuditError> {
        if !self.path.exists() {
            return Ok(false);
        }
        let reader = BufReader::new(File::open(&self.path)?);
        for line in reader.lines() {
            let existing: AuditAnchor = serde_json::from_str(&line?)?;
            if existing.community_id == anchor.community_id && existing.period == anchor.period {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditAnchorAdapter for LocalFileAnchor {
    fn kind(&self) -> &'static str {
        "local_file"
    }

    fn anchor(&mut self, anchor: &AuditAnchor) -> Result<(), AuditError> {
        anchor.validate()?;
        if self.contains(anchor)? {
            return Err(AuditError::DuplicateAnchor);
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, anchor)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }
}

#[derive(Default)]
pub struct MockAnchor {
    pub anchors: Vec<AuditAnchor>,
}

impl AuditAnchorAdapter for MockAnchor {
    fn kind(&self) -> &'static str {
        "mock"
    }

    fn anchor(&mut self, anchor: &AuditAnchor) -> Result<(), AuditError> {
        anchor.validate()?;
        if self
            .anchors
            .iter()
            .any(|item| item.community_id == anchor.community_id && item.period == anchor.period)
        {
            return Err(AuditError::DuplicateAnchor);
        }
        self.anchors.push(anchor.clone());
        Ok(())
    }
}

pub trait D1AnchorWriter {
    fn insert_anchor(&mut self, anchor: &AuditAnchor) -> Result<(), AuditError>;
}

pub struct D1Anchor<W> {
    writer: W,
}

impl<W> D1Anchor<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: D1AnchorWriter> AuditAnchorAdapter for D1Anchor<W> {
    fn kind(&self) -> &'static str {
        "d1"
    }

    fn anchor(&mut self, anchor: &AuditAnchor) -> Result<(), AuditError> {
        anchor.validate()?;
        self.writer.insert_anchor(anchor)
    }
}

/// Interface-only boundary for a possible future public-chain anchor.
///
/// This reference adapter must not be wired to RPC, wallets, keys, or contracts.
pub trait FutureEvmAnchor {
    fn encode_anchor_call(&self, anchor: &AuditAnchor) -> Result<Vec<u8>, AuditError>;
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
    use std::fs;

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

    fn fixture_anchor() -> AuditAnchor {
        AuditAnchor {
            community_id: "community-a".into(),
            period: "2026-07-26".into(),
            merkle_root: "ab".repeat(32),
            anchored_at: 1_774_742_400,
        }
    }

    #[test]
    fn local_file_anchor_is_append_only_and_rejects_duplicates() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("anchors.jsonl");
        let mut adapter = LocalFileAnchor::new(&path);
        let anchor = fixture_anchor();

        adapter.anchor(&anchor).unwrap();
        assert_eq!(adapter.kind(), "local_file");
        assert!(matches!(
            adapter.anchor(&anchor),
            Err(AuditError::DuplicateAnchor)
        ));

        let line = fs::read_to_string(path).unwrap();
        assert_eq!(
            serde_json::from_str::<AuditAnchor>(line.trim()).unwrap(),
            anchor
        );
    }

    #[derive(Default)]
    struct MemoryD1Writer {
        inserted: Vec<AuditAnchor>,
    }

    impl D1AnchorWriter for MemoryD1Writer {
        fn insert_anchor(&mut self, anchor: &AuditAnchor) -> Result<(), AuditError> {
            self.inserted.push(anchor.clone());
            Ok(())
        }
    }

    #[test]
    fn d1_and_mock_adapters_share_the_validated_boundary() {
        let anchor = fixture_anchor();
        let mut d1 = D1Anchor::new(MemoryD1Writer::default());
        let mut mock = MockAnchor::default();
        d1.anchor(&anchor).unwrap();
        mock.anchor(&anchor).unwrap();
        assert_eq!(d1.kind(), "d1");
        assert_eq!(mock.anchors, vec![anchor]);
    }

    struct MockFutureEvm;

    impl FutureEvmAnchor for MockFutureEvm {
        fn encode_anchor_call(&self, anchor: &AuditAnchor) -> Result<Vec<u8>, AuditError> {
            anchor.validate()?;
            Ok(anchor.merkle_root.as_bytes().to_vec())
        }
    }

    #[test]
    fn future_evm_is_encoding_only_without_network_or_keys() {
        let encoded = MockFutureEvm.encode_anchor_call(&fixture_anchor()).unwrap();
        assert_eq!(encoded, "ab".repeat(32).as_bytes());
    }
}
