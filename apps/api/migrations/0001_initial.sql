PRAGMA foreign_keys = ON;

CREATE TABLE communities (
  community_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  root_public_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  policy_version INTEGER NOT NULL,
  status TEXT NOT NULL
);
CREATE TABLE members (
  member_id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  public_key TEXT NOT NULL,
  roles_json TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (community_id, public_key)
);
CREATE TABLE membership_credentials (
  serial TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  member_id TEXT NOT NULL REFERENCES members(member_id),
  credential_json TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE invites (
  invite_id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  code_hash TEXT NOT NULL UNIQUE,
  issued_by_member_id TEXT NOT NULL REFERENCES members(member_id),
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE TABLE join_requests (
  request_id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  member_public_key TEXT NOT NULL,
  requested_at INTEGER NOT NULL,
  status TEXT NOT NULL
);
CREATE TABLE nodes (
  node_id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  owner_member_id TEXT NOT NULL REFERENCES members(member_id),
  endpoint_public_key TEXT NOT NULL,
  certificate_json TEXT NOT NULL,
  failure_domain TEXT NOT NULL,
  region TEXT NOT NULL,
  max_storage_bytes INTEGER NOT NULL CHECK (max_storage_bytes > 0),
  status TEXT NOT NULL
);
CREATE TABLE node_heartbeats (
  node_id TEXT NOT NULL REFERENCES nodes(node_id),
  observed_at INTEGER NOT NULL,
  used_storage_bytes INTEGER NOT NULL CHECK (used_storage_bytes >= 0),
  status TEXT NOT NULL,
  PRIMARY KEY (node_id, observed_at)
);
CREATE TABLE vault_catalog_pointers (
  vault_id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  owner_member_id TEXT NOT NULL REFERENCES members(member_id),
  catalog_cid TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  previous_cid TEXT,
  signed_at INTEGER NOT NULL,
  owner_signature TEXT NOT NULL
);
CREATE TABLE objects (
  object_cid TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  ciphertext_size INTEGER NOT NULL CHECK (ciphertext_size > 0),
  object_kind TEXT NOT NULL,
  replica_target INTEGER NOT NULL CHECK (replica_target > 0),
  created_at INTEGER NOT NULL,
  retention_until INTEGER
);
CREATE TABLE placements (
  placement_id TEXT PRIMARY KEY,
  object_cid TEXT NOT NULL REFERENCES objects(object_cid),
  node_id TEXT NOT NULL REFERENCES nodes(node_id),
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (object_cid, node_id)
);
CREATE TABLE node_tasks (
  task_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(node_id),
  task_kind TEXT NOT NULL,
  object_cid TEXT REFERENCES objects(object_cid),
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE credit_accounts (
  member_id TEXT PRIMARY KEY REFERENCES members(member_id),
  created_at INTEGER NOT NULL
);
CREATE TABLE credit_entries (
  entry_id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES credit_accounts(member_id),
  idempotency_key TEXT NOT NULL UNIQUE,
  milli_gib_hour INTEGER NOT NULL,
  reason TEXT NOT NULL,
  occurred_at INTEGER NOT NULL,
  expires_at INTEGER
);
CREATE TABLE credit_grants (
  grant_id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES credit_accounts(member_id),
  period TEXT NOT NULL,
  milli_gib_hour INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  UNIQUE (member_id, period)
);
CREATE TABLE credit_policies (
  community_id TEXT PRIMARY KEY REFERENCES communities(community_id),
  monthly_base_milli_gib_hour INTEGER NOT NULL,
  earned_expiry_days INTEGER NOT NULL,
  upload_grace_days INTEGER NOT NULL
);
CREATE TABLE proposals (
  proposal_id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_by_member_id TEXT NOT NULL REFERENCES members(member_id),
  created_at INTEGER NOT NULL,
  opens_at INTEGER NOT NULL,
  closes_at INTEGER NOT NULL,
  quorum_percent INTEGER NOT NULL,
  threshold_percent INTEGER NOT NULL,
  status TEXT NOT NULL
);
CREATE TABLE votes (
  proposal_id TEXT NOT NULL REFERENCES proposals(proposal_id),
  member_id TEXT NOT NULL REFERENCES members(member_id),
  choice TEXT NOT NULL,
  cast_at INTEGER NOT NULL,
  member_signature TEXT NOT NULL,
  PRIMARY KEY (proposal_id, member_id)
);
CREATE TABLE auth_challenges (
  challenge_id TEXT PRIMARY KEY,
  challenge_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE TABLE sessions (
  session_id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members(member_id),
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  event_kind TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  occurred_at INTEGER NOT NULL,
  previous_event_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE audit_anchors (
  anchor_id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  period TEXT NOT NULL,
  merkle_root TEXT NOT NULL,
  adapter_kind TEXT NOT NULL,
  anchored_at INTEGER NOT NULL,
  UNIQUE (community_id, period, adapter_kind)
);
CREATE TABLE replay_nonces (
  nonce_hash TEXT PRIMARY KEY,
  member_id TEXT,
  expires_at INTEGER NOT NULL
);
