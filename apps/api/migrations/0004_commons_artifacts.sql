CREATE TABLE commons_artifacts (
  artifact_id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(community_id),
  owner_member_id TEXT NOT NULL REFERENCES members(member_id),
  artifact_kind TEXT NOT NULL,
  envelope_cid TEXT NOT NULL,
  encrypted_envelope_base64 TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  owner_signature TEXT NOT NULL,
  UNIQUE (community_id, envelope_cid)
);

CREATE INDEX commons_artifacts_community_created
ON commons_artifacts (community_id, created_at);
