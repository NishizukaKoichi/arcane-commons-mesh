ALTER TABLE audit_events ADD COLUMN community_sequence INTEGER NOT NULL DEFAULT 0;

UPDATE audit_events AS current
SET community_sequence = (
  SELECT COUNT(*) - 1
  FROM audit_events AS earlier
  WHERE earlier.community_id = current.community_id
    AND earlier.sequence <= current.sequence
);

CREATE UNIQUE INDEX audit_events_community_sequence
ON audit_events (community_id, community_sequence);
