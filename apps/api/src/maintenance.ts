import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export async function appendAuditEvent(
  db: D1Database,
  input: {
    communityId: string;
    kind: string;
    actorId: string;
    subjectId: string;
    occurredAt: number;
  }
): Promise<string> {
  const previous = await db
    .prepare("SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
    .first<{ sequence: number; event_hash: string }>();
  const sequence = previous ? previous.sequence + 1 : 0;
  const previousHash = previous?.event_hash ?? "0".repeat(64);
  const canonical = [
    "acm.audit-event.v1",
    sequence,
    input.occurredAt,
    input.kind,
    input.actorId,
    input.subjectId,
    previousHash
  ].join("|");
  const eventHash = bytesToHex(blake3(new TextEncoder().encode(canonical)));
  await db
    .prepare(
      `INSERT INTO audit_events
       (sequence, community_id, event_kind, actor_id, subject_id,
        occurred_at, previous_event_hash, event_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      sequence,
      input.communityId,
      input.kind,
      input.actorId,
      input.subjectId,
      input.occurredAt,
      previousHash,
      eventHash
    )
    .run();
  return eventHash;
}

type PlacementRow = {
  object_cid: string;
  community_id: string;
  node_id: string;
};

type RepairCandidate = {
  object_cid: string;
  community_id: string;
  node_id: string;
};

export async function runMaintenance(db: D1Database, now: number): Promise<void> {
  const period = new Date(now * 1000).toISOString().slice(0, 13);
  const placements = await db
    .prepare(
      `SELECT p.object_cid, o.community_id, p.node_id
       FROM placements p JOIN objects o ON o.object_cid = p.object_cid
       JOIN nodes n ON n.node_id = p.node_id
       WHERE p.status = 'healthy' AND n.status = 'active'`
    )
    .all<PlacementRow>();
  for (const row of placements.results) {
    const taskId = `audit:${period}:${row.object_cid}:${row.node_id}`;
    await db
      .prepare(
        `INSERT OR IGNORE INTO node_tasks
         (task_id, node_id, task_kind, object_cid, payload_json,
          status, created_at, expires_at)
         VALUES (?, ?, 'audit_object', ?, ?, 'pending', ?, ?)`
      )
      .bind(
        taskId,
        row.node_id,
        row.object_cid,
        JSON.stringify({ challenge: crypto.randomUUID(), sample: "full-cid-v1" }),
        now,
        now + 6 * 3600
      )
      .run();
  }

  const repairs = await db
    .prepare(
      `SELECT o.object_cid, o.community_id, candidate.node_id
       FROM objects o
       JOIN nodes candidate ON candidate.community_id = o.community_id
         AND candidate.status = 'active'
       WHERE (SELECT COUNT(*) FROM placements p
              WHERE p.object_cid = o.object_cid AND p.status = 'healthy') < o.replica_target
         AND NOT EXISTS (SELECT 1 FROM placements existing
                         WHERE existing.object_cid = o.object_cid
                           AND existing.node_id = candidate.node_id)
         AND NOT EXISTS (
           SELECT 1 FROM placements p2 JOIN nodes n2 ON n2.node_id = p2.node_id
           WHERE p2.object_cid = o.object_cid AND p2.status = 'healthy'
             AND n2.failure_domain = candidate.failure_domain
         )
       GROUP BY o.object_cid
       ORDER BY o.object_cid`
    )
    .all<RepairCandidate>();
  for (const row of repairs.results) {
    await db
      .prepare(
        `INSERT OR IGNORE INTO node_tasks
         (task_id, node_id, task_kind, object_cid, payload_json,
          status, created_at, expires_at)
         VALUES (?, ?, 'repair_object', ?, ?, 'pending', ?, ?)`
      )
      .bind(
        `repair:${period}:${row.object_cid}:${row.node_id}`,
        row.node_id,
        row.object_cid,
        JSON.stringify({ sourceSelection: "healthy-placement" }),
        now,
        now + 6 * 3600
      )
      .run();
  }
}
