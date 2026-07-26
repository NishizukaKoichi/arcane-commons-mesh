import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import {
  catalogPointer,
  challengeSession,
  community,
  heartbeat,
  joinRequest,
  membershipApproval,
  node,
  objectRecord,
  placement,
  proposal,
  vote
} from "./schemas";
import {
  asArrayBuffer,
  D1Repository,
  fromBase64Url,
  hashOpaque,
  MemoryRepository,
  type AuthRepository,
  type SessionPrincipal,
  toBase64Url
} from "./repository";
import { appendAuditEvent, runMaintenance } from "./maintenance";

type Bindings = {
  DB?: D1Database;
  INTERNAL_SECRET?: string;
};

type Variables = {
  principal: SessionPrincipal;
};

export type AppOptions = {
  repository?: MemoryRepository;
  now?: () => number;
  internalSecret?: string;
};

export function createApp(options: AppOptions = {}) {
  const memoryRepository = options.repository ?? new MemoryRepository();
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const internalSecret = options.internalSecret;
  const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();
  const repositoryFor = (db?: D1Database): AuthRepository =>
    options.repository ?? (db ? new D1Repository(db) : memoryRepository);
  const verifySignature = async (
    publicKey: string,
    signature: string,
    message: string
  ): Promise<boolean> => {
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        asArrayBuffer(fromBase64Url(publicKey)),
        { name: "Ed25519" },
        false,
        ["verify"]
      );
      return crypto.subtle.verify(
        "Ed25519",
        key,
        asArrayBuffer(fromBase64Url(signature)),
        asArrayBuffer(new TextEncoder().encode(message))
      );
    } catch {
      return false;
    }
  };

  app.get("/health", (context) => context.json({ status: "ok" }));

  app.post("/v1/auth/challenges", async (context) => {
    const random = crypto.getRandomValues(new Uint8Array(32));
    const value = toBase64Url(random);
    const repository = repositoryFor(context.env?.DB);
    const challenge = await repository.createChallenge(await hashOpaque(value), now());
    return context.json(
      {
        challengeId: challenge.id,
        challenge: value,
        expiresAt: challenge.expiresAt
      },
      201
    );
  });

  app.post("/v1/auth/sessions", zValidator("json", challengeSession), async (context) => {
    const body = context.req.valid("json");
    const repository = repositoryFor(context.env?.DB);
    const challenge = await repository.getChallenge(body.challengeId);
    if (
      !challenge ||
      challenge.consumed ||
      challenge.expiresAt < now() ||
      challenge.valueHash !== (await hashOpaque(body.challenge))
    ) {
      return context.json({ error: "expired_or_replayed_challenge" }, 401);
    }
    const valid = await verifySignature(
      body.publicKey,
      body.signature,
      `acm.auth.v1|${challenge.id}|${body.challenge}|${body.replayNonce}|${body.memberId}|${body.publicKey}`
    );
    if (!valid) {
      return context.json({ error: "invalid_signature" }, 401);
    }
    const sessionToken = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const principal = await repository.consumeChallengeAndCreateSession({
      challengeId: body.challengeId,
      replayNonceHash: await hashOpaque(body.replayNonce),
      memberId: body.memberId,
      publicKey: body.publicKey,
      tokenHash: await hashOpaque(sessionToken),
      now: now()
    });
    if (!principal) return context.json({ error: "membership_or_replay_rejected" }, 401);
    return context.json({
      sessionToken,
      expiresAt: principal.expiresAt,
      memberId: principal.memberId
    });
  });

  app.use("/v1/*", async (context, next) => {
    if (
      context.req.path.startsWith("/v1/auth/") ||
      context.req.path === "/v1/communities" ||
      context.req.path === "/v1/internal/audit-anchors/run" ||
      (context.req.method === "POST" && context.req.path.endsWith("/join-requests"))
    ) {
      return next();
    }
    const authorization = context.req.header("authorization");
    if (!authorization?.startsWith("Bearer ")) {
      return context.json({ error: "authentication_required" }, 401);
    }
    const principal = await repositoryFor(context.env?.DB).authenticate(
      await hashOpaque(authorization.slice(7)),
      now()
    );
    if (!principal) return context.json({ error: "invalid_or_expired_session" }, 401);
    context.set("principal", principal);
    await next();
  });

  app.delete("/v1/auth/sessions/current", async (context) => {
    const authorization = context.req.header("authorization");
    if (!authorization?.startsWith("Bearer ")) {
      return context.json({ error: "authentication_required" }, 401);
    }
    const repository = repositoryFor(context.env?.DB);
    const principal = await repository.authenticate(
      await hashOpaque(authorization.slice(7)),
      now()
    );
    if (!principal) return context.json({ error: "invalid_or_expired_session" }, 401);
    await repository.revokeSession(principal.sessionId, now());
    return context.json({ status: "revoked" });
  });

  app.post("/v1/communities", zValidator("json", community), async (context) => {
    const item = context.req.valid("json");
    const roles = [...item.founderRoles].sort();
    if (!roles.includes("member") || !roles.includes("admin")) {
      return context.json({ error: "founder_requires_member_and_admin_roles" }, 400);
    }
    const message = [
      "acm.community-bootstrap.v1",
      item.communityId,
      item.name,
      item.rootPublicKey,
      item.createdAt,
      item.policyVersion,
      item.founderMemberId,
      item.founderPublicKey,
      roles.join(",")
    ].join("|");
    if (!(await verifySignature(item.rootPublicKey, item.rootSignature, message))) {
      return context.json({ error: "invalid_root_signature" }, 401);
    }
    if (context.env?.DB) {
      try {
        await context.env.DB.batch([
          context.env.DB.prepare(
            `INSERT INTO communities
             (community_id, name, root_public_key, created_at, policy_version, status)
             VALUES (?, ?, ?, ?, ?, 'active')`
          ).bind(
            item.communityId,
            item.name,
            item.rootPublicKey,
            item.createdAt,
            item.policyVersion
          ),
          context.env.DB.prepare(
            `INSERT INTO members
             (member_id, community_id, public_key, roles_json, status, created_at)
             VALUES (?, ?, ?, ?, 'active', ?)`
          ).bind(
            item.founderMemberId,
            item.communityId,
            item.founderPublicKey,
            JSON.stringify(roles),
            item.createdAt
          ),
          context.env.DB.prepare(
            `INSERT INTO membership_credentials
             (serial, community_id, member_id, credential_json, issued_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)`
          ).bind(
            `bootstrap:${item.communityId}`,
            item.communityId,
            item.founderMemberId,
            JSON.stringify({ message, rootSignature: item.rootSignature }),
            item.createdAt,
            item.createdAt + 31_536_000
          )
        ]);
        await appendAuditEvent(context.env.DB, {
          communityId: item.communityId,
          kind: "community_created",
          actorId: item.founderMemberId,
          subjectId: item.communityId,
          occurredAt: item.createdAt
        });
      } catch {
        return context.json({ error: "community_conflict" }, 409);
      }
    } else {
      memoryRepository.addMember({
        memberId: item.founderMemberId,
        communityId: item.communityId,
        publicKey: item.founderPublicKey,
        roles
      });
    }
    return context.json(
      {
        communityId: item.communityId,
        name: item.name,
        rootPublicKey: item.rootPublicKey,
        policyVersion: item.policyVersion,
        status: "active"
      },
      201
    );
  });
  app.get("/v1/communities/:communityId", async (context) => {
    const communityId = context.req.param("communityId");
    if (context.get("principal").communityId !== communityId) {
      return context.json({ error: "wrong_community" }, 403);
    }
    if (!context.env?.DB) return context.json({ communityId, status: "active" });
    const row = await context.env.DB.prepare(
      `SELECT community_id AS communityId, name, root_public_key AS rootPublicKey,
              policy_version AS policyVersion, status
       FROM communities WHERE community_id = ?`
    )
      .bind(communityId)
      .first();
    return row ? context.json(row) : context.json({ error: "not_found" }, 404);
  });
  app.post("/v1/communities/:communityId/invites", async (context) => {
    const principal = context.get("principal");
    const communityId = context.req.param("communityId");
    if (principal.communityId !== communityId || !principal.roles.includes("admin")) {
      return context.json({ error: "admin_required" }, 403);
    }
    const inviteId = crypto.randomUUID();
    const inviteCode = toBase64Url(crypto.getRandomValues(new Uint8Array(24)));
    if (context.env?.DB) {
      await context.env.DB.prepare(
        `INSERT INTO invites
         (invite_id, community_id, code_hash, issued_by_member_id, expires_at)
         VALUES (?, ?, ?, ?, ?)`
      )
        .bind(inviteId, communityId, await hashOpaque(inviteCode), principal.memberId, now() + 86400)
        .run();
    }
    return context.json({ inviteId, inviteCode, expiresAt: now() + 86400 }, 201);
  });
  app.post(
    "/v1/communities/:communityId/join-requests",
    zValidator("json", joinRequest),
    async (context) => {
      const communityId = context.req.param("communityId");
      const item = context.req.valid("json");
      const requestId = crypto.randomUUID();
      if (context.env?.DB) {
        const invite = await context.env.DB.prepare(
          `SELECT invite_id FROM invites
           WHERE community_id = ? AND code_hash = ? AND consumed_at IS NULL AND expires_at >= ?`
        )
          .bind(communityId, await hashOpaque(item.inviteCode), now())
          .first<{ invite_id: string }>();
        if (!invite) return context.json({ error: "invalid_invite" }, 401);
        try {
          await context.env.DB.batch([
            context.env.DB.prepare(
              `INSERT INTO join_requests
               (request_id, community_id, member_public_key, requested_at, status)
               VALUES (?, ?, ?, ?, 'pending')`
            ).bind(requestId, communityId, item.memberPublicKey, now()),
            context.env.DB.prepare(
              "UPDATE invites SET consumed_at = ? WHERE invite_id = ? AND consumed_at IS NULL"
            ).bind(now(), invite.invite_id)
          ]);
        } catch {
          return context.json({ error: "join_request_conflict" }, 409);
        }
      }
      return context.json({ requestId, status: "pending" }, 201);
    }
  );
  app.get("/v1/communities/:communityId/join-requests", async (context) => {
    const principal = context.get("principal");
    const communityId = context.req.param("communityId");
    if (principal.communityId !== communityId || !principal.roles.includes("admin")) {
      return context.json({ error: "admin_required" }, 403);
    }
    if (!context.env?.DB) return context.json({ communityId, requests: [] });
    const rows = await context.env.DB.prepare(
      `SELECT request_id AS requestId, member_public_key AS memberPublicKey,
              requested_at AS requestedAt, status
       FROM join_requests WHERE community_id = ? ORDER BY requested_at`
    )
      .bind(communityId)
      .all();
    return context.json({ communityId, requests: rows.results });
  });
  app.post(
    "/v1/communities/:communityId/join-requests/:requestId/approve",
    zValidator("json", membershipApproval),
    async (context) => {
      const principal = context.get("principal");
      const communityId = context.req.param("communityId");
      const requestId = context.req.param("requestId");
      const item = context.req.valid("json");
      if (principal.communityId !== communityId || !principal.roles.includes("admin")) {
        return context.json({ error: "admin_required" }, 403);
      }
      const roles = [...item.roles].sort();
      const message = [
        "acm.membership.v1",
        communityId,
        item.memberId,
        item.memberPublicKey,
        roles.join(","),
        item.serial,
        item.issuedAt,
        item.expiresAt
      ].join("|");
      if (!context.env?.DB) {
        memoryRepository.addMember({
          memberId: item.memberId,
          communityId,
          publicKey: item.memberPublicKey,
          roles
        });
        return context.json({ requestId, memberId: item.memberId, status: "approved" });
      }
      const root = await context.env.DB.prepare(
        "SELECT root_public_key FROM communities WHERE community_id = ? AND status = 'active'"
      )
        .bind(communityId)
        .first<{ root_public_key: string }>();
      const pending = await context.env.DB.prepare(
        `SELECT member_public_key FROM join_requests
         WHERE request_id = ? AND community_id = ? AND status = 'pending'`
      )
        .bind(requestId, communityId)
        .first<{ member_public_key: string }>();
      if (
        !root ||
        !pending ||
        pending.member_public_key !== item.memberPublicKey ||
        !(await verifySignature(root.root_public_key, item.rootSignature, message))
      ) {
        return context.json({ error: "invalid_membership_approval" }, 401);
      }
      try {
        await context.env.DB.batch([
          context.env.DB.prepare(
            `INSERT INTO members
             (member_id, community_id, public_key, roles_json, status, created_at)
             VALUES (?, ?, ?, ?, 'active', ?)`
          ).bind(item.memberId, communityId, item.memberPublicKey, JSON.stringify(roles), now()),
          context.env.DB.prepare(
            `INSERT INTO membership_credentials
             (serial, community_id, member_id, credential_json, issued_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)`
          ).bind(
            item.serial,
            communityId,
            item.memberId,
            JSON.stringify({ message, rootSignature: item.rootSignature }),
            item.issuedAt,
            item.expiresAt
          ),
          context.env.DB.prepare(
            "UPDATE join_requests SET status = 'approved' WHERE request_id = ? AND status = 'pending'"
          ).bind(requestId)
        ]);
      } catch {
        return context.json({ error: "membership_conflict" }, 409);
      }
      return context.json({ requestId, memberId: item.memberId, status: "approved" });
    }
  );
  app.get("/v1/communities/:communityId/members", async (context) => {
    const principal = context.get("principal");
    const communityId = context.req.param("communityId");
    if (principal.communityId !== communityId) {
      return context.json({ error: "wrong_community" }, 403);
    }
    if (!context.env?.DB) return context.json({ communityId, members: [] });
    const rows = await context.env.DB.prepare(
      `SELECT member_id AS memberId, public_key AS publicKey, roles_json AS rolesJson, status
       FROM members WHERE community_id = ? ORDER BY created_at`
    )
      .bind(communityId)
      .all();
    return context.json({
      communityId,
      members: rows.results.map((row) => ({
        ...row,
        roles: JSON.parse(String(row.rolesJson)),
        rolesJson: undefined
      }))
    });
  });
  app.post("/v1/communities/:communityId/members/:memberId/revoke", async (context) => {
    const principal = context.get("principal");
    const communityId = context.req.param("communityId");
    const memberId = context.req.param("memberId");
    if (principal.communityId !== communityId || !principal.roles.includes("admin")) {
      return context.json({ error: "admin_required" }, 403);
    }
    if (context.env?.DB) {
      await context.env.DB.batch([
        context.env.DB.prepare(
          "UPDATE members SET status = 'revoked' WHERE community_id = ? AND member_id = ?"
        ).bind(communityId, memberId),
        context.env.DB.prepare(
          "UPDATE membership_credentials SET revoked_at = ? WHERE community_id = ? AND member_id = ?"
        ).bind(now(), communityId, memberId),
        context.env.DB.prepare(
          "UPDATE sessions SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL"
        ).bind(now(), memberId)
      ]);
    }
    return context.json({ memberId, status: "revoked" });
  });

  app.post("/v1/nodes", zValidator("json", node), async (context) => {
    const item = context.req.valid("json");
    const principal = context.get("principal");
    if (
      item.communityId !== principal.communityId ||
      item.ownerMemberId !== principal.memberId ||
      item.expiresAt <= now()
    ) {
      return context.json({ error: "node_scope_rejected" }, 403);
    }
    const message = [
      "acm.node-certificate.v1",
      item.nodeId,
      item.communityId,
      item.ownerMemberId,
      item.endpointPublicKey,
      "node",
      item.maxStorageBytes,
      item.issuedAt,
      item.expiresAt
    ].join("|");
    if (!(await verifySignature(principal.publicKey, item.certificateSignature, message))) {
      return context.json({ error: "invalid_node_certificate" }, 401);
    }
    if (context.env?.DB) {
      try {
        await context.env.DB.prepare(
          `INSERT INTO nodes
           (node_id, community_id, owner_member_id, endpoint_public_key, certificate_json,
            failure_domain, region, max_storage_bytes, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')`
        )
          .bind(
            item.nodeId,
            item.communityId,
            item.ownerMemberId,
            item.endpointPublicKey,
            JSON.stringify({ message, signature: item.certificateSignature }),
            item.failureDomain,
            item.region,
            item.maxStorageBytes
          )
          .run();
        await appendAuditEvent(context.env.DB, {
          communityId: item.communityId,
          kind: "node_registered",
          actorId: principal.memberId,
          subjectId: item.nodeId,
          occurredAt: now()
        });
      } catch {
        return context.json({ error: "node_conflict" }, 409);
      }
    }
    return context.json({ ...item, certificateSignature: undefined, status: "active" }, 201);
  });
  app.post(
    "/v1/nodes/:nodeId/heartbeat",
    zValidator("json", heartbeat),
    async (context) => {
      const item = context.req.valid("json");
      const nodeId = context.req.param("nodeId");
      const principal = context.get("principal");
      if (context.env?.DB) {
        const owned = await context.env.DB.prepare(
          `SELECT node_id FROM nodes
           WHERE node_id = ? AND owner_member_id = ? AND community_id = ? AND status = 'active'`
        )
          .bind(nodeId, principal.memberId, principal.communityId)
          .first();
        if (!owned) return context.json({ error: "node_owner_required" }, 403);
        await context.env.DB.prepare(
          `INSERT INTO node_heartbeats (node_id, observed_at, used_storage_bytes, status)
           VALUES (?, ?, ?, ?)`
        )
          .bind(nodeId, now(), item.usedStorageBytes, item.status)
          .run();
      }
      return context.json({ nodeId, status: item.status });
    }
  );
  app.get("/v1/nodes/candidates", async (context) => {
    const principal = context.get("principal");
    if (!context.env?.DB) return context.json({ nodes: [] });
    const rows = await context.env.DB.prepare(
      `SELECT n.node_id AS nodeId, n.endpoint_public_key AS endpointPublicKey,
              n.failure_domain AS failureDomain, n.region, n.max_storage_bytes AS maxStorageBytes,
              COALESCE(h.used_storage_bytes, 0) AS usedStorageBytes
       FROM nodes n LEFT JOIN node_heartbeats h ON h.node_id = n.node_id
       WHERE n.community_id = ? AND n.status = 'active'
       GROUP BY n.node_id ORDER BY n.node_id`
    )
      .bind(principal.communityId)
      .all();
    return context.json({ nodes: rows.results });
  });
  app.get("/v1/nodes/:nodeId", async (context) => {
    const principal = context.get("principal");
    if (!context.env?.DB) {
      return context.json({ nodeId: context.req.param("nodeId"), status: "online" });
    }
    const row = await context.env.DB.prepare(
      `SELECT node_id AS nodeId, endpoint_public_key AS endpointPublicKey,
              failure_domain AS failureDomain, region, max_storage_bytes AS maxStorageBytes, status
       FROM nodes WHERE node_id = ? AND community_id = ?`
    )
      .bind(context.req.param("nodeId"), principal.communityId)
      .first();
    return row ? context.json(row) : context.json({ error: "not_found" }, 404);
  });
  app.post("/v1/nodes/:nodeId/disable", async (context) => {
    const principal = context.get("principal");
    if (!principal.roles.includes("admin")) {
      return context.json({ error: "admin_required" }, 403);
    }
    const nodeId = context.req.param("nodeId");
    if (context.env?.DB) {
      await context.env.DB.prepare(
        "UPDATE nodes SET status = 'disabled' WHERE node_id = ? AND community_id = ?"
      )
        .bind(nodeId, principal.communityId)
        .run();
    }
    return context.json({ nodeId, status: "disabled" });
  });

  app.put(
    "/v1/vaults/:vaultId/catalog-pointer",
    zValidator("json", catalogPointer),
    async (context) => {
      const vaultId = context.req.param("vaultId");
      const item = context.req.valid("json");
      const principal = context.get("principal");
      const message = [
        "acm.catalog-pointer.v1",
        vaultId,
        item.catalogCid,
        item.version,
        item.previousCid ?? "",
        item.signedAt
      ].join("|");
      if (!(await verifySignature(principal.publicKey, item.ownerSignature, message))) {
        return context.json({ error: "invalid_catalog_signature" }, 401);
      }
      if (context.env?.DB) {
        const previous = await context.env.DB.prepare(
          `SELECT owner_member_id, catalog_cid, version FROM vault_catalog_pointers
           WHERE vault_id = ?`
        )
          .bind(vaultId)
          .first<{ owner_member_id: string; catalog_cid: string; version: number }>();
        if (
          (previous &&
            (previous.owner_member_id !== principal.memberId ||
              item.version !== previous.version + 1 ||
              item.previousCid !== previous.catalog_cid)) ||
          (!previous && (item.version !== 1 || item.previousCid !== null))
        ) {
          return context.json({ error: "catalog_rollback_or_fork" }, 409);
        }
        await context.env.DB.prepare(
          `INSERT INTO vault_catalog_pointers
           (vault_id, community_id, owner_member_id, catalog_cid, version,
            previous_cid, signed_at, owner_signature)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(vault_id) DO UPDATE SET
             catalog_cid = excluded.catalog_cid,
             version = excluded.version,
             previous_cid = excluded.previous_cid,
             signed_at = excluded.signed_at,
             owner_signature = excluded.owner_signature`
        )
          .bind(
            vaultId,
            principal.communityId,
            principal.memberId,
            item.catalogCid,
            item.version,
            item.previousCid,
            item.signedAt,
            item.ownerSignature
          )
          .run();
        await appendAuditEvent(context.env.DB, {
          communityId: principal.communityId,
          kind: "catalog_pointer_updated",
          actorId: principal.memberId,
          subjectId: vaultId,
          occurredAt: item.signedAt
        });
      }
      return context.json({ vaultId, ...item });
    }
  );
  app.get("/v1/vaults/:vaultId/catalog-pointer", async (context) => {
    const vaultId = context.req.param("vaultId");
    const principal = context.get("principal");
    if (!context.env?.DB) return context.json({ vaultId, catalogPointer: null });
    const row = await context.env.DB.prepare(
      `SELECT catalog_cid AS catalogCid, version, previous_cid AS previousCid,
              signed_at AS signedAt, owner_signature AS ownerSignature
       FROM vault_catalog_pointers
       WHERE vault_id = ? AND community_id = ? AND owner_member_id = ?`
    )
      .bind(vaultId, principal.communityId, principal.memberId)
      .first();
    return row
      ? context.json({ vaultId, catalogPointer: row })
      : context.json({ error: "not_found" }, 404);
  });

  app.post("/v1/objects", zValidator("json", objectRecord), async (context) => {
    const item = context.req.valid("json");
    const principal = context.get("principal");
    if (context.env?.DB) {
      try {
        await context.env.DB.prepare(
          `INSERT INTO objects
           (object_cid, community_id, ciphertext_size, object_kind,
            replica_target, created_at, retention_until)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            item.cid,
            principal.communityId,
            item.ciphertextSize,
            item.objectKind,
            item.replicaTarget,
            now(),
            now() + 30 * 86400
          )
          .run();
      } catch {
        return context.json({ error: "object_conflict" }, 409);
      }
    }
    return context.json(item, 201);
  });
  app.get("/v1/objects/:cid", async (context) => {
    const cidValue = context.req.param("cid");
    const principal = context.get("principal");
    if (!context.env?.DB) return context.json({ cid: cidValue });
    const row = await context.env.DB.prepare(
      `SELECT object_cid AS cid, ciphertext_size AS ciphertextSize,
              object_kind AS objectKind, replica_target AS replicaTarget,
              created_at AS createdAt, retention_until AS retentionUntil
       FROM objects WHERE object_cid = ? AND community_id = ?`
    )
      .bind(cidValue, principal.communityId)
      .first();
    return row ? context.json(row) : context.json({ error: "not_found" }, 404);
  });
  app.post(
    "/v1/objects/:cid/placements",
    zValidator("json", placement),
    async (context) => {
      const cidValue = context.req.param("cid");
      const item = context.req.valid("json");
      const principal = context.get("principal");
      if (context.env?.DB) {
        const nodeRow = await context.env.DB.prepare(
          "SELECT failure_domain FROM nodes WHERE node_id = ? AND community_id = ? AND status = 'active'"
        )
          .bind(item.nodeId, principal.communityId)
          .first<{ failure_domain: string }>();
        if (!nodeRow) return context.json({ error: "node_not_available" }, 409);
        try {
          await context.env.DB.prepare(
            `INSERT INTO placements
             (placement_id, object_cid, node_id, status, created_at)
             VALUES (?, ?, ?, 'healthy', ?)`
          )
            .bind(
              item.placementId,
              cidValue,
              item.nodeId,
              item.createdAt
            )
            .run();
        } catch {
          return context.json({ error: "placement_conflict" }, 409);
        }
      }
      return context.json({ ...item, cid: cidValue, status: "healthy" }, 201);
    }
  );
  app.get("/v1/objects/:cid/placements", async (context) => {
    const cidValue = context.req.param("cid");
    const principal = context.get("principal");
    if (!context.env?.DB) return context.json({ cid: cidValue, placements: [] });
    const rows = await context.env.DB.prepare(
      `SELECT p.placement_id AS placementId, p.node_id AS nodeId,
              n.failure_domain AS failureDomain, p.status, p.created_at AS createdAt
       FROM placements p JOIN objects o ON o.object_cid = p.object_cid
       JOIN nodes n ON n.node_id = p.node_id
       WHERE p.object_cid = ? AND o.community_id = ? ORDER BY p.created_at`
    )
      .bind(cidValue, principal.communityId)
      .all();
    return context.json({ cid: cidValue, placements: rows.results });
  });
  app.post("/v1/placements/:placementId/failed", async (context) => {
    const placementId = context.req.param("placementId");
    const principal = context.get("principal");
    if (context.env?.DB) {
      await context.env.DB.prepare(
        `UPDATE placements SET status = 'failed'
         WHERE placement_id = ? AND object_cid IN
           (SELECT object_cid FROM objects WHERE community_id = ?)`
      )
        .bind(placementId, principal.communityId)
        .run();
    }
    return context.json({ placementId, status: "failed" });
  });

  app.get("/v1/nodes/:nodeId/tasks", async (context) => {
    const nodeId = context.req.param("nodeId");
    const principal = context.get("principal");
    if (!context.env?.DB) return context.json({ nodeId, tasks: [] });
    const owned = await context.env.DB.prepare(
      "SELECT node_id FROM nodes WHERE node_id = ? AND owner_member_id = ? AND community_id = ?"
    )
      .bind(nodeId, principal.memberId, principal.communityId)
      .first();
    if (!owned) return context.json({ error: "node_owner_required" }, 403);
    const rows = await context.env.DB.prepare(
      `SELECT task_id AS taskId, task_kind AS taskKind, object_cid AS objectCid,
              payload_json AS payloadJson, status, created_at AS createdAt,
              expires_at AS expiresAt
       FROM node_tasks WHERE node_id = ? AND expires_at >= ? ORDER BY created_at`
    )
      .bind(nodeId, now())
      .all();
    return context.json({ nodeId, tasks: rows.results });
  });
  for (const action of ["accept", "complete", "fail"]) {
    app.post(`/v1/tasks/:taskId/${action}`, async (context) => {
      const taskId = context.req.param("taskId");
      const principal = context.get("principal");
      if (context.env?.DB) {
        const status = action === "accept" ? "accepted" : action === "complete" ? "completed" : "failed";
        const result = await context.env.DB.prepare(
          `UPDATE node_tasks SET status = ?
           WHERE task_id = ? AND node_id IN
             (SELECT node_id FROM nodes WHERE owner_member_id = ? AND community_id = ?)`
        )
          .bind(status, taskId, principal.memberId, principal.communityId)
          .run();
        if ((result.meta.changes ?? 0) !== 1) {
          return context.json({ error: "task_not_found_or_not_owned" }, 404);
        }
        return context.json({ taskId, status });
      }
      return context.json({ taskId, status: action });
    });
  }

  app.get("/v1/credits/me", async (context) => {
    const principal = context.get("principal");
    if (!context.env?.DB) {
      return context.json({ balanceMilliGibHour: 0, transferable: false });
    }
    const row = await context.env.DB.prepare(
      `SELECT COALESCE(SUM(milli_gib_hour), 0) AS balance
       FROM credit_entries
       WHERE member_id = ? AND (expires_at IS NULL OR expires_at >= ?)`
    )
      .bind(principal.memberId, now())
      .first<{ balance: number }>();
    return context.json({
      balanceMilliGibHour: Number(row?.balance ?? 0),
      transferable: false
    });
  });
  app.get("/v1/credits/me/entries", async (context) => {
    const principal = context.get("principal");
    if (!context.env?.DB) return context.json({ entries: [] });
    const rows = await context.env.DB.prepare(
      `SELECT entry_id AS entryId, milli_gib_hour AS milliGibHour, reason,
              occurred_at AS occurredAt, expires_at AS expiresAt
       FROM credit_entries WHERE member_id = ? ORDER BY occurred_at`
    )
      .bind(principal.memberId)
      .all();
    return context.json({ entries: rows.results });
  });
  app.get("/v1/communities/:communityId/credit-policy", async (context) => {
    const principal = context.get("principal");
    const communityId = context.req.param("communityId");
    if (principal.communityId !== communityId) {
      return context.json({ error: "wrong_community" }, 403);
    }
    const row = context.env?.DB
      ? await context.env.DB.prepare(
          `SELECT monthly_base_milli_gib_hour AS monthlyBaseMilliGibHour,
                  earned_expiry_days AS earnedExpiryDays,
                  upload_grace_days AS uploadGraceDays
           FROM credit_policies WHERE community_id = ?`
        )
          .bind(communityId)
          .first()
      : null;
    return context.json({
      communityId,
      unit: "milli_gib_hour",
      transferable: false,
      policy: row
    });
  });

  app.post(
    "/v1/communities/:communityId/proposals",
    zValidator("json", proposal),
    async (context) => {
      const item = context.req.valid("json");
      const principal = context.get("principal");
      const communityId = context.req.param("communityId");
      if (communityId !== principal.communityId || item.communityId !== communityId) {
        return context.json({ error: "wrong_community" }, 403);
      }
      if (item.opensAt >= item.closesAt) {
        return context.json({ error: "invalid_voting_window" }, 400);
      }
      if (context.env?.DB) {
        try {
          await context.env.DB.prepare(
            `INSERT INTO proposals
             (proposal_id, community_id, title, body, created_by_member_id,
              created_at, opens_at, closes_at, quorum_percent, threshold_percent, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`
          )
            .bind(
              item.proposalId,
              communityId,
              item.title,
              item.body,
              principal.memberId,
              now(),
              item.opensAt,
              item.closesAt,
              item.quorumPercent,
              item.thresholdPercent
            )
            .run();
        } catch {
          return context.json({ error: "proposal_conflict" }, 409);
        }
      } else {
        memoryRepository.proposals.add(item.proposalId);
      }
      return context.json(item, 201);
    }
  );
  app.get("/v1/communities/:communityId/proposals", async (context) => {
    const communityId = context.req.param("communityId");
    if (context.get("principal").communityId !== communityId) {
      return context.json({ error: "wrong_community" }, 403);
    }
    if (!context.env?.DB) return context.json({ communityId, proposals: [] });
    const rows = await context.env.DB.prepare(
      `SELECT proposal_id AS proposalId, title, body, opens_at AS opensAt,
              closes_at AS closesAt, quorum_percent AS quorumPercent,
              threshold_percent AS thresholdPercent, status
       FROM proposals WHERE community_id = ? ORDER BY created_at`
    )
      .bind(communityId)
      .all();
    return context.json({ communityId, proposals: rows.results });
  });
  app.get("/v1/proposals/:proposalId", async (context) => {
    const proposalId = context.req.param("proposalId");
    const principal = context.get("principal");
    if (!context.env?.DB) return context.json({ proposalId });
    const row = await context.env.DB.prepare(
      `SELECT proposal_id AS proposalId, title, body, opens_at AS opensAt,
              closes_at AS closesAt, quorum_percent AS quorumPercent,
              threshold_percent AS thresholdPercent, status
       FROM proposals WHERE proposal_id = ? AND community_id = ?`
    )
      .bind(proposalId, principal.communityId)
      .first();
    return row ? context.json(row) : context.json({ error: "not_found" }, 404);
  });
  app.put("/v1/proposals/:proposalId/vote", zValidator("json", vote), async (context) => {
    const proposalId = context.req.param("proposalId");
    const item = context.req.valid("json");
    const principal = context.get("principal");
    if (item.memberId !== principal.memberId) {
      return context.json({ error: "member_mismatch" }, 403);
    }
    const message = [
      "acm.vote.v1",
      proposalId,
      item.memberId,
      item.choice.charAt(0).toUpperCase() + item.choice.slice(1),
      item.castAt
    ].join("|");
    if (!(await verifySignature(principal.publicKey, item.memberSignature, message))) {
      return context.json({ error: "invalid_vote_signature" }, 401);
    }
    if (context.env?.DB) {
      const active = await context.env.DB.prepare(
        `SELECT proposal_id FROM proposals
         WHERE proposal_id = ? AND community_id = ? AND opens_at <= ? AND closes_at >= ?`
      )
        .bind(proposalId, principal.communityId, item.castAt, item.castAt)
        .first();
      if (!active) return context.json({ error: "proposal_not_found_or_closed" }, 404);
      await context.env.DB.prepare(
        `INSERT INTO votes (proposal_id, member_id, choice, cast_at, member_signature)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(proposal_id, member_id) DO UPDATE SET
           choice = excluded.choice, cast_at = excluded.cast_at,
           member_signature = excluded.member_signature`
      )
        .bind(proposalId, item.memberId, item.choice, item.castAt, item.memberSignature)
        .run();
      await appendAuditEvent(context.env.DB, {
        communityId: principal.communityId,
        kind: "vote_cast",
        actorId: principal.memberId,
        subjectId: proposalId,
        occurredAt: item.castAt
      });
    } else {
      if (!memoryRepository.proposals.has(proposalId)) {
        return context.json({ error: "proposal_not_found" }, 404);
      }
      memoryRepository.recordVote(proposalId, item);
    }
    return context.json({ proposalId, status: "recorded" });
  });
  app.get("/v1/proposals/:proposalId/result", async (context) => {
    const proposalId = context.req.param("proposalId");
    if (context.env?.DB) {
      const principal = context.get("principal");
      const rows = await context.env.DB.prepare(
        `SELECT v.choice, COUNT(*) AS count
         FROM votes v JOIN proposals p ON p.proposal_id = v.proposal_id
         WHERE v.proposal_id = ? AND p.community_id = ? GROUP BY v.choice`
      )
        .bind(proposalId, principal.communityId)
        .all<{ choice: "yes" | "no" | "abstain"; count: number }>();
      const result = { yes: 0, no: 0, abstain: 0 };
      for (const row of rows.results) result[row.choice] = Number(row.count);
      return context.json(result);
    }
    const votes = memoryRepository.votes.get(proposalId)?.values() ?? [];
    const result = { yes: 0, no: 0, abstain: 0 };
    for (const item of votes) result[item.choice] += 1;
    return context.json(result);
  });

  app.get("/v1/communities/:communityId/audit-events", async (context) => {
    const communityId = context.req.param("communityId");
    if (context.get("principal").communityId !== communityId) {
      return context.json({ error: "wrong_community" }, 403);
    }
    if (!context.env?.DB) return context.json({ communityId, events: [] });
    const rows = await context.env.DB.prepare(
      `SELECT sequence, event_kind AS eventKind, actor_id AS actorId,
              subject_id AS subjectId, occurred_at AS occurredAt,
              previous_event_hash AS previousEventHash, event_hash AS eventHash
       FROM audit_events WHERE community_id = ? ORDER BY sequence`
    )
      .bind(communityId)
      .all();
    return context.json({ communityId, events: rows.results });
  });
  app.get("/v1/communities/:communityId/audit-anchors", async (context) => {
    const communityId = context.req.param("communityId");
    if (context.get("principal").communityId !== communityId) {
      return context.json({ error: "wrong_community" }, 403);
    }
    if (!context.env?.DB) return context.json({ communityId, anchors: [] });
    const rows = await context.env.DB.prepare(
      `SELECT anchor_id AS anchorId, period, merkle_root AS merkleRoot,
              adapter_kind AS adapterKind, anchored_at AS anchoredAt
       FROM audit_anchors WHERE community_id = ? ORDER BY anchored_at`
    )
      .bind(communityId)
      .all();
    return context.json({ communityId, anchors: rows.results });
  });
  app.post("/v1/internal/audit-anchors/run", async (context) => {
    const expectedInternalSecret = internalSecret ?? context.env?.INTERNAL_SECRET;
    if (
      !expectedInternalSecret ||
      context.req.header("x-acm-internal-secret") !== expectedInternalSecret
    ) {
      return context.json({ error: "not_found" }, 404);
    }
    if (context.env?.DB) await runMaintenance(context.env.DB, now());
    return context.json({ status: "scheduled" }, 202);
  });

  app.notFound((context) => context.json({ error: "not_found" }, 404));
  return { app, repository: memoryRepository };
}
