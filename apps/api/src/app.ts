import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { catalogPointer, challengeSession, community, node, objectRecord, proposal, vote } from "./schemas";
import { asArrayBuffer, fromBase64Url, MemoryRepository } from "./repository";

export type AppOptions = {
  repository?: MemoryRepository;
  now?: () => number;
  internalSecret?: string;
};

export function createApp(options: AppOptions = {}) {
  const repository = options.repository ?? new MemoryRepository();
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const internalSecret = options.internalSecret;
  const app = new Hono();

  app.get("/health", (context) => context.json({ status: "ok" }));

  app.post("/v1/auth/challenges", (context) => {
    const challenge = repository.createChallenge(now());
    return context.json(
      {
        challengeId: challenge.id,
        challenge: challenge.value,
        expiresAt: challenge.expiresAt
      },
      201
    );
  });

  app.post("/v1/auth/sessions", zValidator("json", challengeSession), async (context) => {
    const body = context.req.valid("json");
    const challenge = repository.consumeChallenge(body.challengeId, body.replayNonce, now());
    if (!challenge) {
      return context.json({ error: "expired_or_replayed_challenge" }, 401);
    }
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        asArrayBuffer(fromBase64Url(body.publicKey)),
        { name: "Ed25519" },
        false,
        ["verify"]
      );
      const valid = await crypto.subtle.verify(
        "Ed25519",
        key,
        asArrayBuffer(fromBase64Url(body.signature)),
        asArrayBuffer(
          new TextEncoder().encode(
            `acm.auth.v1|${challenge.id}|${challenge.value}|${body.replayNonce}`
          )
        )
      );
      if (!valid) {
        return context.json({ error: "invalid_signature" }, 401);
      }
    } catch {
      return context.json({ error: "invalid_signature" }, 401);
    }
    return context.json({
      sessionToken: crypto.randomUUID(),
      expiresAt: now() + 900,
      memberId: body.memberId
    });
  });

  app.delete("/v1/auth/sessions/current", (context) =>
    context.json({ status: "revoked" })
  );

  app.post("/v1/communities", zValidator("json", community), (context) =>
    context.json(context.req.valid("json"), 201)
  );
  app.get("/v1/communities/:communityId", (context) =>
    context.json({ communityId: context.req.param("communityId"), status: "active" })
  );
  app.post("/v1/communities/:communityId/invites", (context) =>
    context.json({ inviteId: crypto.randomUUID(), expiresInSeconds: 86400 }, 201)
  );
  app.post("/v1/communities/:communityId/join-requests", (context) =>
    context.json({ requestId: crypto.randomUUID(), status: "pending" }, 201)
  );
  app.get("/v1/communities/:communityId/join-requests", (context) =>
    context.json({ communityId: context.req.param("communityId"), requests: [] })
  );
  app.post("/v1/communities/:communityId/join-requests/:requestId/approve", (context) =>
    context.json({ requestId: context.req.param("requestId"), status: "approved" })
  );
  app.get("/v1/communities/:communityId/members", (context) =>
    context.json({ communityId: context.req.param("communityId"), members: [] })
  );
  app.post("/v1/communities/:communityId/members/:memberId/revoke", (context) =>
    context.json({ memberId: context.req.param("memberId"), status: "revoked" })
  );

  app.post("/v1/nodes", zValidator("json", node), (context) =>
    context.json(context.req.valid("json"), 201)
  );
  app.post("/v1/nodes/:nodeId/heartbeat", (context) =>
    context.json({ nodeId: context.req.param("nodeId"), status: "online" })
  );
  app.get("/v1/nodes/candidates", (context) => context.json({ nodes: [] }));
  app.get("/v1/nodes/:nodeId", (context) =>
    context.json({ nodeId: context.req.param("nodeId"), status: "online" })
  );
  app.post("/v1/nodes/:nodeId/disable", (context) =>
    context.json({ nodeId: context.req.param("nodeId"), status: "disabled" })
  );

  app.put(
    "/v1/vaults/:vaultId/catalog-pointer",
    zValidator("json", catalogPointer),
    (context) => context.json({ vaultId: context.req.param("vaultId"), ...context.req.valid("json") })
  );
  app.get("/v1/vaults/:vaultId/catalog-pointer", (context) =>
    context.json({ vaultId: context.req.param("vaultId"), catalogPointer: null })
  );

  app.post("/v1/objects", zValidator("json", objectRecord), (context) =>
    context.json(context.req.valid("json"), 201)
  );
  app.get("/v1/objects/:cid", (context) =>
    context.json({ cid: context.req.param("cid") })
  );
  app.post("/v1/objects/:cid/placements", (context) =>
    context.json({ placementId: crypto.randomUUID(), cid: context.req.param("cid") }, 201)
  );
  app.get("/v1/objects/:cid/placements", (context) =>
    context.json({ cid: context.req.param("cid"), placements: [] })
  );
  app.post("/v1/placements/:placementId/failed", (context) =>
    context.json({ placementId: context.req.param("placementId"), status: "failed" })
  );

  app.get("/v1/nodes/:nodeId/tasks", (context) =>
    context.json({ nodeId: context.req.param("nodeId"), tasks: [] })
  );
  for (const action of ["accept", "complete", "fail"]) {
    app.post(`/v1/tasks/:taskId/${action}`, (context) =>
      context.json({ taskId: context.req.param("taskId"), status: action })
    );
  }

  app.get("/v1/credits/me", (context) =>
    context.json({ balanceMilliGibHour: 0, transferable: false })
  );
  app.get("/v1/credits/me/entries", (context) => context.json({ entries: [] }));
  app.get("/v1/communities/:communityId/credit-policy", (context) =>
    context.json({
      communityId: context.req.param("communityId"),
      unit: "milli_gib_hour",
      transferable: false
    })
  );

  app.post(
    "/v1/communities/:communityId/proposals",
    zValidator("json", proposal),
    (context) => {
      const item = context.req.valid("json");
      repository.proposals.add(item.proposalId);
      return context.json(item, 201);
    }
  );
  app.get("/v1/communities/:communityId/proposals", (context) =>
    context.json({ communityId: context.req.param("communityId"), proposals: [] })
  );
  app.get("/v1/proposals/:proposalId", (context) =>
    context.json({ proposalId: context.req.param("proposalId") })
  );
  app.put("/v1/proposals/:proposalId/vote", zValidator("json", vote), (context) => {
    const proposalId = context.req.param("proposalId");
    if (!repository.proposals.has(proposalId)) {
      return context.json({ error: "proposal_not_found" }, 404);
    }
    repository.recordVote(proposalId, context.req.valid("json"));
    return context.json({ proposalId, status: "recorded" });
  });
  app.get("/v1/proposals/:proposalId/result", (context) => {
    const votes = repository.votes.get(context.req.param("proposalId"))?.values() ?? [];
    const result = { yes: 0, no: 0, abstain: 0 };
    for (const item of votes) result[item.choice] += 1;
    return context.json(result);
  });

  app.get("/v1/communities/:communityId/audit-events", (context) =>
    context.json({ communityId: context.req.param("communityId"), events: [] })
  );
  app.get("/v1/communities/:communityId/audit-anchors", (context) =>
    context.json({ communityId: context.req.param("communityId"), anchors: [] })
  );
  app.post("/v1/internal/audit-anchors/run", (context) => {
    if (!internalSecret || context.req.header("x-acm-internal-secret") !== internalSecret) {
      return context.json({ error: "not_found" }, 404);
    }
    return context.json({ status: "scheduled" }, 202);
  });

  app.notFound((context) => context.json({ error: "not_found" }, 404));
  return { app, repository };
}
