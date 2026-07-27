import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app";
import { auditMerkleRoot } from "../src/maintenance";
import { community, node } from "../src/schemas";
import {
  fromBase64Url,
  hashOpaque,
  MemoryRepository,
  toBase64Url
} from "../src/repository";

function rawPublicKey(key: KeyObject): Uint8Array {
  const der = key.export({ type: "spki", format: "der" });
  return new Uint8Array(der.subarray(der.length - 32));
}

async function login(
  app: ReturnType<typeof createApp>["app"],
  repository: MemoryRepository,
  now = 100
): Promise<{ token: string; privateKey: KeyObject }> {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const encodedPublicKey = toBase64Url(rawPublicKey(publicKey));
  repository.addMember({
    memberId: "member-a",
    communityId: "community-a",
    publicKey: encodedPublicKey,
    roles: ["member", "admin"]
  });
  const challengeResponse = await app.request("/v1/auth/challenges", { method: "POST" });
  const challenge = await challengeResponse.json<{ challengeId: string; challenge: string }>();
  const replayNonce = `nonce-${now.toString().padStart(12, "0")}`;
  const message = `acm.auth.v1|${challenge.challengeId}|${challenge.challenge}|${replayNonce}|member-a|${encodedPublicKey}`;
  const response = await app.request("/v1/auth/sessions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challengeId: challenge.challengeId,
      challenge: challenge.challenge,
      memberId: "member-a",
      publicKey: encodedPublicKey,
      signature: toBase64Url(sign(null, Buffer.from(message), privateKey)),
      replayNonce
    })
  });
  expect(response.status).toBe(200);
  return {
    token: (await response.json<{ sessionToken: string }>()).sessionToken,
    privateKey
  };
}

describe("control plane API", () => {
  it("accepts iroh endpoint IDs and the node membership role", () => {
    expect(
      node.parse({
        nodeId: "node-a",
        communityId: "community-a",
        ownerMemberId: "member-a",
        endpointPublicKey: "a".repeat(64),
        failureDomain: "mac-local-a",
        region: "loopback",
        maxStorageBytes: 1024,
        certificateSignature: "a".repeat(86),
        issuedAt: 100,
        expiresAt: 200
      }).endpointPublicKey
    ).toHaveLength(64);
    expect(
      community.parse({
        communityId: "community-a",
        name: "Local mesh",
        rootPublicKey: "a".repeat(43),
        createdAt: 100,
        policyVersion: 1,
        founderMemberId: "member-a",
        founderPublicKey: "b".repeat(43),
        founderRoles: ["member", "admin", "node"],
        founderCredentialSerial: 1,
        founderCredentialExpiresAt: 200,
        founderCredentialSignature: "a".repeat(86),
        rootSignature: "b".repeat(86)
      }).founderRoles
    ).toContain("node");
  });

  it("builds deterministic BLAKE3 Merkle roots including the empty day", () => {
    expect(auditMerkleRoot([])).toHaveLength(64);
    expect(auditMerkleRoot(["a".repeat(64), "b".repeat(64), "c".repeat(64)])).toBe(
      auditMerkleRoot(["a".repeat(64), "b".repeat(64), "c".repeat(64)])
    );
    expect(auditMerkleRoot(["b".repeat(64), "a".repeat(64)])).not.toBe(
      auditMerkleRoot(["a".repeat(64), "b".repeat(64)])
    );
  });

  it("accepts a signed one-use challenge then rejects replay", async () => {
    let now = 100;
    const repository = new MemoryRepository();
    const { app } = createApp({ repository, now: () => now });
    const challengeResponse = await app.request("/v1/auth/challenges", { method: "POST" });
    const challenge = await challengeResponse.json<{
      challengeId: string;
      challenge: string;
    }>();
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const encodedPublicKey = toBase64Url(rawPublicKey(publicKey));
    repository.addMember({
      memberId: "member-a",
      communityId: "community-a",
      publicKey: encodedPublicKey,
      roles: ["member"]
    });
    const replayNonce = "nonce-0000000001";
    const message = `acm.auth.v1|${challenge.challengeId}|${challenge.challenge}|${replayNonce}|member-a|${encodedPublicKey}`;
    const signature = sign(null, Buffer.from(message), privateKey);
    const body = JSON.stringify({
      challengeId: challenge.challengeId,
      challenge: challenge.challenge,
      memberId: "member-a",
      publicKey: encodedPublicKey,
      signature: toBase64Url(signature),
      replayNonce
    });
    const first = await app.request("/v1/auth/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body
    });
    expect(first.status).toBe(200);
    const replay = await app.request("/v1/auth/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body
    });
    expect(replay.status).toBe(401);
    now += 1000;
    expect(fromBase64Url(challenge.challenge)).toHaveLength(32);
  });

  it("rejects expired challenges", async () => {
    let now = 100;
    const repository = new MemoryRepository();
    const challenge = await repository.createChallenge(await hashOpaque("challenge"), now);
    now = 401;
    expect(
      await repository.consumeChallengeAndCreateSession({
        challengeId: challenge.id,
        replayNonceHash: await hashOpaque("nonce-0000000001"),
        memberId: "member-a",
        publicKey: "x",
        tokenHash: await hashOpaque("token"),
        now
      })
    ).toBeUndefined();
  });

  it("requires a session and prevents cross-community reads", async () => {
    const repository = new MemoryRepository();
    const { app } = createApp({ repository, now: () => 100 });
    expect((await app.request("/v1/communities/community-a")).status).toBe(401);
    const { token } = await login(app, repository);
    expect(
      (
        await app.request("/v1/communities/community-b", {
          headers: { authorization: `Bearer ${token}` }
        })
      ).status
    ).toBe(403);
  });

  it("does not consume a challenge when its signature is invalid", async () => {
    const repository = new MemoryRepository();
    const { app } = createApp({ repository, now: () => 100 });
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const encodedPublicKey = toBase64Url(rawPublicKey(publicKey));
    repository.addMember({
      memberId: "member-a",
      communityId: "community-a",
      publicKey: encodedPublicKey,
      roles: ["member"]
    });
    const challengeResponse = await app.request("/v1/auth/challenges", { method: "POST" });
    const challenge = await challengeResponse.json<{
      challengeId: string;
      challenge: string;
    }>();
    const replayNonce = "nonce-0000000002";
    const request = {
      challengeId: challenge.challengeId,
      challenge: challenge.challenge,
      memberId: "member-a",
      publicKey: encodedPublicKey,
      replayNonce
    };
    const invalid = await app.request("/v1/auth/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...request, signature: toBase64Url(new Uint8Array(64)) })
    });
    expect(invalid.status).toBe(401);

    const message = `acm.auth.v1|${challenge.challengeId}|${challenge.challenge}|${replayNonce}|member-a|${encodedPublicKey}`;
    const valid = await app.request("/v1/auth/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ...request,
        signature: toBase64Url(sign(null, Buffer.from(message), privateKey))
      })
    });
    expect(valid.status).toBe(200);
  });

  it("rejects a second vote from the same member", async () => {
    const repository = new MemoryRepository();
    const { app } = createApp({ repository, now: () => 100 });
    const { token, privateKey } = await login(app, repository);
    repository.proposals.add("proposal-a");
    for (const [index, choice] of (["yes", "no"] as const).entries()) {
      const castAt = 100;
      const canonicalChoice = choice.charAt(0).toUpperCase() + choice.slice(1);
      const voteMessage = `acm.vote.v1|proposal-a|member-a|${canonicalChoice}|${castAt}`;
      const response = await app.request("/v1/proposals/proposal-a/vote", {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          memberId: "member-a",
          choice,
          castAt,
          memberSignature: toBase64Url(sign(null, Buffer.from(voteMessage), privateKey))
        })
      });
      expect(response.status).toBe(index === 0 ? 200 : 409);
    }
    const result = await app.request("/v1/proposals/proposal-a/result", {
      headers: { authorization: `Bearer ${token}` }
    });
    expect(await result.json()).toEqual({ yes: 1, no: 0, abstain: 0 });
    expect(repository.voteHistory).toHaveLength(1);
  });

  it("rejects a vote with a forged member signature", async () => {
    const repository = new MemoryRepository();
    const { app } = createApp({ repository, now: () => 100 });
    const { token } = await login(app, repository);
    repository.proposals.add("proposal-a");
    const response = await app.request("/v1/proposals/proposal-a/vote", {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        memberId: "member-a",
        choice: "yes",
        castAt: 100,
        memberSignature: toBase64Url(new Uint8Array(64))
      })
    });
    expect(response.status).toBe(401);
    expect(repository.voteHistory).toHaveLength(0);
  });

  it("has no credit transfer, purchase, sale, exchange, or token routes", async () => {
    const repository = new MemoryRepository();
    const { app } = createApp({ repository });
    const { token } = await login(app, repository, 101);
    for (const path of [
      "/v1/credits/transfer",
      "/v1/credits/buy",
      "/v1/credits/sell",
      "/v1/credits/exchange",
      "/v1/tokens",
      "/v1/wallet"
    ]) {
      const response = await app.request(path, {
        method: "POST",
        headers: { authorization: `Bearer ${token}` }
      });
      expect(response.status, path).toBe(404);
    }
  });

  it("hides the internal anchor endpoint without an exact local secret", async () => {
    const { app } = createApp({ internalSecret: "local-test-secret" });
    expect(
      (await app.request("/v1/internal/audit-anchors/run", { method: "POST" })).status
    ).toBe(404);
    expect(
      (
        await app.request("/v1/internal/audit-anchors/run", {
          method: "POST",
          headers: { "x-acm-internal-secret": "local-test-secret" }
        })
      ).status
    ).toBe(202);
  });
});
