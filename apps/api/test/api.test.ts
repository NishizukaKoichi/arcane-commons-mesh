import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app";
import { fromBase64Url, MemoryRepository, toBase64Url } from "../src/repository";

function rawPublicKey(key: KeyObject): Uint8Array {
  const der = key.export({ type: "spki", format: "der" });
  return new Uint8Array(der.subarray(der.length - 32));
}

describe("control plane API", () => {
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
    const replayNonce = "nonce-0000000001";
    const message = `acm.auth.v1|${challenge.challengeId}|${challenge.challenge}|${replayNonce}`;
    const signature = sign(null, Buffer.from(message), privateKey);
    const body = JSON.stringify({
      challengeId: challenge.challengeId,
      memberId: "member-a",
      publicKey: toBase64Url(rawPublicKey(publicKey)),
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
    const challenge = repository.createChallenge(now);
    now = 401;
    expect(repository.consumeChallenge(challenge.id, "nonce-0000000001", now)).toBeUndefined();
  });

  it("counts only the latest vote for one member and keeps both history events", async () => {
    const repository = new MemoryRepository();
    const { app } = createApp({ repository, now: () => 100 });
    repository.proposals.add("proposal-a");
    for (const choice of ["yes", "no"] as const) {
      const response = await app.request("/v1/proposals/proposal-a/vote", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          memberId: "member-a",
          choice,
          castAt: 100,
          memberSignature: "s".repeat(80)
        })
      });
      expect(response.status).toBe(200);
    }
    const result = await app.request("/v1/proposals/proposal-a/result");
    expect(await result.json()).toEqual({ yes: 0, no: 1, abstain: 0 });
    expect(repository.voteHistory).toHaveLength(2);
  });

  it("has no credit transfer, purchase, sale, exchange, or token routes", async () => {
    const { app } = createApp();
    for (const path of [
      "/v1/credits/transfer",
      "/v1/credits/buy",
      "/v1/credits/sell",
      "/v1/credits/exchange",
      "/v1/tokens",
      "/v1/wallet"
    ]) {
      const response = await app.request(path, { method: "POST" });
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
