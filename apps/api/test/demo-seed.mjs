import { generateKeyPairSync, sign } from "node:crypto";
import { writeFile } from "node:fs/promises";

const baseUrl = "http://127.0.0.1:8787";
const createdAt = Math.floor(Date.now() / 1000);
const communityId = `local-demo-${Date.now()}`;
const aliceMemberId = `alice-${Date.now()}`;
const bobMemberId = `bob-${Date.now()}`;

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function rawPublicKey(key) {
  const der = key.export({ type: "spki", format: "der" });
  return base64Url(der.subarray(der.length - 32));
}

async function request(path, init = {}) {
  const response = await fetch(`${baseUrl}${path}`, init);
  const body = await response.json();
  if (!response.ok) {
    throw new Error(`${path} failed (${response.status}): ${JSON.stringify(body)}`);
  }
  return body;
}

const root = generateKeyPairSync("ed25519");
const alice = generateKeyPairSync("ed25519");
const bob = generateKeyPairSync("ed25519");
const rootPublicKey = rawPublicKey(root.publicKey);
const alicePublicKey = rawPublicKey(alice.publicKey);
const bobPublicKey = rawPublicKey(bob.publicKey);
const founderRoles = ["admin", "member"];
const bootstrapMessage = [
  "acm.community-bootstrap.v1",
  communityId,
  "Arcane Commons Local Demo",
  rootPublicKey,
  createdAt,
  1,
  aliceMemberId,
  alicePublicKey,
  founderRoles.join(",")
].join("|");

await request("/v1/communities", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    communityId,
    name: "Arcane Commons Local Demo",
    rootPublicKey,
    createdAt,
    policyVersion: 1,
    founderMemberId: aliceMemberId,
    founderPublicKey: alicePublicKey,
    founderRoles,
    rootSignature: base64Url(sign(null, Buffer.from(bootstrapMessage), root.privateKey))
  })
});

const challenge = await request("/v1/auth/challenges", { method: "POST" });
const replayNonce = `nonce-${crypto.randomUUID()}`;
const authMessage = [
  "acm.auth.v1",
  challenge.challengeId,
  challenge.challenge,
  replayNonce,
  aliceMemberId,
  alicePublicKey
].join("|");
const session = await request("/v1/auth/sessions", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    challengeId: challenge.challengeId,
    challenge: challenge.challenge,
    memberId: aliceMemberId,
    publicKey: alicePublicKey,
    signature: base64Url(sign(null, Buffer.from(authMessage), alice.privateKey)),
    replayNonce
  })
});
const authorization = `Bearer ${session.sessionToken}`;

const invite = await request(`/v1/communities/${communityId}/invites`, {
  method: "POST",
  headers: { authorization }
});
const join = await request(`/v1/communities/${communityId}/join-requests`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ inviteCode: invite.inviteCode, memberPublicKey: bobPublicKey })
});
const bobRoles = ["member"];
const serial = `demo-${crypto.randomUUID()}`;
const membershipMessage = [
  "acm.membership.v1",
  communityId,
  bobMemberId,
  bobPublicKey,
  bobRoles.join(","),
  serial,
  createdAt,
  createdAt + 86400
].join("|");
await request(
  `/v1/communities/${communityId}/join-requests/${join.requestId}/approve`,
  {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body: JSON.stringify({
      memberId: bobMemberId,
      memberPublicKey: bobPublicKey,
      roles: bobRoles,
      serial,
      issuedAt: createdAt,
      expiresAt: createdAt + 86400,
      rootSignature: base64Url(
        sign(null, Buffer.from(membershipMessage), root.privateKey)
      )
    })
  }
);

for (const [index, nodeId] of [
  "storage-a",
  "storage-b",
  "storage-c",
  "auditor"
].entries()) {
  const endpoint = generateKeyPairSync("ed25519");
  const endpointPublicKey = rawPublicKey(endpoint.publicKey);
  const certificateMessage = [
    "acm.node-certificate.v1",
    nodeId,
    communityId,
    aliceMemberId,
    endpointPublicKey,
    "node",
    67_108_864,
    createdAt,
    createdAt + 86400
  ].join("|");
  await request("/v1/nodes", {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body: JSON.stringify({
      nodeId,
      communityId,
      ownerMemberId: aliceMemberId,
      endpointPublicKey,
      failureDomain: `local-domain-${index}`,
      region: "local-demo",
      maxStorageBytes: 67_108_864,
      certificateSignature: base64Url(
        sign(null, Buffer.from(certificateMessage), alice.privateKey)
      ),
      issuedAt: createdAt,
      expiresAt: createdAt + 86400
    })
  });
}

await writeFile(
  ".demo/bootstrap.json",
  `${JSON.stringify(
    {
      communityId,
      members: ["Alice", "Bob"],
      nodes: ["storage-a", "storage-b", "storage-c", "auditor"],
      privateKeysPersisted: false
    },
    null,
    2
  )}\n`
);

console.log(`seeded community=${communityId} members=2 nodes=4`);
