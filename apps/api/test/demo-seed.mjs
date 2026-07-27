import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

const baseUrl = "http://127.0.0.1:8787";
const createdAt = Math.floor(Date.now() / 1000);
const communityId = `local-demo-${Date.now()}`;

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function rawPublicKey(key) {
  const der = key.export({ type: "spki", format: "der" });
  return base64Url(der.subarray(der.length - 32));
}

function deterministicKeyPair(seedByte) {
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.alloc(32, seedByte)]),
    format: "der",
    type: "pkcs8"
  });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

function concat(parts) {
  return Buffer.concat(parts.map((part) => Buffer.from(part)));
}

function field(value) {
  const bytes = typeof value === "string" ? Buffer.from(value) : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return concat([length, bytes]);
}

function unsigned(value, size) {
  const bytes = Buffer.alloc(size);
  if (size === 2) bytes.writeUInt16BE(value);
  else if (size === 4) bytes.writeUInt32BE(value);
  else bytes.writeBigInt64BE(BigInt(value));
  return bytes;
}

function membershipBytes(input) {
  const roles = [...input.roles].sort();
  return concat([
    field("acm.membership.v1"),
    unsigned(1, 2),
    field(input.communityId),
    field(Buffer.from(input.memberPublicKey, "base64url")),
    field(input.memberId),
    unsigned(roles.length, 4),
    ...roles.map(field),
    unsigned(input.issuedAt, 8),
    unsigned(input.expiresAt, 8),
    unsigned(input.serial, 8),
    field(Buffer.from(input.issuerPublicKey, "base64url"))
  ]);
}

function nodeCertificateBytes(input) {
  return concat([
    field("acm.node-certificate.v1"),
    unsigned(1, 2),
    field(input.nodeId),
    field(input.communityId),
    field(input.ownerMemberId),
    field(input.endpointPublicKey),
    unsigned(1, 4),
    field("node"),
    unsigned(input.maxStorageBytes, 8),
    unsigned(input.issuedAt, 8),
    unsigned(input.expiresAt, 8)
  ]);
}

async function request(path, init = {}) {
  const response = await fetch(`${baseUrl}${path}`, init);
  const body = await response.json();
  if (!response.ok) {
    throw new Error(`${path} failed (${response.status}): ${JSON.stringify(body)}`);
  }
  return body;
}

const root = deterministicKeyPair(1);
const alice = deterministicKeyPair(11);
const bob = deterministicKeyPair(12);
const rootPublicKey = rawPublicKey(root.publicKey);
const alicePublicKey = rawPublicKey(alice.publicKey);
const bobPublicKey = rawPublicKey(bob.publicKey);
const aliceMemberId = `mem_${bytesToHex(
  blake3(Buffer.from(alicePublicKey, "base64url"))
)}`;
const bobMemberId = `mem_${bytesToHex(
  blake3(Buffer.from(bobPublicKey, "base64url"))
)}`;
const founderRoles = ["admin", "auditor", "member", "node"];
const founderCredentialSerial = Date.now();
const founderCredentialExpiresAt = createdAt + 86400;
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
    founderCredentialSerial,
    founderCredentialExpiresAt,
    founderCredentialSignature: base64Url(
      sign(
        null,
        membershipBytes({
          communityId,
          memberPublicKey: alicePublicKey,
          memberId: aliceMemberId,
          roles: founderRoles,
          issuedAt: createdAt,
          expiresAt: founderCredentialExpiresAt,
          serial: founderCredentialSerial,
          issuerPublicKey: rootPublicKey
        }),
        root.privateKey
      )
    ),
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
const serial = Date.now() + 1;
const membershipMessage = membershipBytes({
  communityId,
  memberId: bobMemberId,
  memberPublicKey: bobPublicKey,
  roles: bobRoles,
  serial,
  issuedAt: createdAt,
  expiresAt: createdAt + 86400,
  issuerPublicKey: rootPublicKey
});
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
        sign(null, membershipMessage, root.privateKey)
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
  const endpointDocument = JSON.parse(
    await readFile(`.demo/nodes/${nodeId}/network-endpoint.json`, "utf8")
  );
  const endpointPublicKey = endpointDocument.endpoint_addr.id;
  const certificateMessage = nodeCertificateBytes({
    nodeId,
    communityId,
    ownerMemberId: aliceMemberId,
    endpointPublicKey,
    maxStorageBytes: 67_108_864,
    issuedAt: createdAt,
    expiresAt: createdAt + 86400
  });
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
        sign(null, certificateMessage, alice.privateKey)
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
      transport: "iroh-quic-loopback-authenticated",
      privateKeysPersisted: false
    },
    null,
    2
  )}\n`
);

console.log(`seeded community=${communityId} members=2 nodes=4`);
