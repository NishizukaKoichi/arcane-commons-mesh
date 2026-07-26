import { generateKeyPairSync, sign } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

const port = 8791;
const baseUrl = `http://127.0.0.1:${port}`;
const forbiddenPlaintext = [
  Buffer.from("ACM_D1_FORBIDDEN_FILENAME_20260726.txt"),
  Buffer.from("ACM_D1_FORBIDDEN_CONTENT_20260726"),
  Buffer.from("ACM_D1_FORBIDDEN_FILE_KEY_20260726")
];

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function rawPublicKey(key) {
  const der = key.export({ type: "spki", format: "der" });
  return base64Url(der.subarray(der.length - 32));
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
  const sortedRoles = [...input.roles].sort();
  return concat([
    field("acm.membership.v1"),
    unsigned(1, 2),
    field(input.communityId),
    field(Buffer.from(input.memberPublicKey, "base64url")),
    field(input.memberId),
    unsigned(sortedRoles.length, 4),
    ...sortedRoles.map(field),
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

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8", stdio: "pipe" });
  if (result.status !== 0) {
    throw new Error(`${command} failed:\n${result.stdout}\n${result.stderr}`);
  }
}

async function waitForHealth() {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return;
    } catch {
      // Worker startup is expected to refuse connections briefly.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("local Worker did not become healthy");
}

async function startWorker() {
  const child = spawn(
    "pnpm",
    [
      "exec",
      "wrangler",
      "dev",
      "--local",
      "--ip",
      "127.0.0.1",
      "--port",
      String(port),
      "--var",
      "INTERNAL_SECRET:d1-test-secret"
    ],
    { stdio: ["ignore", "pipe", "pipe"] }
  );
  let diagnostic = "";
  child.stdout.on("data", (chunk) => {
    diagnostic += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    diagnostic += chunk.toString();
  });
  try {
    await waitForHealth();
    return { child, diagnostic: () => diagnostic };
  } catch (error) {
    child.kill("SIGTERM");
    throw new Error(`${error.message}\n${diagnostic}`);
  }
}

async function stopWorker(child) {
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 3000))
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

async function request(path, init = {}) {
  const response = await fetch(`${baseUrl}${path}`, init);
  const body = await response.json();
  return { response, body };
}

run("pnpm", [
  "exec",
  "wrangler",
  "d1",
  "migrations",
  "apply",
  "arcane-commons-mesh-local",
  "--local"
]);

const root = generateKeyPairSync("ed25519");
const founder = generateKeyPairSync("ed25519");
const rootPublicKey = rawPublicKey(root.publicKey);
const founderPublicKey = rawPublicKey(founder.publicKey);
const communityId = `community-d1-${Date.now()}`;
const founderMemberId = `mem_${bytesToHex(
  blake3(Buffer.from(founderPublicKey, "base64url"))
)}`;
const createdAt = Math.floor(Date.now() / 1000);
const roles = ["admin", "member"];
const founderCredentialSerial = Date.now();
const founderCredentialExpiresAt = createdAt + 86400;
const founderCredentialBytes = membershipBytes({
  communityId,
  memberPublicKey: founderPublicKey,
  memberId: founderMemberId,
  roles,
  issuedAt: createdAt,
  expiresAt: founderCredentialExpiresAt,
  serial: founderCredentialSerial,
  issuerPublicKey: rootPublicKey
});
const bootstrapMessage = [
  "acm.community-bootstrap.v1",
  communityId,
  "D1 Integration Commons",
  rootPublicKey,
  createdAt,
  1,
  founderMemberId,
  founderPublicKey,
  roles.join(",")
].join("|");

let worker = await startWorker();
let token;
const runId = `${Date.now()}-${crypto.randomUUID()}`;
const catalogCid = bytesToHex(blake3(Buffer.from(`catalog:${runId}`)));
let expectedCatalogCid = catalogCid;
const objectBytes = Buffer.from(`encrypted-object:${runId}`);
const objectCid = bytesToHex(blake3(objectBytes));
const vaultId = `vault-d1-${runId}`;
const nodeId = `node-d1-${Date.now()}`;
const repairNodeId = `node-repair-d1-${Date.now()}`;
const proposalId = `proposal-d1-${Date.now()}`;
try {
  const bootstrap = await request("/v1/communities", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      communityId,
      name: "D1 Integration Commons",
      rootPublicKey,
      createdAt,
      policyVersion: 1,
      founderMemberId,
      founderPublicKey,
      founderRoles: roles,
      founderCredentialSerial,
      founderCredentialExpiresAt,
      founderCredentialSignature: base64Url(
        sign(null, founderCredentialBytes, root.privateKey)
      ),
      rootSignature: base64Url(sign(null, Buffer.from(bootstrapMessage), root.privateKey))
    })
  });
  if (bootstrap.response.status !== 201) {
    throw new Error(`community bootstrap failed: ${JSON.stringify(bootstrap.body)}`);
  }

  const challenge = await request("/v1/auth/challenges", { method: "POST" });
  const replayNonce = `nonce-${crypto.randomUUID()}`;
  const authMessage = [
    "acm.auth.v1",
    challenge.body.challengeId,
    challenge.body.challenge,
    replayNonce,
    founderMemberId,
    founderPublicKey
  ].join("|");
  const session = await request("/v1/auth/sessions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challengeId: challenge.body.challengeId,
      challenge: challenge.body.challenge,
      memberId: founderMemberId,
      publicKey: founderPublicKey,
      signature: base64Url(sign(null, Buffer.from(authMessage), founder.privateKey)),
      replayNonce
    })
  });
  if (session.response.status !== 200) {
    throw new Error(`session creation failed: ${JSON.stringify(session.body)}`);
  }
  token = session.body.sessionToken;

  const nodeEndpoint = generateKeyPairSync("ed25519");
  const nodeEndpointPublicKey = rawPublicKey(nodeEndpoint.publicKey);
  const nodeMessage = nodeCertificateBytes({
    nodeId,
    communityId,
    ownerMemberId: founderMemberId,
    endpointPublicKey: nodeEndpointPublicKey,
    maxStorageBytes: 10_000_000,
    issuedAt: createdAt,
    expiresAt: createdAt + 86400
  });
  const registeredNode = await request("/v1/nodes", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      nodeId,
      communityId,
      ownerMemberId: founderMemberId,
      endpointPublicKey: nodeEndpointPublicKey,
      failureDomain: "d1-integration-domain",
      region: "local",
      maxStorageBytes: 10_000_000,
      certificateSignature: base64Url(
        sign(null, nodeMessage, founder.privateKey)
      ),
      issuedAt: createdAt,
      expiresAt: createdAt + 86400
    })
  });
  if (registeredNode.response.status !== 201) {
    throw new Error(`node registration failed: ${JSON.stringify(registeredNode.body)}`);
  }
  const repairEndpoint = generateKeyPairSync("ed25519");
  const repairEndpointPublicKey = rawPublicKey(repairEndpoint.publicKey);
  const repairNodeMessage = nodeCertificateBytes({
    repairNodeId,
    nodeId: repairNodeId,
    communityId,
    ownerMemberId: founderMemberId,
    endpointPublicKey: repairEndpointPublicKey,
    maxStorageBytes: 10_000_000,
    issuedAt: createdAt,
    expiresAt: createdAt + 86400
  });
  const registeredRepairNode = await request("/v1/nodes", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      nodeId: repairNodeId,
      communityId,
      ownerMemberId: founderMemberId,
      endpointPublicKey: repairEndpointPublicKey,
      failureDomain: "d1-repair-domain",
      region: "local",
      maxStorageBytes: 10_000_000,
      certificateSignature: base64Url(
        sign(null, repairNodeMessage, founder.privateKey)
      ),
      issuedAt: createdAt,
      expiresAt: createdAt + 86400
    })
  });
  if (registeredRepairNode.response.status !== 201) {
    throw new Error(
      `repair node registration failed: ${JSON.stringify(registeredRepairNode.body)}`
    );
  }

  const catalogMessage = [
    "acm.catalog-pointer.v1",
    vaultId,
    catalogCid,
    1,
    "",
    createdAt
  ].join("|");
  const catalog = await request(`/v1/vaults/${vaultId}/catalog-pointer`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      catalogCid,
      version: 1,
      previousCid: null,
      signedAt: createdAt,
      ownerSignature: base64Url(
        sign(null, Buffer.from(catalogMessage), founder.privateKey)
      )
    })
  });
  if (catalog.response.status !== 200) {
    throw new Error(`catalog pointer failed: ${JSON.stringify(catalog.body)}`);
  }
  const forkCids = ["fork-a", "fork-b"].map((label) =>
    bytesToHex(blake3(Buffer.from(`${label}:${runId}`)))
  );
  const forkResults = await Promise.all(
    forkCids.map((forkCid) => {
      const signedAt = createdAt + 1;
      const forkMessage = [
        "acm.catalog-pointer.v1",
        vaultId,
        forkCid,
        2,
        catalogCid,
        signedAt
      ].join("|");
      return request(`/v1/vaults/${vaultId}/catalog-pointer`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          catalogCid: forkCid,
          version: 2,
          previousCid: catalogCid,
          signedAt,
          ownerSignature: base64Url(
            sign(null, Buffer.from(forkMessage), founder.privateKey)
          )
        })
      });
    })
  );
  const acceptedForks = forkResults.filter((result) => result.response.status === 200);
  const rejectedForks = forkResults.filter((result) => result.response.status === 409);
  if (acceptedForks.length !== 1 || rejectedForks.length !== 1) {
    throw new Error(`catalog CAS did not reject one concurrent fork: ${JSON.stringify(
      forkResults.map((result) => result.body)
    )}`);
  }
  expectedCatalogCid = acceptedForks[0].body.catalogCid;

  const object = await request("/v1/objects", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      cid: objectCid,
      ciphertextSize: objectBytes.length,
      objectKind: "data_chunk",
      replicaTarget: 3,
      fileName: forbiddenPlaintext[0].toString(),
      plaintextContent: forbiddenPlaintext[1].toString(),
      fileKey: forbiddenPlaintext[2].toString()
    })
  });
  if (object.response.status !== 201) {
    throw new Error(`object registration failed: ${JSON.stringify(object.body)}`);
  }
  const placed = await request(`/v1/objects/${objectCid}/placements`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify((() => {
      const placementId = `placement-d1-${Date.now()}`;
      const receiptMessage = [
        "acm.placement-receipt.v1",
        placementId,
        objectCid,
        nodeId,
        createdAt
      ].join("|");
      return {
      placementId,
      nodeId,
      createdAt,
      ciphertextBase64: base64Url(objectBytes),
      nodeSignature: base64Url(
        sign(null, Buffer.from(receiptMessage), nodeEndpoint.privateKey)
      )
    };
    })())
  });
  if (placed.response.status !== 201) {
    throw new Error(`placement failed: ${JSON.stringify(placed.body)}`);
  }
  const inflatedBytes = Buffer.from(`tiny-proof:${runId}`);
  const inflatedCid = bytesToHex(blake3(inflatedBytes));
  const inflatedObject = await request("/v1/objects", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      cid: inflatedCid,
      ciphertextSize: 4_000_000,
      objectKind: "data_chunk",
      replicaTarget: 3
    })
  });
  if (inflatedObject.response.status !== 201) {
    throw new Error(`inflated object fixture setup failed: ${JSON.stringify(inflatedObject.body)}`);
  }
  const inflatedPlacementId = `placement-inflated-${Date.now()}`;
  const inflatedReceipt = [
    "acm.placement-receipt.v1",
    inflatedPlacementId,
    inflatedCid,
    nodeId,
    createdAt
  ].join("|");
  const inflatedPlacement = await request(`/v1/objects/${inflatedCid}/placements`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      placementId: inflatedPlacementId,
      nodeId,
      createdAt,
      ciphertextBase64: base64Url(inflatedBytes),
      nodeSignature: base64Url(
        sign(null, Buffer.from(inflatedReceipt), nodeEndpoint.privateKey)
      )
    })
  });
  if (inflatedPlacement.response.status !== 401) {
    throw new Error("self-reported ciphertext size was accepted without byte-length proof");
  }
  const maintenance = await request("/v1/internal/audit-anchors/run", {
    method: "POST",
    headers: { "x-acm-internal-secret": "d1-test-secret" }
  });
  if (maintenance.response.status !== 202) {
    throw new Error(`maintenance scheduling failed: ${JSON.stringify(maintenance.body)}`);
  }
  const tasks = await request(`/v1/nodes/${nodeId}/tasks`, {
    headers: { authorization: `Bearer ${token}` }
  });
  if (
    tasks.response.status !== 200 ||
    !tasks.body.tasks.some((task) => task.taskKind === "audit_object")
  ) {
    throw new Error(`audit task was not scheduled: ${JSON.stringify(tasks.body)}`);
  }
  const auditTask = tasks.body.tasks.find((task) => task.taskKind === "audit_object");
  for (const action of ["accept", "complete"]) {
    const challenge = JSON.parse(auditTask.payloadJson).challenge;
    const storedAt = Math.floor(Date.now() / 1000);
    const proofMessage = [
      "acm.task-proof.v1",
      auditTask.taskId,
      auditTask.taskKind,
      objectCid,
      challenge,
      storedAt
    ].join("|");
    const transition = await request(`/v1/tasks/${auditTask.taskId}/${action}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        ...(action === "complete" ? { "content-type": "application/json" } : {})
      },
      ...(action === "complete" ? {
        body: JSON.stringify({
          storedAt,
          ciphertextBase64: base64Url(objectBytes),
          nodeSignature: base64Url(
            sign(null, Buffer.from(proofMessage), nodeEndpoint.privateKey)
          )
        })
      } : {})
    });
    if (transition.response.status !== 200) {
      throw new Error(`audit task ${action} failed: ${JSON.stringify(transition.body)}`);
    }
  }
  const credits = await request("/v1/credits/me", {
    headers: { authorization: `Bearer ${token}` }
  });
  if (
    credits.response.status !== 200 ||
    credits.body.balanceMilliGibHour <= 10_800_000 ||
    credits.body.transferable !== false
  ) {
    throw new Error(`audited storage credit was not earned: ${JSON.stringify(credits.body)}`);
  }
  const anchors = await request(`/v1/communities/${communityId}/audit-anchors`, {
    headers: { authorization: `Bearer ${token}` }
  });
  if (anchors.response.status !== 200 || anchors.body.anchors.length < 1) {
    throw new Error(`daily D1 anchor was not created: ${JSON.stringify(anchors.body)}`);
  }
  const repairTasks = await request(`/v1/nodes/${repairNodeId}/tasks`, {
    headers: { authorization: `Bearer ${token}` }
  });
  const repairTask = repairTasks.body.tasks.find(
    (task) => task.taskKind === "repair_object" && task.objectCid === objectCid
  );
  if (!repairTask) {
    throw new Error(`repair task was not scheduled: ${JSON.stringify(repairTasks.body)}`);
  }
  for (const action of ["accept", "complete"]) {
    const challenge = JSON.parse(repairTask.payloadJson).challenge;
    const storedAt = Math.floor(Date.now() / 1000);
    const proofMessage = [
      "acm.task-proof.v1",
      repairTask.taskId,
      repairTask.taskKind,
      objectCid,
      challenge,
      storedAt
    ].join("|");
    const transition = await request(`/v1/tasks/${repairTask.taskId}/${action}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        ...(action === "complete" ? { "content-type": "application/json" } : {})
      },
      ...(action === "complete" ? {
        body: JSON.stringify({
          storedAt,
          ciphertextBase64: base64Url(objectBytes),
          nodeSignature: base64Url(
            sign(null, Buffer.from(proofMessage), repairEndpoint.privateKey)
          )
        })
      } : {})
    });
    if (transition.response.status !== 200) {
      throw new Error(`repair task ${action} failed: ${JSON.stringify(transition.body)}`);
    }
  }

  const proposal = await request(`/v1/communities/${communityId}/proposals`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      proposalId,
      communityId,
      title: "D1 persistence",
      body: "Verify one-member-one-vote survives a Worker restart.",
      opensAt: createdAt - 1,
      closesAt: createdAt + 3600,
      quorumPercent: 20,
      thresholdPercent: 50
    })
  });
  if (proposal.response.status !== 201) {
    throw new Error(`proposal failed: ${JSON.stringify(proposal.body)}`);
  }
  const voteMessage = [
    "acm.vote.v1",
    proposalId,
    founderMemberId,
    "Yes",
    createdAt
  ].join("|");
  const cast = await request(`/v1/proposals/${proposalId}/vote`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      memberId: founderMemberId,
      choice: "yes",
      castAt: createdAt,
      memberSignature: base64Url(sign(null, Buffer.from(voteMessage), founder.privateKey))
    })
  });
  if (cast.response.status !== 200) {
    throw new Error(`vote failed: ${JSON.stringify(cast.body)}`);
  }
} finally {
  await stopWorker(worker.child);
}

worker = await startWorker();
try {
  const persisted = await request(`/v1/communities/${communityId}`, {
    headers: { authorization: `Bearer ${token}` }
  });
  if (persisted.response.status !== 200 || persisted.body.communityId !== communityId) {
    throw new Error(`D1 state did not survive Worker restart: ${JSON.stringify(persisted.body)}`);
  }
  const catalog = await request(`/v1/vaults/${vaultId}/catalog-pointer`, {
    headers: { authorization: `Bearer ${token}` }
  });
  if (
    catalog.response.status !== 200 ||
    catalog.body.catalogPointer.catalogCid !== expectedCatalogCid
  ) {
    throw new Error(`catalog did not persist: ${JSON.stringify(catalog.body)}`);
  }
  const placements = await request(`/v1/objects/${objectCid}/placements`, {
    headers: { authorization: `Bearer ${token}` }
  });
  if (placements.response.status !== 200 || placements.body.placements.length !== 2) {
    throw new Error(`placement did not persist: ${JSON.stringify(placements.body)}`);
  }
  const result = await request(`/v1/proposals/${proposalId}/result`, {
    headers: { authorization: `Bearer ${token}` }
  });
  if (result.response.status !== 200 || result.body.yes !== 1) {
    throw new Error(`vote did not persist: ${JSON.stringify(result.body)}`);
  }
  const audit = await request(`/v1/communities/${communityId}/audit-events`, {
    headers: { authorization: `Bearer ${token}` }
  });
  if (audit.response.status !== 200 || audit.body.events.length < 6) {
    throw new Error(`audit events missing: ${JSON.stringify(audit.body)}`);
  }
  let previousHash = "0".repeat(64);
  for (const [sequence, event] of audit.body.events.entries()) {
    const canonical = [
      "acm.audit-event.v1",
      sequence,
      event.occurredAt,
      event.eventKind,
      event.actorId,
      event.subjectId,
      previousHash
    ].join("|");
    const expectedHash = bytesToHex(blake3(Buffer.from(canonical)));
    if (
      event.sequence !== sequence ||
      event.previousEventHash !== previousHash ||
      event.eventHash !== expectedHash
    ) {
      throw new Error(`audit chain is not contiguous at sequence ${sequence}`);
    }
    previousHash = event.eventHash;
  }

  const unauthenticated = await request(`/v1/communities/${communityId}`);
  if (unauthenticated.response.status !== 401) {
    throw new Error("protected route accepted a request without a session");
  }
} finally {
  await stopWorker(worker.child);
}

for (const path of readdirSync(".wrangler/state", { recursive: true })
  .map((entry) => `.wrangler/state/${entry}`)
  .filter((entry) => !entry.endsWith("/"))) {
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch {
    continue;
  }
  for (const sentinel of forbiddenPlaintext) {
    if (bytes.includes(sentinel)) {
      throw new Error(`plaintext sentinel persisted in D1 state: ${path}`);
    }
  }
}

console.log(
  "D1 integration PASS: signed control records, proof-bound storage tasks, restart, auth rejection, plaintext absence"
);
