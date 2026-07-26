import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";

const port = 8791;
const baseUrl = `http://127.0.0.1:${port}`;

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function rawPublicKey(key) {
  const der = key.export({ type: "spki", format: "der" });
  return base64Url(der.subarray(der.length - 32));
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
const founderMemberId = `member-d1-${Date.now()}`;
const createdAt = Math.floor(Date.now() / 1000);
const roles = ["admin", "member"];
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
const catalogCid = createHash("sha256").update(`catalog:${runId}`).digest("hex");
const objectCid = createHash("sha256").update(`object:${runId}`).digest("hex");
const vaultId = `vault-d1-${runId}`;
const nodeId = `node-d1-${Date.now()}`;
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
  const nodeMessage = [
    "acm.node-certificate.v1",
    nodeId,
    communityId,
    founderMemberId,
    nodeEndpointPublicKey,
    "node",
    10_000_000,
    createdAt,
    createdAt + 86400
  ].join("|");
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
        sign(null, Buffer.from(nodeMessage), founder.privateKey)
      ),
      issuedAt: createdAt,
      expiresAt: createdAt + 86400
    })
  });
  if (registeredNode.response.status !== 201) {
    throw new Error(`node registration failed: ${JSON.stringify(registeredNode.body)}`);
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

  const object = await request("/v1/objects", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      cid: objectCid,
      ciphertextSize: 4096,
      objectKind: "data_chunk",
      replicaTarget: 3
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
    body: JSON.stringify({
      placementId: `placement-d1-${Date.now()}`,
      nodeId,
      createdAt
    })
  });
  if (placed.response.status !== 201) {
    throw new Error(`placement failed: ${JSON.stringify(placed.body)}`);
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
    const transition = await request(`/v1/tasks/${auditTask.taskId}/${action}`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}` }
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
  if (catalog.response.status !== 200 || catalog.body.catalogPointer.catalogCid !== catalogCid) {
    throw new Error(`catalog did not persist: ${JSON.stringify(catalog.body)}`);
  }
  const placements = await request(`/v1/objects/${objectCid}/placements`, {
    headers: { authorization: `Bearer ${token}` }
  });
  if (placements.response.status !== 200 || placements.body.placements.length !== 1) {
    throw new Error(`placement did not persist: ${JSON.stringify(placements.body)}`);
  }
  const result = await request(`/v1/proposals/${proposalId}/result`, {
    headers: { authorization: `Bearer ${token}` }
  });
  if (result.response.status !== 200 || result.body.yes !== 1) {
    throw new Error(`vote did not persist: ${JSON.stringify(result.body)}`);
  }

  const unauthenticated = await request(`/v1/communities/${communityId}`);
  if (unauthenticated.response.status !== 401) {
    throw new Error("protected route accepted a request without a session");
  }
} finally {
  await stopWorker(worker.child);
}

console.log(
  "D1 integration PASS: signed bootstrap/node/catalog/vote, persisted metadata/session, restart, auth rejection"
);
