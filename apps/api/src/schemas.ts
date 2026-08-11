import { z } from "zod";

export const cid = z.string().regex(/^[0-9a-f]{64}$/);
export const publicKey = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const endpointPublicKey = z
  .string()
  .regex(/^(?:[A-Za-z0-9_-]{43}|[0-9a-f]{64})$/);
export const opaqueId = z.string().min(3).max(128);

export const challengeSession = z.object({
  challengeId: opaqueId,
  challenge: z.string().min(40).max(128),
  memberId: opaqueId,
  publicKey,
  signature: z.string().min(80).max(128),
  replayNonce: z.string().min(16).max(128)
});

export const community = z.object({
  communityId: opaqueId,
  name: z.string().min(1).max(100),
  rootPublicKey: publicKey,
  createdAt: z.number().int(),
  policyVersion: z.number().int().positive(),
  founderMemberId: opaqueId,
  founderPublicKey: publicKey,
  founderRoles: z.array(z.enum(["member", "admin", "auditor", "node"])).min(1).max(4),
  founderCredentialSerial: z.number().int().nonnegative(),
  founderCredentialExpiresAt: z.number().int(),
  founderCredentialSignature: z.string().min(80).max(128),
  rootSignature: z.string().min(80).max(128)
});

export const node = z.object({
  nodeId: opaqueId,
  communityId: opaqueId,
  ownerMemberId: opaqueId,
  endpointPublicKey,
  failureDomain: z.string().min(1).max(128),
  region: z.string().min(1).max(64),
  maxStorageBytes: z.number().int().positive(),
  certificateSignature: z.string().min(80).max(128),
  issuedAt: z.number().int(),
  expiresAt: z.number().int()
});

export const joinRequest = z.object({
  inviteCode: z.string().min(20).max(256),
  memberPublicKey: publicKey
});

export const membershipApproval = z.object({
  memberId: opaqueId,
  memberPublicKey: publicKey,
  roles: z.array(z.enum(["member", "admin", "auditor", "node"])).min(1).max(4),
  serial: z.number().int().nonnegative(),
  issuedAt: z.number().int(),
  expiresAt: z.number().int(),
  rootSignature: z.string().min(80).max(128)
});

export const heartbeat = z.object({
  usedStorageBytes: z.number().int().nonnegative(),
  status: z.enum(["online", "degraded"])
});

export const placement = z.object({
  placementId: opaqueId,
  nodeId: opaqueId,
  createdAt: z.number().int(),
  ciphertextBase64: z.string().min(1).max(8_000_000),
  nodeSignature: z.string().min(80).max(128)
});

export const taskProof = z.object({
  storedAt: z.number().int(),
  ciphertextBase64: z.string().min(1).max(8_000_000),
  nodeSignature: z.string().min(80).max(128)
});

export const objectRecord = z.object({
  cid,
  ciphertextSize: z.number().int().positive().max(4 * 1024 * 1024 + 128 * 1024),
  objectKind: z.enum(["data_chunk", "encrypted_manifest", "encrypted_catalog"]),
  replicaTarget: z.number().int().min(1).max(9)
});

export const catalogPointer = z.object({
  catalogCid: cid,
  version: z.number().int().positive(),
  previousCid: cid.nullable(),
  signedAt: z.number().int(),
  ownerSignature: z.string().min(80).max(128)
});

export const commonsArtifact = z.object({
  artifactId: z.string().regex(/^(?:res|spl|cap|exe|memr|gri|leg|exp)_[0-9a-f]{64}$/),
  kind: z.enum([
    "research", "spell", "capability", "execution", "memory", "grimoire", "legacy",
    "federation_export"
  ]),
  envelopeCid: cid,
  encryptedEnvelopeBase64: z.string().min(1).max(400_000),
  createdAt: z.number().int().nonnegative(),
  ownerSignature: z.string().min(80).max(128)
});

export const proposal = z.object({
  proposalId: opaqueId,
  communityId: opaqueId,
  title: z.string().min(1).max(200),
  body: z.string().min(1).max(20_000),
  opensAt: z.number().int(),
  closesAt: z.number().int(),
  quorumPercent: z.number().int().min(0).max(100).default(20),
  thresholdPercent: z.number().int().min(0).max(100).default(50)
});

export const vote = z.object({
  memberId: opaqueId,
  choice: z.enum(["yes", "no", "abstain"]),
  castAt: z.number().int(),
  memberSignature: z.string().min(80).max(128)
});
