import { z } from "zod";

export const cid = z.string().regex(/^[0-9a-f]{64}$/);
export const publicKey = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const opaqueId = z.string().min(3).max(128);

export const challengeSession = z.object({
  challengeId: opaqueId,
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
  policyVersion: z.number().int().positive()
});

export const node = z.object({
  nodeId: opaqueId,
  communityId: opaqueId,
  ownerMemberId: opaqueId,
  endpointPublicKey: publicKey,
  failureDomain: z.string().min(1).max(128),
  region: z.string().min(1).max(64),
  maxStorageBytes: z.number().int().positive()
});

export const objectRecord = z.object({
  cid,
  ciphertextSize: z.number().int().positive(),
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
