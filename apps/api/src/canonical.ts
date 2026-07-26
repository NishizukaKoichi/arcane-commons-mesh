import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { fromBase64Url } from "./repository";

const encoder = new TextEncoder();

function concat(parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function field(value: Uint8Array | string): Uint8Array {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, bytes.length, false);
  return concat([length, bytes]);
}

function integer(value: number | bigint, bytes: 2 | 4 | 8): Uint8Array {
  const output = new Uint8Array(bytes);
  const view = new DataView(output.buffer);
  if (bytes === 2) view.setUint16(0, Number(value), false);
  else if (bytes === 4) view.setUint32(0, Number(value), false);
  else view.setBigInt64(0, BigInt(value), false);
  return output;
}

export function memberIdFor(publicKey: string): string {
  return `mem_${bytesToHex(blake3(fromBase64Url(publicKey)))}`;
}

export function membershipCanonicalBytes(input: {
  communityId: string;
  memberPublicKey: string;
  memberId: string;
  roles: string[];
  issuedAt: number;
  expiresAt: number;
  serial: number;
  issuerPublicKey: string;
}): Uint8Array {
  const roles = [...input.roles].sort();
  return concat([
    field("acm.membership.v1"),
    integer(1, 2),
    field(input.communityId),
    field(fromBase64Url(input.memberPublicKey)),
    field(input.memberId),
    integer(roles.length, 4),
    ...roles.map(field),
    integer(input.issuedAt, 8),
    integer(input.expiresAt, 8),
    integer(input.serial, 8),
    field(fromBase64Url(input.issuerPublicKey))
  ]);
}

export function nodeCertificateCanonicalBytes(input: {
  nodeId: string;
  communityId: string;
  ownerMemberId: string;
  endpointPublicKey: string;
  maxStorageBytes: number;
  issuedAt: number;
  expiresAt: number;
}): Uint8Array {
  return concat([
    field("acm.node-certificate.v1"),
    integer(1, 2),
    field(input.nodeId),
    field(input.communityId),
    field(input.ownerMemberId),
    field(input.endpointPublicKey),
    integer(1, 4),
    field("node"),
    integer(input.maxStorageBytes, 8),
    integer(input.issuedAt, 8),
    integer(input.expiresAt, 8)
  ]);
}
