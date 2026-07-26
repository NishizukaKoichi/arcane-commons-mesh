import { readFileSync } from "node:fs";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  memberIdFor,
  membershipCanonicalBytes,
  nodeCertificateCanonicalBytes
} from "../src/canonical";
import { toBase64Url } from "../src/repository";

const fixture = JSON.parse(
  readFileSync("../../packages/protocol-fixtures/canonical-v1.json", "utf8")
) as {
  membership_hex: string;
  node_hex: string;
  member_id: string;
  object_fixture: string;
  object_cid: string;
};

describe("cross-language canonical encoding", () => {
  it("matches the Rust membership and node certificate fixture", () => {
    const memberPublicKey = toBase64Url(new Uint8Array(32).fill(2));
    const issuerPublicKey = toBase64Url(new Uint8Array(32).fill(1));
    expect(memberIdFor(memberPublicKey)).toBe(fixture.member_id);
    expect(bytesToHex(blake3(new TextEncoder().encode(fixture.object_fixture)))).toBe(
      fixture.object_cid
    );
    expect(
      Buffer.from(
        membershipCanonicalBytes({
          communityId: "community-fixture",
          memberPublicKey,
          memberId: fixture.member_id,
          roles: ["member", "admin"],
          issuedAt: 100,
          expiresAt: 200,
          serial: 7,
          issuerPublicKey
        })
      ).toString("hex")
    ).toBe(fixture.membership_hex);
    expect(
      Buffer.from(
        nodeCertificateCanonicalBytes({
          nodeId: "node-fixture",
          communityId: "community-fixture",
          ownerMemberId: fixture.member_id,
          endpointPublicKey: "endpoint-fixture",
          maxStorageBytes: 4096,
          issuedAt: 100,
          expiresAt: 200
        })
      ).toString("hex")
    ).toBe(fixture.node_hex);
  });
});
