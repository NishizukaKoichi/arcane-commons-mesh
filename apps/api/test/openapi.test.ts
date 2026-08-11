import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const specification = readFileSync(
  new URL("../openapi.yaml", import.meta.url),
  "utf8"
).toLowerCase();

describe("OpenAPI negative capabilities", () => {
  it("documents required coordination surfaces without financial routes", () => {
    for (const required of [
      "/v1/auth/challenges",
      "/v1/communities",
      "/v1/nodes",
      "/v1/objects",
      "/v1/credits/me",
      "/v1/proposals/{proposalid}/vote",
      "/v1/communities/{communityid}/commons-artifacts",
      "/v1/internal/audit-anchors/run"
    ]) {
      expect(specification).toContain(required);
    }
    for (const forbidden of [
      "/transfer",
      "/buy",
      "/sell",
      "/exchange",
      "/wallet",
      "/token"
    ]) {
      expect(specification).not.toContain(forbidden);
    }
  });
});
