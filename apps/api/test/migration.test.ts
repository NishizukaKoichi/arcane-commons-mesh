import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const migration = readFileSync(
  new URL("../migrations/0001_initial.sql", import.meta.url),
  "utf8"
).toLowerCase();

describe("D1 migration privacy contract", () => {
  it("contains every required table", () => {
    for (const table of [
      "communities",
      "members",
      "membership_credentials",
      "invites",
      "join_requests",
      "nodes",
      "node_heartbeats",
      "vault_catalog_pointers",
      "objects",
      "placements",
      "node_tasks",
      "credit_accounts",
      "credit_entries",
      "credit_grants",
      "credit_policies",
      "proposals",
      "votes",
      "auth_challenges",
      "sessions",
      "audit_events",
      "audit_anchors",
      "replay_nonces"
    ]) {
      expect(migration).toContain(`create table ${table}`);
    }
  });

  it("has no plaintext user-data or secret columns", () => {
    for (const forbidden of [
      "file_name",
      "relative_path",
      "file_key",
      "vault_master_key",
      "identity_private_key",
      "plaintext_content",
      "recovery_secret"
    ]) {
      expect(migration).not.toContain(forbidden);
    }
  });

  it("uses integer credit and one current vote per member", () => {
    expect(migration).toContain("milli_gib_hour integer");
    expect(migration).toContain("primary key (proposal_id, member_id)");
    expect(migration).not.toContain(" real");
    expect(migration).not.toContain(" float");
  });
});
