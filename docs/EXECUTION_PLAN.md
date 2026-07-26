# Execution plan

## Context snapshot — 2026-07-26

- Canonical repo: `/Volumes/Pensive/arcane-commons-mesh`, branch `main`.
- Source of truth: `CODEX_MASTER_PROMPT.md` plus repository behavior and ADRs.
- Goal: a local, reproducible three-node encrypted cooperative-backup MVP.
- Out of scope: external deployment/push, paid services, real blockchain,
  production-security claims, and globally independent failure domains.
- Toolchain: Node 22.13, pnpm 10.13.1, Rust 1.91.
- Initial state: new repository; no inherited code or dirty changes.

## Decisions

1. Rust `mesh-core` is the only domain implementation. CLI and Tauri use it.
2. Coordinator, transport, secret store, clock, and audit anchor are adapters.
3. CI acceptance uses an in-memory transport; iroh is a separate local integration.
4. The critical path is encrypt → three placements → outage restore → corrupt
   replica fallback → clean recovery.
5. Canonical signed bytes, rollback protection, deletion authority, and key
   derivation are specified before network implementation.

## Milestones and gates

1. Foundation: workspace, docs, contracts, CI skeleton, ADRs.
2. Crypto/CAS: unit tests for AEAD, streaming, recovery, signatures, paths, quota.
3. Coordinator boundary and in-memory three-node vertical integration test.
4. Local iroh transport and process-level node demo.
5. Worker/D1 auth, membership, registry, catalog pointer, and OpenAPI.
6. Audit, repair, deterministic integer credit, governance.
7. CLI `verify:mvp`, then thin Tauri UI and public information site.
8. All gates, secret/plaintext scans, clean-room README run, review, local commit.

## Evidence

Every acceptance criterion receives an ID in the machine-readable verification
report. A single `verify:mvp` exit code is not sufficient evidence for claims that
also require static review, documentation, or local process history.

## Progress

- 2026-07-26: foundation and vertical encryption/recovery/CAS proof committed.
- 2026-07-26: added constant-memory chunk streaming boundaries, deterministic
  domain-separated membership signing, audit hash chain/Merkle root, and
  idempotent integer storage-credit arithmetic. Network/API adapters remain next.
- 2026-07-26: separated protocol, storage-node, and testkit crates. The in-memory
  mesh now enforces independent failure domains and tests three replicas, outage
  restore, corrupted-replica rejection, audit health, and encrypted repair.
- 2026-07-26: added the exchangeable local control-plane model with one-use
  challenges and replay nonces, membership, node/object/placement records,
  monotonic catalog pointers, non-transferable credit, one-member-one-vote,
  append-only vote history, and tamper-evident community snapshot export.
- 2026-07-26: added a pinned Hono/Worker adapter, complete initial D1 schema,
  OpenAPI surface, Ed25519 challenge verification, replay/expiry tests,
  one-member-one-vote API tests, forbidden financial-route tests, and Wrangler
  dry-run build. No external deployment was performed.
- 2026-07-26: added the Tauri 2/React desktop, Stronghold initialization,
  responsive Japanese-first onboarding/dashboard/vault/provider/community/
  recovery surfaces, generated platform icons, five safety-flow UI tests, and a
  successful unsigned local Tauri release build. Desktop and 390px mobile browser
  passes showed no horizontal overflow.
- 2026-07-26: expanded `acmctl` to the specified command tree and replaced the
  four-assertion verifier with all fifteen deterministic offline steps. The
  verifier now emits machine-readable evidence for replication, outage,
  corruption, repair, credit, forbidden routes, voting, clean recovery,
  plaintext absence, and audit integrity.
- 2026-07-26: added a four-page static public-information site with an explicit
  limitations/status page, public boundary summary, and local-build download
  guidance. It has no authentication, secrets, analytics, or remote runtime and
  was not deployed.
- 2026-07-26: added SHA-pinned CI, isolated local-MVP integration, unsigned
  macOS desktop build, and manually approved Cloudflare deployment workflows.
  Local pnpm and RustSec audits found no known vulnerability; RustSec reported
  transitive maintenance/unsoundness warnings in the Tauri Linux GTK3 tree.
- 2026-07-26: implemented the validated `AuditAnchorAdapter` boundary with an
  append-only local JSONL file, a D1 writer adapter, deterministic mock, and an
  interface-only future EVM encoder. No RPC, wallet, key, or contract exists.
- 2026-07-26: added the native iroh 1.0.3 QUIC transport with authenticated
  endpoint identities, the `arcane-commons-mesh/1` ALPN, bounded frames,
  direct-first/network relay configuration, and a relay/discovery-free loopback
  integration test. Rust moved to 1.91, iroh's supported minimum.
- 2026-07-26: final review found completion-blocking trust gaps. The first repair
  binds membership credentials to the configured community root, verifies real
  Ed25519 catalog/vote/request signatures, binds request node IDs to iroh endpoint
  certificates using server time, and rejects repeated request IDs. API/D1,
  desktop, process demo, and durable storage findings remain open.
