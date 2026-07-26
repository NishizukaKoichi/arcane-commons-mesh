# Execution plan

## Context snapshot — 2026-07-26

- Canonical repo: `/Volumes/Pensive/arcane-commons-mesh`, branch `main`.
- Source of truth: `CODEX_MASTER_PROMPT.md` plus repository behavior and ADRs.
- Goal: a local, reproducible three-node encrypted cooperative-backup MVP.
- Out of scope: external deployment/push, paid services, real blockchain,
  production-security claims, and globally independent failure domains.
- Toolchain: Node 22.13, pnpm 10.13.1, Rust 1.88.
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
