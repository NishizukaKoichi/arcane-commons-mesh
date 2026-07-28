# Context snapshot

- Date: 2026-07-28
- Scope: desktop-to-single-Mac, three-process authenticated network milestone
- Canonical repo: `/Volumes/Pensive/arcane-commons-mesh`, `main`
- Source of truth: `CODEX_MASTER_PROMPT.md`, running code, ADRs, and this snapshot

## Goal and success criteria

Replace verifier-side file IPC with actual authenticated iroh/QUIC operations
across three isolated storage-node processes. Replication, outage fallback,
corruption rejection, repair, and Recovery Kit reconstruction must pass without
external deployment, relay, or a second Mac.

Out of scope: geographic redundancy, public relay deployment, NAT traversal,
production membership enrollment, and proof of surviving loss of this Mac.

## Current state

The v0.1 crypto, storage, control plane, desktop, recovery, and local acceptance
suite existed at commit `3607fb8`. This milestone adds bidirectional QUIC RPC,
real demo endpoint registration, a reproducible network smoke command, and moves
both the acceptance path and Tauri desktop storage path from filesystem IPC to
QUIC. The desktop now reports the health of all three isolated storage processes;
catalogs, manifests, and encrypted chunks use those endpoints when connected.

## Decisions

- 2026-07-28: keep the demo loopback-only and relay-free so it is deterministic,
  free, and requires no external service.
- 2026-07-28: retain JSON records but encode binary payloads as base64url and
  enforce a bounded frame sized for the maximum encrypted object.
- 2026-07-28: persist a public local connection profile in desktop application
  data and confine deterministic demo credentials to the loopback adapter.
  Alternative: keep app-local stores. Risk: demo authority is unsuitable for
  external use. Rollback: remove the profile to restore the app-local path.
- 2026-07-28: a disconnected response stream must not terminate a storage node;
  one client may stop after obtaining enough healthy replicas.

## Next boundary

The next separate milestone is production membership issuance and independently
hosted node endpoints. It requires another machine or a consciously selected
hosted environment to prove device-loss recovery.
