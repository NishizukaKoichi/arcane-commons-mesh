# 0006 — Single-Mac authenticated QUIC mesh

Status: accepted for the 2026-07-28 local-network milestone

## What changed

- Storage-node child processes expose bidirectional iroh/QUIC RPC endpoints.
- The verifier uses those endpoints for PUT, GET, corrupted-replica fallback,
  repair, and Recovery Kit reconstruction instead of filesystem IPC.
- Local D1 registers the actual iroh endpoint IDs.
- Binary wire payloads use base64url within a bounded JSON frame.
- `node` is an explicit membership role in the API schema.

## Why

Filesystem IPC proved process isolation but did not exercise connection
authentication, request replay persistence, wire-size enforcement, or
request/response binding. One Mac can still validate those properties by using
separate loopback endpoints and storage roots.

## Alternatives considered

- Unix sockets would prove inter-process I/O but not the selected iroh protocol.
- A public relay would add deployment, availability, and trust dependencies
  without helping the deterministic one-Mac milestone.
- Replacing JSON with a new binary codec would reduce wire overhead but add a
  larger compatibility migration. Base64url keeps the current versioned schema
  explicit while bounding its worst-case size.

## Risks and rollback

Loopback tests do not prove NAT traversal, relay operation, or independent
failure domains. The frame limit includes base64 expansion and is covered by a
maximum-object test. Roll back by reverting this commit; `pnpm demo:down`
removes all generated local node state.
