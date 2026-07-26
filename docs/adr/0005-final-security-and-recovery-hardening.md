# 0005 — Final security and recovery hardening

Status: accepted for v0.1 local MVP

## What changed

- BLAKE3 object identifiers and canonical signed-record bytes are shared across
  Rust and TypeScript fixtures.
- Every public iroh transport constructor now requires a durable SQLite replay
  database.
- Recovery copies and retains the complete signed catalog chain, so garbage
  collection cannot invalidate an older external Recovery Kit.
- The process-node repair check now runs as a destination-node task with a
  challenge-bound receipt instead of a verifier-side direct copy.
- Desktop backend tests exercise Recovery Kit import, garbage collection, and
  retained-file restoration without relying on renderer mocks.

## Why

The final security and data-loss reviews found that divergent encodings,
process-only replay state, and deletion of old catalog checkpoints could cause
authentication failures, replay acceptance after restart, or unrecoverable
vaults.

## Alternatives considered

Keeping only the newest catalog was smaller, but made stale Recovery Kits
unusable. Discovering catalogs without a trusted checkpoint was rejected
because it weakens rollback and ownership guarantees.

## Risks and rollback

Catalog history consumes a small amount of additional ciphertext storage and
recovery scans remain bounded by the linked chain. Rollback is a normal revert
of this commit; it must not be performed after users depend on older Recovery
Kits.
