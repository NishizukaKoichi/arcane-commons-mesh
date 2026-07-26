# ADR 0010: Worker authentication persistence and BLAKE3 implementation

## What changed

The Worker persists hashed one-use challenges, replay nonces, short-lived session tokens, memberships, signed coordination records, and audit events in D1. It uses `@noble/hashes` for BLAKE3-compatible audit hashes.

## Why

An in-memory repository loses security state on restart and cannot reject replay across Worker instances. The audit chain must use the same specified BLAKE3 primitive as the Rust implementation.

## Alternatives considered

- Web Crypto has no BLAKE3 primitive.
- A custom BLAKE3 implementation would be unsafe and difficult to audit.
- Keeping session state in memory would make D1 restart tests misleading.

## Risks and rollback

This adds a supply-chain dependency and makes D1 availability part of online coordination. The dependency is lockfile-pinned and covered by audit-chain tests. Roll back by replacing the implementation behind the repository and hash boundaries without changing stored plaintext policy.
