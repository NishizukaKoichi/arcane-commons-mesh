# ADR 0004: Worker dependencies and custody boundary

Status: accepted — 2026-07-26.

The local Worker adapter pins Hono 4.12.32, Zod 4.4.3,
`@hono/zod-validator` 0.9.0, Wrangler 4.114.0, TypeScript 7.0.2, and Vitest
4.1.10 in the lockfile. These were the published stable versions checked at
implementation time.

Worker/D1 is coordination only. The schema contains public identities,
credentials, nodes, CIDs, ciphertext sizes, placements, tasks, integer credit,
votes, challenges, sessions, and audit hashes. It deliberately has no column or
route for file bodies, plaintext file names or paths, file/vault/identity private
keys, or recovery secrets. R2 is not configured.

The deployment workflow remains dry-run/local until separately authorized.
Rollback is removal of `apps/api`; the shared Rust control model remains the
portable contract.
