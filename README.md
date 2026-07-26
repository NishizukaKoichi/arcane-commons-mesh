# Arcane Commons Mesh / 魔法網

Arcane Commons Mesh v0.1 is a local, independently verifiable MVP for a
members-only cooperative backup mesh. It encrypts data before storage, places
ciphertext on three isolated local storage nodes, restores through an outage,
rejects corruption, and recovers from an encrypted recovery file.

This is not production-ready, fully decentralized, anonymous, or independently
security-audited. It has no cryptocurrency, transferable credit, wallet, or real
blockchain connection.

## Prerequisites

- macOS or Linux
- Node 22.13 and pnpm 10.13
- Rust 1.91

## Verify locally

```sh
pnpm install
pnpm lint
pnpm format:check
pnpm typecheck
pnpm test
pnpm build
pnpm verify:mvp
```

No external deployment, account, token, relay, or blockchain is required.
See `docs/EXECUTION_PLAN.md`, `docs/THREAT_MODEL.md`, and `docs/RECOVERY.md`.

`pnpm verify:mvp` performs all fifteen local acceptance steps: fixture creation,
owner-side encryption, three placements, source isolation, node outage, restore,
deliberate corruption, healthy fallback and repair, provider earning, owner
consumption, forbidden financial-route checks, one-member-one-vote, clean
Recovery Kit restore, plaintext absence checks, and audit-chain/Merkle
verification. Evidence is written to `.verify/verify-mvp-report.json`.

The unsigned local desktop artifact is built with:

```sh
pnpm --filter @arcane-commons/desktop tauri build --no-bundle
```

The current release binary is placed under `target/release/`. It is an unaudited
development artifact and must not be treated as the only copy of valuable data.

The local public-information site is built as static files with:

```sh
pnpm --filter @arcane-commons/site build
```

Its output is placed under `apps/site/dist/`. The site makes no network calls and
does not imply that a signed public release or geographically independent mesh
already exists.
