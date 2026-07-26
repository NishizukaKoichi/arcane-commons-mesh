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
- Rust 1.88

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
