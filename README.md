# Arcane Commons Mesh / 魔法網

Arcane Commons Mesh v0.1 is a local, independently verifiable MVP for a
members-only cooperative backup mesh. It encrypts data before storage, places
ciphertext on three local storage-node processes, restores through an outage,
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

## Run the local demo

```sh
pnpm demo:up
curl http://127.0.0.1:8787/health
pnpm demo:down
```

This starts a local Worker with D1, three storage node processes, and one auditor
process. All state and logs stay under `.demo/`. `demo:down` stops recorded
processes and removes that directory.

## Exercise the encrypted CLI vault

Vault commands read the passphrase from standard input. This example uses a
shell prompt so the passphrase is not placed in command history:

```sh
read -s ACM_PASSPHRASE
printf '%s\n' "$ACM_PASSPHRASE" | cargo run -p arcane-mesh-cli -- vault create
printf '%s\n' "$ACM_PASSPHRASE" | cargo run -p arcane-mesh-cli -- vault add ./example.pdf
printf '%s\n' "$ACM_PASSPHRASE" | cargo run -p arcane-mesh-cli -- vault list
unset ACM_PASSPHRASE
```

Local vault state stays in ignored `.acm/`. Data chunks use three local replicas;
encrypted manifests and signed encrypted catalogs use five. Keep the generated
Recovery Kit somewhere separate from the computer.

To rebuild in a clean directory from an external Kit and mounted/exported node
stores:

```sh
printf '%s\n' "$ACM_PASSPHRASE" | cargo run -p arcane-mesh-cli -- \
  recovery import /Volumes/Backup/owner.acm-recovery \
  --source /Volumes/Node-A/storage \
  --source /Volumes/Node-B/storage \
  --source /Volumes/Node-C/storage
```

The unsigned local desktop artifact is built with:

```sh
pnpm --filter @arcane-commons/desktop tauri build --no-bundle
```

The current release binary is placed under `target/release/`. Onboarding writes
an encrypted Recovery Kit to Downloads and stores identity/vault keys in a
Stronghold snapshot. Real file additions are streamed, encrypted, and replicated
to separate object stores on the same Mac. The desktop labels this as local MVP
storage: it is not geographic redundancy and does not survive loss of that Mac.
The onboarding screen can import a Kit from explicitly supplied storage-node
folders; automatic remote-node discovery is not part of this local artifact.
It is an unaudited
development artifact and must not be treated as the only copy of valuable data.

The local public-information site is built as static files with:

```sh
pnpm --filter @arcane-commons/site build
```

Its output is placed under `apps/site/dist/`. The site makes no network calls and
does not imply that a signed public release or geographically independent mesh
already exists.
