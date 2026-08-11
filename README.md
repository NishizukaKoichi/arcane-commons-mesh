# Arcane Commons Mesh / 魔法網

Arcane Commons v1 is a public, independently verifiable reference
implementation for sovereign data, durable community knowledge and attributable
creator reward. It combines an encrypted cooperative storage mesh with signed
Research, Spell, Capability, Compute-to-Data, Pensive, Grimoire, Legacy and
federation/export protocols.

The source is published under the [MIT License](LICENSE) so anyone may fork,
modify, redistribute, or continue the project. Contributions and independent
implementations are welcome. The protocol journey is complete and reproducible;
this is a reference implementation rather than a hosted production service.
Release changes are recorded in [CHANGELOG.md](CHANGELOG.md).

This is implementation-complete as a reference and operator handoff, but it is
not a hosted production service, fully decentralized, anonymous, or independently
security-audited. Its signed adapter fixtures are not certified TEE evidence or
proof that money moved. It has no
cryptocurrency, transferable credit, wallet, or real blockchain connection.

> **Do not use this as the only copy of valuable data.** The current three-node
> demo runs on one computer and does not survive loss of that computer.

## Prerequisites

- macOS or Linux
- Node 22.13 and pnpm 10.13
- Rust 1.91

## Download the CLI

Prebuilt `acmctl` archives for Apple silicon macOS, Intel macOS, x86-64 Linux,
and x86-64 Windows are published on the
[GitHub Releases page](https://github.com/NishizukaKoichi/arcane-commons-mesh/releases).
Every archive has a separate SHA-256 checksum. Verify it before extracting, then
run `acmctl doctor`. These binaries are reproducibly built by GitHub Actions but
are not code-signed, notarized, or independently audited. See
[`docs/RELEASE.md`](docs/RELEASE.md) for exact installation and verification
steps.

## Verify locally

```sh
pnpm install
pnpm lint
pnpm format:check
pnpm typecheck
pnpm test
pnpm build
pnpm verify:mvp
pnpm verify:commons
pnpm verify:handoff
```

No external deployment, account, token, relay, or blockchain is required.
See `docs/EXECUTION_PLAN.md`, `docs/THREAT_MODEL.md`, and `docs/RECOVERY.md`.

`pnpm verify:mvp` performs all fifteen local acceptance steps: fixture creation,
owner-side encryption, three placements, source isolation, node outage, restore,
deliberate corruption, healthy fallback and repair, provider earning, owner
consumption, forbidden financial-route checks, one-member-one-vote, clean
Recovery Kit restore, plaintext absence checks, and audit-chain/Merkle
verification. Evidence is written to `.verify/verify-mvp-report.json`.

The connected Arcane Commons v1 protocol journey is exercised with:

```sh
pnpm verify:commons
```

It verifies thirteen additional steps spanning signed Research Commons causal
records, bounded Spell contracts, portable Capability Manifests and exact revenue
splits, measured Compute-to-Data attestations, replaceable confidential-runtime
evidence and idempotent settlement receipts, provenance-aware Pensive grants,
quorum-confirmed Grimoire knowledge, time-locked multi-guardian Legacy directives,
and signed federation export/import receipts. Evidence is written to
`.verify/verify-commons-report.json`. The authenticated API persists only opaque
encrypted Commons envelopes; the desktop saves and reloads its eight-stage
workspace under a Stronghold-held key and exports an API-compatible signed
artifact.

## Run the local demo

```sh
pnpm demo:up
curl http://127.0.0.1:8787/health
pnpm demo:smoke
pnpm demo:down
```

This starts a local Worker with D1, three storage node processes, and one auditor
process. Each node has a separate iroh endpoint, identity, replay database, and
object store. `demo:smoke` sends random ciphertext through authenticated QUIC,
stores it on all three nodes, reads it back, and verifies all three CIDs. All
state and logs stay under `.demo/`. `demo:down` stops recorded processes and
removes that directory. See `docs/NETWORK_LOCAL.md`.

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

The current development binary is placed under `target/release/`. GitHub Releases
distribute the cross-platform verification CLI, not the unsigned Tauri desktop
application.
Onboarding writes an encrypted Recovery Kit to Downloads and stores identity/vault
keys in a Stronghold snapshot. After `pnpm demo:up`, the desktop can discover the local
demo from the active clone and send encrypted catalogs, manifests, and chunks to
three separate loopback QUIC storage-node processes. It verifies replica health
and restores from a healthy CID-verified copy. Without that connection it uses
app-local object stores. Neither mode is geographic redundancy.
The Commons screen composes Research through Export, saves only an encrypted
envelope, reloads it after restart and writes a signed portable artifact. It
does not claim that a real TEE ran or that a payment settled. The onboarding
screen can import a Kit from explicitly supplied storage-node
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

## Adopt or continue the project

Anyone can fork under the [MIT license](LICENSE). Start with the accountable
[operator handoff](docs/OPERATOR_HANDOFF.md), [adapter contracts](docs/ADAPTER_CONTRACTS.md),
[incident response runbook](docs/INCIDENT_RESPONSE.md), and
[maintainer succession policy](MAINTAINERS.md). Proposed changes follow
[CONTRIBUTING.md](CONTRIBUTING.md); private vulnerabilities follow
[SECURITY.md](SECURITY.md). The
[Operator adoption issue](.github/ISSUE_TEMPLATE/operator_adoption.yml) is a
public, secret-free declaration of who owns each external responsibility.

The software contracts and local journeys are complete. A real service still
requires an adopter to:

1. run nodes across independent machines, operators and regions;
2. integrate and review real confidential-compute and chosen payment adapters
   against the portable signed contracts;
3. add a deliberately operated relay, monitoring and abuse response;
4. sign, notarize and update desktop distributions;
5. obtain independent cryptography, recovery and data-loss review;
6. prove recovery after the original owner computer is unavailable.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), the
[threat model](docs/THREAT_MODEL.md), and the
[local-network guide](docs/NETWORK_LOCAL.md) before changing security or
protocol behavior.
