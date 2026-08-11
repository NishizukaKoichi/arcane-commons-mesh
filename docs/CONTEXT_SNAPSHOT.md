# Current context snapshot

Updated: 2026-08-11

Arcane Commons Mesh v1 is a public MIT-licensed reference implementation for
sovereign encrypted storage, attributable capabilities, bounded automation,
community knowledge, recovery and portable federation. The repository includes
a Rust core and CLI, authenticated three-node local mesh, Worker/D1 coordinator,
Tauri desktop, static information site, protocol fixtures and release automation.

## Reproducible state

- `verify:mvp` proves the fifteen storage, outage, repair, recovery, governance
  and audit acceptance steps.
- `verify:commons` proves the thirteen connected Commons steps, including signed
  confidential-runtime evidence and idempotent settlement receipts.
- `verify:handoff` proves that adoption, adapter, security, maintenance and
  incident ownership documents remain present and linked from the README.
- CI runs code quality, platform build, integration and release workflows.
- GitHub Releases distribute checksum-protected cross-platform `acmctl` archives.

## Boundary between code and operations

The implementation is complete as a reference and handoff. It does not create
independent operators, geographic redundancy, provider trust roots, merchant
accounts, legal authority, code signing or an independent security audit. An
adopter supplies those explicitly and owns the resulting promises. The canonical
route is `docs/OPERATOR_HANDOFF.md`; portable external integration contracts are
in `docs/ADAPTER_CONTRACTS.md`.

## Current rollback posture

Protocol state remains signed and exportable. Local demo data is disposable.
Operators must pin deployments to commits and adapter versions, retain the prior
compatible release, preserve external Recovery Kits and test loss of the original
computer before accepting valuable data.
