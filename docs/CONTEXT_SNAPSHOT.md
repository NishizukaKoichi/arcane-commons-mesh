# Context snapshot

- Date: 2026-08-11
- Scope: publicly downloadable v0.1 CLI distribution and verifiable handoff
- Canonical repo: resolved Git checkout, `main`
- Source of truth: `CODEX_MASTER_PROMPT.md`, running code, ADRs, and this snapshot

## Goal and success criteria

Make the completed local Commons Kernel / Mesh proof usable from GitHub without
requiring every evaluator to compile Rust. Platform archives must be built from
an immutable tag, accompanied by SHA-256 checksums, and preserve the project's
honest research-MVP boundary.

Out of scope: geographic redundancy, public relay deployment, NAT traversal,
production membership enrollment, and proof of surviving loss of this Mac.

## Current state

The v0.1 crypto, storage, control plane, desktop, recovery, authenticated QUIC
mesh, public MIT handoff, and local acceptance suite exist on `main`. GitHub CI
is green and the repository is public. This milestone adds tag-driven GitHub
Release builds for macOS (Apple silicon and Intel), x86-64 Linux, and x86-64
Windows, with one checksum per immutable archive and public installation docs.

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
- 2026-08-11: distribute only the CLI in v0.1. The Tauri desktop remains a local
  development artifact until OS signing, notarization, update infrastructure,
  and the transitive Linux GTK security warnings are resolved. Alternative:
  publish unsigned desktop bundles. Risk: users could mistake them for a
  production-safe backup product. Rollback: remove the release workflow before
  tagging; published releases are corrected with a new patch tag, never replaced.
- 2026-08-11: pin patched transitive JavaScript dependencies with narrow pnpm
  overrides after the release audit found four high-severity advisories. Updating
  top-level frameworks did not move their lockfile selections. Risk: a transitive
  compatibility regression; mitigation and rollback: all workspace gates run
  against the overrides, and removing the override block restores prior resolution.

## Next boundary

The next separate milestone is production membership issuance and independently
hosted node endpoints. It requires another machine or a consciously selected
hosted environment to prove device-loss recovery. Research Commons,
Compute-to-Data, Spell Commons, and Capability Exchange remain later protocol
phases and are not represented as implemented by this v0.1 release.

## Arcane Commons v1 work in progress — 2026-08-11

The next implementation line now has executable protocol primitives for signed
research causal records, scoped and expiring Spell contracts, portable Capability
Manifests with exact non-governance revenue allocation, measured execution
attestations, provenance-aware Pensive entries and grants, and time-locked
multi-guardian Legacy directives. `pnpm verify:commons` exercises nine connected
steps and writes machine-readable evidence.

This is an intentionally committed intermediate boundary, not a v1 completion
claim. Grimoire quorum confirmation and signed federation export/import are now
implemented at the protocol layer. Persistent API/UI journeys, real payment
adapters, real confidential-compute attestation, integrated Mesh storage, and
end-to-end release verification remain required.
