# ADR 0011: v1 reference boundary and encrypted desktop export

Status: accepted for v1 — 2026-08-11

## What changed

The Commons protocol records, encrypted artifact API and eight-stage desktop
journey are one v1 reference implementation. Desktop state is encrypted with a
domain-separated key derived from the existing Stronghold-held vault master key.
Its export uses the API publication envelope and owner-signature format. The
already-workspace-standard `base64` crate is reused for URL-safe transport.

## Why

A UI-only composition would not preserve user state or demonstrate portable
publication. Reusing the vault secret avoids creating a second key lifecycle,
and an API-compatible export keeps the coordinator replaceable.

## Alternatives considered

Plain JSON was rejected because project context is private. A new desktop-only
password store was rejected because it duplicates recovery and rotation. Direct
automatic API upload was deferred because community enrollment and endpoint
choice are deployment-specific authority boundaries.

## Risks and rollback

The local runtime attestation is not certified TEE evidence and allocation is
not payment settlement; UI and documentation state this explicitly. Roll back
by removing the three Tauri commands and Commons envelope file; existing vault
and recovery formats are unchanged.
