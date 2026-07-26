# Arcane Commons Mesh contributor rules

## Canonical workspace

- The only canonical repository is `/Volumes/Pensive/arcane-commons-mesh`.
- Resolve the mount, working directory, and Git root before editing.
- Never fall back to iCloud, Desktop, Documents, Downloads, or `/tmp`.

## Repository layout

- `crates/`: Rust domain, storage, node, CLI, protocol, and testkit code.
- `apps/`: Tauri desktop, Cloudflare Worker API, and public site.
- `packages/`: TypeScript contracts, UI, and shared configuration.
- `docs/`: specifications, decisions, security, recovery, and operations.
- `scripts/`: reproducible demo and MVP verification entry points.

## Required gates

Run `pnpm lint`, `pnpm format:check`, `pnpm typecheck`, `pnpm test`,
`pnpm test:integration`, `pnpm build`, and `pnpm verify:mvp`.
Also run Rust fmt, clippy with warnings denied, tests, and build for the workspace.

## Security invariants

- Never invent cryptography or reuse an AEAD nonce.
- Never log or commit private keys, file keys, recovery material, passphrases,
  raw invite codes, tokens, plaintext file names, paths, or contents.
- Cloudflare stores coordination metadata only, never user blobs or decryption keys.
- Storage credit is integer, non-transferable, non-financial, and never voting weight.
- No real blockchain, wallet, RPC, contract, push, or deployment in v0.1.
- Storage nodes only access an explicitly selected root, reject traversal and links,
  verify CIDs, enforce quotas, and use atomic writes.

## Definition of done

All 25 acceptance criteria in `CODEX_MASTER_PROMPT.md` require evidence. All local
gates must pass, documentation must match behavior, the working tree must be clean,
and an intentional local commit must exist. Do not claim production safety,
complete decentralization, or independent security audit.
