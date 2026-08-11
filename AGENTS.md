# Arcane Commons Mesh contributor rules

## Canonical workspace

- Treat the resolved Git root of the active clone as the canonical repository.
- Resolve the working directory and Git root before editing.
- Never combine files from multiple clones, archives, or backup copies.

## Repository layout

- `crates/`: Rust domain, storage, node, CLI, protocol, and testkit code.
- `apps/`: Tauri desktop, Cloudflare Worker API, and public site.
- `packages/`: TypeScript contracts, UI, and shared configuration.
- `docs/`: specifications, decisions, security, recovery, and operations.
- `scripts/`: reproducible demo and MVP verification entry points.

## Required gates

Run `pnpm lint`, `pnpm format:check`, `pnpm typecheck`, `pnpm test`,
`pnpm test:integration`, `pnpm build`, `pnpm verify:mvp`,
`pnpm verify:commons`, and `pnpm verify:handoff`.
Also run Rust fmt, clippy with warnings denied, tests, and build for the workspace.

## Security invariants

- Never invent cryptography or reuse an AEAD nonce.
- Never log or commit private keys, file keys, recovery material, passphrases,
  raw invite codes, tokens, plaintext file names, paths, or contents.
- Cloudflare stores coordination metadata only, never user blobs or decryption keys.
- Storage credit is integer, non-transferable, non-financial, and never voting weight.
- No real blockchain, wallet, RPC, merchant account, or provider trust root is
  supplied by the reference implementation.
- Never deploy, push, or create paid infrastructure without the current user's
  explicit authorization.
- Storage nodes only access an explicitly selected root, reject traversal and links,
  verify CIDs, enforce quotas, and use atomic writes.

## Definition of done

All acceptance journeys require evidence. All local gates must pass,
documentation must match behavior, the working tree must be clean,
and an intentional local commit must exist. Do not claim production safety,
complete decentralization, or independent security audit.
