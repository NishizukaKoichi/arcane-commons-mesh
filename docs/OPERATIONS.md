# Local operations

## Control plane

Install dependencies with `pnpm install`. Validate the Worker without deployment:

```sh
pnpm --filter @arcane-commons/api typecheck
pnpm --filter @arcane-commons/api test
pnpm --filter @arcane-commons/api build
```

The build uses Wrangler `--dry-run`; it does not deploy. Local D1 migrations live
in `apps/api/migrations`. The internal anchor endpoint is hidden unless the exact
local internal secret header is configured. Never place community, identity, or
vault private keys in Worker secrets.

## Incident defaults

- Disable new placement to a node after five minutes without heartbeat.
- Create repair candidates after 24 hours offline.
- Do not delete data because credit is insufficient; stop new uploads and retain
  the export window for at least 30 days.
- Treat a CID mismatch as a failed placement, preserve a redacted audit event,
  and restore from another healthy replica.
- Never include recovery files, passphrases, tokens, raw invites, paths, or
  contents in diagnostics.
