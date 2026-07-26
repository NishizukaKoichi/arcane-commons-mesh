# ADR 0007: Pin CI actions and isolate deployment authority

## What changed

All third-party GitHub Actions are referenced by full commit SHA with the reviewed
release noted in a comment. Node, pnpm, Rust, Ubuntu, macOS, and cargo-audit are
version-pinned. Checkout does not retain write credentials.

The Cloudflare workflow only accepts manual dispatch, targets a protected
`production` environment, has read-only repository permissions, and requires
repository secrets. Push and pull-request events cannot deploy.

## Why

Mutable major tags allow action code to change without a repository diff.
Deployment credentials also require a separate human approval boundary from
ordinary validation.

## Alternatives considered

- Major action tags were rejected because they are mutable.
- Automatic deployment from `main` was rejected because this MVP has no
  authorization to deploy and no production-readiness claim.

## Risks and rollback

Pinned actions and runners require deliberate maintenance. A compromised pinned
commit remains a risk, so updates must re-check release provenance. Rollback is a
revert of the workflow/ADR commit; no workflow was executed during implementation.
