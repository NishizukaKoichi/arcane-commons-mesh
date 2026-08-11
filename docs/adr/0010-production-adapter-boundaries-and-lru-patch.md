# ADR 0010: portable adapter evidence and transitive LRU patch

Status: accepted — 2026-08-11.

## What changed

The core now verifies provider-neutral signed confidential-runtime evidence and
settlement instructions/receipts. The lockfile also advances transitive `lru`
from 0.18.1 to 0.18.2 while retaining pinned `iroh` 1.0.3.

## Why

External operators need stable conformance boundaries without being forced into
one TEE vendor or payment rail. RustSec reported an unsoundness warning in
`lru` 0.18.1 reached through `iroh-relay`; 0.18.2 is API-compatible, supports the
workspace Rust version and removes that advisory.

## Alternatives considered

Embedding a provider SDK or payment API would couple policy and credentials to
the reference core. Leaving `lru` unchanged would preserve the lockfile but retain
an avoidable warning on the network path.

## Risk and rollback

Adapters can still mis-verify raw vendor evidence, so communities explicitly
trust issuer keys and must audit adapters. Roll back the new record types and
conformance steps together before any external implementation depends on them;
the dependency patch can be reverted independently if upstream incompatibility
appears. Signed v1 records remain unchanged.
