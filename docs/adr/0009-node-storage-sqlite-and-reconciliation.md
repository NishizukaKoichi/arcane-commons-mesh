# ADR 0009: Node storage SQLite metadata and startup reconciliation

## What changed

Storage nodes keep cumulative object-size metadata in a local SQLite database. Startup removes incomplete `.partial` writes and rebuilds the metadata table from valid content-addressed blobs.

## Why

Per-object quota checks allowed cumulative usage to exceed the configured limit. A crash between file and database updates also needs a deterministic, local recovery path.

## Alternatives considered

- A JSON index is simpler but has weaker concurrent update and crash behavior.
- Trusting only directory scans avoids a database but does not satisfy the required node metadata database boundary.

## Risks and rollback

Startup reconciliation reads every stored blob and may be slow for large stores; v0.1 favors integrity over startup speed. Roll back by removing `rusqlite` and this metadata layer while retaining the content-addressed layout.
