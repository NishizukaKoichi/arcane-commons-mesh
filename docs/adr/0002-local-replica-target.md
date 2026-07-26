# ADR 0002: Local replica target

Status: accepted for local v0.1 — 2026-07-26.

The prompt defines three demo storage nodes but asks manifests and catalogs to
target five distinct replicas. Five distinct placements cannot be demonstrated on
three nodes.

The local MVP therefore uses three physical placements for data, encrypted
manifests, and encrypted catalogs. The format retains a configurable desired
replica count, and production policy remains five for manifest/catalog. This keeps
the acceptance demo internally consistent without pretending that processes on
one host are independent failure domains. Rollback: add two demo nodes and set
the local metadata targets to five.
