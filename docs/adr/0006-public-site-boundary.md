# ADR 0006: Keep the public site static and non-authoritative

## What changed

The public information surface is a four-page static Astro site. It explains the
project, protocol boundary, current verification status, and local build path.
It contains no account system, coordinator client, telemetry, secrets, or
download claim for an unsigned development artifact.

## Why

The site must make the local MVP understandable without becoming another trusted
service or overstating readiness. Static output can be inspected and hosted by
any provider later, while the repository remains the source of truth.

## Alternatives considered

- A Worker-rendered site was rejected because it adds runtime and deployment
  coupling without improving the current informational surface.
- Publishing the unsigned desktop binary was rejected because there is not yet a
  release signing, update, or independent security-review process.

## Risks and rollback

The hand-written status text can drift from repository evidence. Release work
must update it alongside the acceptance matrix. Rollback is removal of
`apps/site` and the root workspace script entries; no persistent data is stored.
