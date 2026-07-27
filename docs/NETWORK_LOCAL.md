# Single-Mac authenticated QUIC mesh

## When to use

Use this runbook to exercise the real node transport on one Mac before adding
independent machines. Do not use it as evidence of geographic redundancy,
device-loss survival, NAT traversal, or public relay availability.

## Architecture

`pnpm demo:up` starts three storage-node child processes and one auditor. Every
process owns:

- a dedicated storage root under ignored `.demo/nodes/<node>`;
- a distinct iroh endpoint bound to loopback;
- a durable SQLite request-replay database;
- a CID-verifying, quota-enforcing object store.

The demo bootstrap registers the actual iroh endpoint IDs in local D1.
Requests use the `arcane-commons-mesh/1` ALPN and bind the community membership
credential, node certificate, remote endpoint ID, request ID, operation, object
CID, payload CID, and expiry. Object bytes are base64url encoded inside the
bounded JSON wire frame; the maximum encrypted object remains 4 MiB plus
protocol overhead.

## Procedure

```sh
pnpm demo:up
curl --fail http://127.0.0.1:8787/health
pnpm demo:smoke
pnpm demo:down
```

Expected smoke evidence:

```text
transport=iroh-quic-loopback-authenticated
replicas=3/3
round_trip=pass
plaintext_sent=false
```

For the destructive fault matrix in an isolated temporary environment:

```sh
pnpm verify:mvp
```

That command kills one node process, corrupts one stored blob, restores through
another endpoint, repairs a replacement replica over QUIC, and reconstructs the
vault from a Recovery Kit.

## Verification

- Node endpoint files exist only while the ignored demo is running:
  `.demo/nodes/*/network-endpoint.json`.
- `pnpm demo:down` stops recorded processes and removes `.demo`.
- `pnpm verify:mvp` writes ignored evidence to
  `.verify/verify-mvp-report.json`.

## Rollback and limitations

Run `pnpm demo:down`; no external service or account is changed. All endpoints
are loopback-only and relay-free. The desktop vault still uses local object
stores and does not yet discover these demo endpoints, so this milestone proves
the reusable node transport and recovery path rather than full desktop
device-loss safety.
