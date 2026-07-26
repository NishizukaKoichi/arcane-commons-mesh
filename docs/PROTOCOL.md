# Mesh protocol v1

Protocol identifier: `arcane-commons-mesh/1`.

Every request contains a protocol version, opaque request ID, community and node
IDs, operation, optional object CID, issue/expiry times, and a signed membership
credential. Requests live for at most five minutes. Unknown versions, malformed
CIDs, oversized frames, expired requests, wrong-community credentials, and
unauthorized roles fail closed.

Operations are `HELLO`, `HAS_OBJECT`, `PUT_OBJECT`, `GET_OBJECT`,
`AUDIT_OBJECT`, `DELETE_AFTER`, `REPLICATE_OBJECT`, and `PING`.

- Members may connect, ping, inspect availability, and retrieve authorized objects.
- Nodes may accept and replicate ciphertext.
- Auditors may issue bounded ciphertext audits.
- Administrators may request deletion scheduling, but actual deletion additionally
  requires the owner tombstone, retention expiry, and reference check specified in
  ADR 0003.

The native transport is iroh QUIC using the same protocol identifier as ALPN.
Network endpoints prefer direct paths and retain encrypted relay fallback.
Deterministic tests bind only `127.0.0.1`, disable relay and discovery, and pass a
complete endpoint address explicitly, so CI requires no external network.

Every wire frame includes the signed membership credential and a member-signed
node certificate. The receiver binds that certificate's separate endpoint public
key to the authenticated iroh connection before accepting the frame. Frame size,
credential scope, lifetime, role, and object CID are then validated fail-closed.
