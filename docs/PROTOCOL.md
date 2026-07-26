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

The current acceptance transport is isolated and in-memory. It exercises the same
node and protocol boundaries without relay or Internet access. The iroh QUIC
adapter remains pending; it must bind the transport endpoint key to the signed node
certificate and add per-connection challenge signatures before it is accepted.
