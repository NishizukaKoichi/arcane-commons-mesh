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

## Commons records

Commons v1 records are domain-separated Ed25519-signed canonical structures.
Research records form an ordered causal graph. Spells authorize only the named
action, data scope, subject, budget, invocation count and time window.
Capabilities bind a package/policy CID and a normalized 10,000-bps creator
split. Execution attestations bind the capability, spell, runtime measurement,
input CIDs and output CID. Confidential-runtime evidence additionally binds a
trusted issuer, provider, raw-quote CID, freshness nonce, measurement, execution
and validity window. Settlement instructions bind the payer, capability,
execution, exact allocations, currency, idempotency key and expiry; trusted
operator receipts bind the rail, hashed external reference, status, exact amount
and time. Pensive grants bind memory access to domain, purpose,
read/write limits and time. Grimoire ratification counts distinct eligible
signers. Legacy execution requires its time lock and distinct guardian
threshold. Federation exports bind ordered items through a Merkle root and are
accepted with a signed destination receipt.

The API publication envelope is signed over
`acm.commons-artifact.v1|communityId|artifactId|kind|envelopeCid|createdAt`.
The coordinator verifies that signature and BLAKE3 CID but cannot decrypt the
envelope.
