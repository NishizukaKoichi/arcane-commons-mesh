# Threat model

Status: locally verified, unaudited v1 reference implementation. It is not approved for the only
copy of valuable data.

| Threat | Required control | Current status |
|---|---|---|
| Malicious storage node / modified chunk | CID before decrypt, AEAD, plaintext hash, fallback | implemented and tested through separate QUIC node processes |
| Compromised control plane | client keys, signed records, linked checkpoints | keys excluded; membership, node, vote, and catalog records signed |
| Stolen device | Stronghold, encrypted Recovery Kit, account lock | Stronghold and Recovery Kit implemented; OS-session compromise remains |
| Replay attacker | one-use challenges, request nonce/expiry, certificate binding | D1 and every public iroh transport constructor require persistent replay state |
| Invite brute force | random code, hash at rest, expiry, attempt limits | hash/expiry/one-use implemented; rate limiting remains deployment work |
| Traversal/symlink/race | no links, root-bound operations, atomic write | implemented for node/object paths; platform filesystem races still require audit |
| Quota/slowloris/oversize | cumulative integer quota, frame/blob bounds, timeouts | implemented; production load testing remains |
| Malicious member/revoked credential | scoped roles, expiry, session revocation | implemented at API and transport boundaries |
| Colluding nodes/auditor | owner/failure-domain diversity; no self-audit | limited |
| Rollback/fork | monotonic linked pointers and client checkpoints | linked catalog pointers implemented; independent gossip is not |
| False audit/repair claim | node-key signature plus ciphertext/CID proof bound to task challenge | D1 route implemented and integration-tested; this is full-blob possession-at-check, not a compact proof of retrievability |
| Unauthorized deletion | owner tombstone + retention + reference check | local tombstone, retained restore, and explicit CLI GC implemented; catalog history is retained so stale Recovery Kits remain usable; distributed signed GC remains incomplete |

Storage providers can observe ciphertext size, timing, placement, and access
patterns. The system is not anonymous. Final-chunk padding does not hide total
file size. A single-machine multi-process demo proves process-failure recovery,
not geographic independence. When connected, the desktop uses three separate
loopback QUIC node processes; otherwise it falls back to app-local object stores.
Neither mode survives loss of that device. Full-blob
sampling is not proof of retrievability
and remains susceptible to collusion and timing strategies.

Identity and vault keys are stored in Stronghold and the encrypted Recovery Kit;
they are not columns in D1 or node SQLite. Passphrases are accepted through
desktop input or CLI standard input, never CLI arguments or environment
variables. The desktop currently keeps its unlocked passphrase in renderer
memory for the active app session; a renderer compromise can therefore steal it.

Parsers reject unknown versions, excessive KDF parameters, oversized objects,
trailing recovery bytes, malformed encodings, symlink storage roots, and invalid
CIDs. QUIC requests bind the membership credential and node certificate to the
client endpoint, request ID, operation, object CID, payload CID, and expiry.
Responses are bound to the request ID and payload CID over the authenticated
endpoint connection. The local process demo does not prove NAT traversal, relay availability,
geographic diversity, resistance to coordinated operators, or production
availability.
