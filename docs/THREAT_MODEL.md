# Threat model

Status: locally verified, unaudited v0.1 MVP. It is not approved for the only
copy of valuable data.

| Threat | Required control | Current status |
|---|---|---|
| Malicious storage node / modified chunk | CID before decrypt, AEAD, plaintext hash, fallback | implemented and tested locally |
| Compromised control plane | client keys, signed records, linked checkpoints | keys excluded; membership, node, vote, and catalog records signed |
| Stolen device | Stronghold, encrypted Recovery Kit, account lock | Stronghold and Recovery Kit implemented; OS-session compromise remains |
| Replay attacker | one-use challenges, request nonce/expiry, certificate binding | D1 and iroh replay checks implemented |
| Invite brute force | random code, hash at rest, expiry, attempt limits | hash/expiry/one-use implemented; rate limiting remains deployment work |
| Traversal/symlink/race | no links, root-bound operations, atomic write | implemented for node/object paths; platform filesystem races still require audit |
| Quota/slowloris/oversize | cumulative integer quota, frame/blob bounds, timeouts | implemented; production load testing remains |
| Malicious member/revoked credential | scoped roles, expiry, session revocation | implemented at API and transport boundaries |
| Colluding nodes/auditor | owner/failure-domain diversity; no self-audit | limited |
| Rollback/fork | monotonic linked pointers and client checkpoints | linked catalog pointers implemented; independent gossip is not |
| Unauthorized deletion | owner tombstone + retention + reference check | local tombstone implemented; distributed signed GC remains incomplete |

Storage providers can observe ciphertext size, timing, placement, and access
patterns. The system is not anonymous. Final-chunk padding does not hide total
file size. A single-machine three-process demo proves process-failure recovery,
not geographic independence. Full-blob sampling is not proof of retrievability
and remains susceptible to collusion and timing strategies.

Identity and vault keys are stored in Stronghold and the encrypted Recovery Kit;
they are not columns in D1 or node SQLite. Passphrases are accepted through
desktop input or CLI standard input, never CLI arguments or environment
variables. The desktop currently keeps its unlocked passphrase in renderer
memory for the active app session; a renderer compromise can therefore steal it.

Parsers reject unknown versions, excessive KDF parameters, oversized objects,
trailing recovery bytes, malformed encodings, symlink storage roots, and invalid
CIDs. The local process demo does not prove NAT traversal, relay availability,
geographic diversity, resistance to coordinated operators, or production
availability.
