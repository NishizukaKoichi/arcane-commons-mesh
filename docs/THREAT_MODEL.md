# Threat model

Status: design and implementation in progress. This is an unaudited MVP.

| Threat | Required control | Current status |
|---|---|---|
| Malicious storage node / modified chunk | CID before decrypt, AEAD, plaintext hash, fallback | partial: CID/AEAD/fallback |
| Compromised control plane | client keys, signed records, linked checkpoints | specified |
| Stolen device | Stronghold/keychain adapter, encrypted recovery, account lock | planned |
| Replay attacker | one-use challenges, request nonce/expiry, certificate binding | credential expiry implemented; API pending |
| Invite brute force | 128-bit code, hash at rest, expiry, attempt limits | planned |
| Traversal/symlink/race | normalized relative paths, no links, root-bound file operations | planned |
| Quota/slowloris/oversize | integer quotas, frame/blob bounds, timeouts/cancellation | local quota implemented; network pending |
| Malicious member/revoked credential | scoped roles, expiry, serial revocation at every entry | signed scope/expiry implemented; revocation pending |
| Colluding nodes/auditor | owner/failure-domain diversity; no self-audit | limited |
| Rollback/fork | monotonic linked pointers and client checkpoints | specified |
| Unauthorized deletion | owner tombstone + retention + reference check | specified |

Storage providers can observe ciphertext size, timing, placement, and access
patterns. The system is not anonymous. Final-chunk padding does not hide total
file size. A single-machine three-process demo proves process-failure recovery,
not geographic independence. Full-blob sampling is not proof of retrievability
and remains susceptible to collusion and timing strategies.

Secrets never enter logs, diagnostics, D1, node metadata, environment arguments,
or support bundles. Parsers reject unknown versions, excessive KDF parameters,
oversized objects, trailing recovery bytes, and malformed encodings.
