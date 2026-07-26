# ADR 0003: Cryptographic protocol bindings

Status: accepted — 2026-07-26.

Signed objects use deterministic canonical bytes, a schema version, and a unique
ASCII domain such as `acm.membership.v1`, `acm.node-cert.v1`, or
`acm.catalog-pointer.v1`. Domains, community, issuer, subject, serial/version,
expiry, and previous hash are signed. Unknown versions fail closed; JSON text is
never signed directly.

Vault keys derive purpose-separated manifest and catalog wrapping keys using
BLAKE3 derive-key contexts. Each AEAD envelope binds its version, algorithm,
object kind, vault, version, owner, and lengths as AAD and uses a fresh 24-byte
OS-random nonce. Ciphertext envelopes are signed where owner authenticity is
required.

Catalog pointers are monotonic and link the previous pointer. Clients persist the
last checkpoint and reject rollback or same-version forks. A clean recovery on a
new device cannot independently detect a control plane that withholds all newer
history; this remains a documented v0.1 limitation.

Deletion requires an owner-signed tombstone bound to vault/version/object,
retention expiry, and a fresh reference check. A control-plane signature alone
cannot authorize deletion.
