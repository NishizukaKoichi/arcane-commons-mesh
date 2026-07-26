# Product specification

Arcane Commons Mesh / 魔法網 v0.1 is a members-only cooperative backup MVP.
Owners retain plaintext and recovery keys. Storage providers receive
content-addressed encrypted blobs only. Worker + D1 coordinates membership,
nodes, placements, non-transferable capacity credits, governance, and audits.

Required outcomes are Recovery Kit-gated onboarding, constant-memory file
encryption, three data replicas, five encrypted metadata replicas, outage and
corruption recovery, dedicated quota-bound node storage, audited GiB-hour
credits, and one-member-one-vote governance.

D1 must not contain file names, paths, plaintext, file keys, vault master keys,
or recovery secrets. Nodes contain ciphertext and local SQLite metadata.

There is no cryptocurrency, wallet, exchange, smart contract, live EVM
connection, anonymous public network, Byzantine consensus, mobile app,
cross-user deduplication, or production-security claim in v0.1.

`pnpm verify:mvp` is the canonical offline acceptance path. The evidence mapping
is in `docs/ACCEPTANCE.md`.
