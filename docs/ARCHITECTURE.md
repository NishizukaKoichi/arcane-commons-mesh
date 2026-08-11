# Architecture

The owner device is the data, identity and key trust boundary. `mesh-core`
defines cryptography, recovery and the signed Research, Spell, Capability,
Execution, Pensive, Grimoire, Legacy and Federation records. `mesh-protocol`
defines bounded authenticated wire operations. `mesh-node` stores opaque
CID-addressed blobs. `mesh-control` and the Worker/D1 adapter coordinate
membership, placement, governance, audit and encrypted Commons artifacts.

The API is not a decryption authority. It rejects cross-community publication,
future timestamps, invalid Ed25519 signatures and envelope/CID mismatches, and
stores no plaintext or key. Desktop state is XChaCha20-Poly1305 encrypted under
a domain-separated key derived from the Stronghold-held vault master key.
Desktop export emits the same opaque envelope plus the fields and signature
needed by the publication endpoint.

Compute runtimes and payment rails are replaceable adapters. Core verification
binds the chosen runtime measurement and deterministic allocation, but does not
pretend a local attestation is certified hardware evidence or an allocation is
settlement. iroh, Cloudflare and Tauri are replaceable delivery adapters; signed
records, encrypted envelopes and federation bundles remain portable.
