# ADR 0008: Use iroh 1.0.3 with Rust 1.91

## What changed

The native transport uses exact iroh 1.0.3. The workspace and CI toolchain move
from Rust 1.88 to 1.91, the minimum version supported by that iroh release.

## Why

iroh 1.0 is the maintained API line and provides authenticated QUIC, direct-path
selection, and encrypted relay fallback. The last iroh release supporting Rust
1.88 resolves through pre-release cryptography dependencies that no longer
compile together, so retaining 1.88 would require a fragile transitive override.

## Alternatives considered

- iroh 0.95.1 on Rust 1.88 was compiled and rejected after its resolved
  `ed25519-dalek`/PKCS#8 dependency set failed upstream.
- A custom QUIC stack was rejected because it would duplicate iroh's endpoint
  identity, path selection, and relay behavior.

## Risks and rollback

Rust 1.91 raises the contributor toolchain requirement and iroh adds a large
dependency tree. CI pins both. Rollback is removal of the transport module and
iroh/tokio dependencies plus restoration of Rust 1.88.
