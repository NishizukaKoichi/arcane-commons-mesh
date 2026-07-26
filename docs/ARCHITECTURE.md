# Architecture

The owner device is the data and key trust boundary. `mesh-core` owns encryption,
identity, recovery, audit, credit, and vault formats. `mesh-protocol` defines the
bounded authorized wire operations. `mesh-node` stores opaque CID-addressed blobs
inside a selected root. `mesh-testkit` provides the offline acceptance transport.

`mesh-control` is an exchangeable coordination model for membership, nodes,
objects, placements, catalog checkpoints, credit, proposals, votes, audit events,
and versioned community snapshots. It contains no file body, plaintext file name
or path, file key, vault key, or recovery secret. The Cloudflare Worker/D1 adapter
must preserve this boundary.

The desktop application and `acmctl` are clients of these shared Rust components,
not parallel implementations. iroh and Cloudflare are adapters; neither is the
sole source of data ownership or decryption authority.
