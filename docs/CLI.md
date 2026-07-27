# `acmctl`

The CLI shares `mesh-core`, `mesh-control`, `mesh-node`, and `mesh-testkit` with
the desktop. It never accepts a recovery passphrase as an argument or environment
variable. Recovery commands read it from standard input.

Implemented command surface:

```text
acmctl doctor
acmctl identity create
acmctl recovery export <output>
acmctl recovery import <input> [--source <node-root> ...]
acmctl community create
acmctl community join-request
acmctl community approve-member
acmctl community export-snapshot <output>
acmctl community verify-snapshot <input>
acmctl vault create
acmctl vault recover <recovery> --source <node-root> ...
acmctl vault add <path>
acmctl vault list
acmctl vault restore <file-id> <output>
acmctl vault delete <file-id>
acmctl vault gc
acmctl vault verify
acmctl node init <root>
acmctl node run <root>
acmctl node status <root>
acmctl demo up
acmctl demo smoke
acmctl demo down
acmctl demo seed
acmctl verify-mvp
```

Vault commands read the recovery passphrase from standard input, decrypt the local
Recovery Kit, and operate on encrypted catalog, manifest, and chunk replicas.
Recovery with source roots rebuilds a clean local vault and discovers a newer
contiguous signed catalog chain when the external Kit contains an older
checkpoint.
Normal delete writes a 30-day tombstone and remains restorable during retention.
`vault gc` removes expired manifest/chunk replicas and advances the signed
encrypted catalog.
Commands that need initialized identity/catalog/control-plane state fail closed.
`node init` requires a new or empty
dedicated directory. It never scans the home directory or follows an arbitrary
remote path.

`demo smoke` performs a three-node authenticated QUIC write/read/CID round trip
against the running local demo.

`verify-mvp` uses an isolated temporary owner, real storage-node child processes
with separate iroh loopback endpoints for data and recovery metadata, six
in-memory failure domains for model checks, and a clean recovery root. Storage,
outage fallback, corruption rejection, repair, and clean recovery traverse the
QUIC RPC path. It writes a machine-readable summary to
`.verify/verify-mvp-report.json`, which is ignored by Git.
