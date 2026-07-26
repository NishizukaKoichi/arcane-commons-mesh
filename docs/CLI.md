# `acmctl`

The CLI shares `mesh-core`, `mesh-control`, `mesh-node`, and `mesh-testkit` with
the desktop. It never accepts a recovery passphrase as an argument or environment
variable. Recovery commands read it from standard input.

Implemented command surface:

```text
acmctl doctor
acmctl identity create
acmctl recovery export <output>
acmctl recovery import <input>
acmctl community create
acmctl community join-request
acmctl community approve-member
acmctl community export-snapshot <output>
acmctl community verify-snapshot <input>
acmctl vault create
acmctl vault add <path>
acmctl vault list
acmctl vault restore <file-id> <output>
acmctl vault verify
acmctl node init <root>
acmctl node run <root>
acmctl node status <root>
acmctl demo up
acmctl demo down
acmctl demo seed
acmctl verify-mvp
```

Commands that need initialized identity/catalog/control-plane state fail closed or
report the missing local prerequisite. `node init` requires a new or empty
dedicated directory. It never scans the home directory or follows an arbitrary
remote path.

`verify-mvp` uses an isolated temporary owner, four local node roots, a clean
recovery root, and the in-memory offline transport. It writes a machine-readable
summary to `.verify/verify-mvp-report.json`, which is ignored by Git.
