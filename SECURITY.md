# Security policy

This repository is an unaudited reference implementation. Do not use it as the sole copy of valuable
data. Report vulnerabilities through GitHub's private vulnerability reporting
for this repository. If that feature is unavailable, open an issue containing
no exploit details and ask the maintainer for a private channel. Never attach
recovery files, passphrases, private keys, raw invite codes, or user data.

The security boundary and known limitations are documented in
`docs/THREAT_MODEL.md`.

The release gate fails on high-severity npm advisories. At the v1 handoff, npm
still reports lower-severity transitive advisories and RustSec reports warnings,
including the transitive Tauri Linux GTK3/`glib` path. These are known review
items, not a claim of a clean independent audit. Every operator must rerun both
audits, evaluate its actual target platforms and record any exception before a
deployment. See `docs/INCIDENT_RESPONSE.md` for operational response.
