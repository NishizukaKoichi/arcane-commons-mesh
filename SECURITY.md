# Security policy

This repository is an unaudited MVP. Do not use it as the sole copy of valuable
data. Report vulnerabilities through GitHub's private vulnerability reporting
for this repository. If that feature is unavailable, open an issue containing
no exploit details and ask the maintainer for a private channel. Never attach
recovery files, passphrases, private keys, raw invite codes, or user data.

The security boundary and known limitations are documented in
`docs/THREAT_MODEL.md`.

The latest local dependency audit found no known npm or Rust vulnerability
advisories. RustSec did report maintenance warnings in transitive Tauri Linux
GTK3 dependencies and an unsoundness warning for transitive `glib` 0.18.5.
These are release-blocking review items for a Linux distribution, even though
the macOS MVP does not execute that GTK path.
