# Recovery

Recovery files use Argon2id and XChaCha20-Poly1305. Defaults are 256 MiB memory,
three iterations, one lane, a 16-byte random salt, 24-byte random nonce, and
32-byte output. Import enforces safe lower and upper bounds before allocating.
The complete public header is AAD.

Exports use create-new mode, mode 0600, and refuse to overwrite. After catalog
changes, the active kit is atomically refreshed with the vault ID, latest
encrypted catalog CID/version, and owner public key. The CLI and
desktop do not place passphrases in argv or environment; the desktop retains the
unlocked passphrase in renderer memory for the active session. Signed federation
export moves portable community records to a named successor, but production key
custody and legal authority transfer remain operator governance duties. The deterministic recovery test
starts without identity or catalog cache, discovers the catalog from the
encrypted kit pointer, retrieves catalog/manifest/chunks from child storage-node
processes, and verifies AEAD, owner signature, domains, CIDs, lengths, and final
plaintext hash.

An older external Kit remains usable: `acmctl recovery import --source ...` and
the desktop import screen scan supplied storage-node roots for a contiguous,
owner-signed catalog chain newer than the Kit checkpoint. They rebuild state,
secrets, catalogs, manifests, and chunk replicas.

The desktop does not discover geographically remote nodes automatically. The
user must supply mounted/exported storage-node roots during import. Its default
local object stores are lost with the Mac, so the desktop artifact must not be
presented as device-loss-safe without independently hosted node roots.
