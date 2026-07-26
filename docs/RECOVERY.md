# Recovery

Recovery files use Argon2id and XChaCha20-Poly1305. Defaults are 256 MiB memory,
three iterations, one lane, a 16-byte random salt, 24-byte random nonce, and
32-byte output. Import enforces safe lower and upper bounds before allocating.
The complete public header is AAD.

Exports are atomic, mode 0600, and refuse to overwrite. Passphrases are never
stored, logged, placed in argv/environment, or copied automatically. Community
authority recovery is an explicit separate export because it grants membership
issuance power. A new device verifies AEAD, linked catalog state where available,
chunk CIDs, plaintext lengths, padding, and final plaintext hashes.
