# Privacy

Files are encrypted before leaving the owner device. Storage nodes receive opaque,
content-addressed ciphertext and do not receive file names, relative paths,
manifests in plaintext, file keys, vault keys, or recovery secrets. The control
plane receives only coordination metadata.

This does not provide anonymity. Storage providers can observe ciphertext size,
transfer timing, peer identity, and access frequency. The control plane can
observe membership, node ownership, placement relationships, ciphertext sizes,
credit activity, proposals, and votes. Region and failure-domain tags are
intentional metadata. Padding the final chunk does not conceal total file size.

Support bundles use an allowlist and must show the proposed file list before
export. They exclude file-system paths, raw invites, session tokens, keys,
recovery material, user content, and plaintext catalog data.
