# Maintainer and operator stewardship

Arcane Commons Mesh is MIT-licensed: nobody needs permission to fork, operate,
modify, or continue it. The original repository is a reference implementation,
not a promise that its author will operate infrastructure or accept liability.

## Taking responsibility

An adopter should open an **Operator adoption** issue (or use the same checklist
in a fork) naming the deployment, jurisdiction, accountable security contact,
data-retention policy, recovery owner, attestation issuer, settlement operator,
and incident channel. Never put keys, credentials, private reports, or user data
in the issue.

Operators own their infrastructure, legal analysis, user promises, monitoring,
backups, key custody, third-party contracts, incident response and financial
reconciliation. Maintainers own only changes they explicitly review and merge.

## Repository succession

A future maintainer can demonstrate readiness with a sustained record of scoped
reviews, green gates, security handling and release verification. Repository
access is granted by current repository administrators; if they are unavailable,
the MIT license makes a fork the continuity mechanism. Protocol compatibility is
measured by the checked-in conformance journeys, not by repository ownership.

Releases require an intentional version change, a clean commit, all documented
gates, immutable checksums and verification of at least one downloaded archive.
Security-sensitive changes require a decision note describing risk and rollback.
