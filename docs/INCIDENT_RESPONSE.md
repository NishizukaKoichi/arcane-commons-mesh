# Incident response

Operators must publish a private reporting channel and name an incident lead
before launch. Never place secrets, recovery material, provider quotes, personal
data or exploit details in public issues.

## Severity and first response

- **Critical:** key or plaintext exposure, forged authority, unrecoverable loss,
  incorrect settlement, or active remote compromise. Stop affected writes and
  financial actions, preserve evidence, rotate/revoke through documented custody,
  and notify affected communities.
- **High:** sustained loss of quorum, invalid attestation acceptance, widespread
  restore failure or bypass of authorization. Isolate the boundary and disable the
  affected capability.
- **Medium/Low:** contained degradation or non-sensitive defect. Track, patch and
  verify through normal release gates.

## Runbooks

- **Storage node:** remove it from placement, verify healthy CIDs, repair to a new
  independently controlled node, then reconcile quota and audit history.
- **Identity or operator key:** distrust the public key, halt dependent issuance,
  identify the last trusted record, rotate under the community process and replay
  verification from that point. Never silently rewrite history.
- **Attestation provider:** stop accepting new evidence, update trust roots and
  measurements after review, then expire or explicitly revoke affected work.
- **Settlement:** freeze retries, reconcile by instruction idempotency key, issue
  signed failure/reversal state, and use the rail's regulated dispute process.
- **Coordinator/relay:** nodes and encrypted data remain authoritative; restore a
  clean coordinator and validate signed state rather than copying mutable caches.
- **Data loss:** restore from an external Recovery Kit and independent node roots;
  record which CIDs are unavailable and do not claim recovery that was not tested.

Close an incident only after containment, integrity verification, recovery,
community notification, a written timeline and a tested corrective action. Keep
evidence access-limited according to jurisdiction and retention policy.
