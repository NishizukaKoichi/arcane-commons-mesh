# Replaceable production adapter contracts

The core protocol does not select a confidential-compute vendor or payment rail.
It defines signed, portable records that adapters must produce. The conformance
journey uses deterministic local issuers; passing it is not provider certification
and does not prove that money moved or confidential hardware executed.

## Confidential compute

An adapter validates the provider's raw quote using the provider's current trust
roots, then issues `ConfidentialRuntimeEvidence`. The record binds its issuer,
provider, quote CID, freshness nonce CID, approved runtime measurement and the
existing `ExecutionAttestation` ID. `ConfidentialRuntimePolicy` rejects expired,
future, untrusted, mismatched or incorrectly signed evidence.

Production adapters must retain the provider quote outside public logs, publish
its CID, make nonce generation replay-safe, document revocation and fail closed
when provider verification is unavailable. A relying community controls its own
trusted issuer keys and approved measurements.

## Settlement

The payer signs a `SettlementInstruction` that binds capability, execution,
currency, exact integer allocations, total, expiry and an idempotency key. A
trusted rail adapter returns a signed `SettlementReceipt` binding the instruction,
hashed external reference, status, amount and time. Settled and reversed receipts
must cover the exact total; failed receipts transfer zero.

Production adapters must enforce the idempotency key at the rail boundary, keep
external transaction identifiers out of public records, reconcile each recipient,
handle reversals as new signed state and never interpret payment as voting power.
Communities choose trusted settlement-operator keys; the repository supplies no
merchant account, money transmitter, wallet or financial guarantee.

Run `pnpm verify:commons` to execute both contracts end to end. Independent
implementations should consume `.verify/verify-commons-report.json` and reproduce
the same validation failures for tampering, untrusted issuers and invalid amounts.
