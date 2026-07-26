# Storage Credit / 共有容量

Storage Credit is a non-transferable internal accounting unit:

`1 credit = 1 GiB-hour of physical replicated ciphertext storage`.

The ledger uses signed 64-bit integer `milli_gib_hour`; floating point is
forbidden. Physical cost includes replica count and rounds upward. Every entry has
an idempotency key. Earned credit requires a successful audit in the preceding 24
hours, expires after 90 days, and may be capped by community policy.

Each active member receives a non-rollover monthly base grant equivalent to
5 GiB logical data × 3 replicas × 30 days × 24 hours. Insufficient balance blocks
new uploads but does not immediately delete existing data; the default export
grace period is 30 days.

There is intentionally no transfer, purchase, sale, withdrawal, exchange,
staking, interest, wallet, price, or voting-weight operation.
