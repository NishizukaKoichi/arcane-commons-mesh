# Operator handoff

This is the shortest accountable path from a public fork to an operated system.
It deliberately separates complete software boundaries from external choices
that only a real operator can make.

## 1. Establish accountability

Name the legal/operator entity, jurisdiction, security contact, privacy and
retention rules, incident channel, recovery owner and user-facing service limits.
Open the Operator adoption checklist without secrets. Decide which community
constitution and governance rules apply.

## 2. Reproduce the baseline

Use the pinned Node, pnpm and Rust versions. Run `pnpm install --frozen-lockfile`,
then every command under **Verify locally** in the README. Preserve the generated
non-secret reports and the commit SHA. Do not proceed on a red gate.

## 3. Replace local boundaries

- Run storage nodes on independently administered machines and failure domains.
- Implement a confidential-compute adapter using `docs/ADAPTER_CONTRACTS.md`.
- Implement a settlement adapter only if paid capabilities are offered.
- Configure authenticated coordination, relay, monitoring and abuse response.
- Generate separate production keys; never reuse demo seeds or checked-in data.
- Provide external, tested recovery copies before accepting valuable data.

## 4. Prove operations

Exercise node loss, coordinator loss, stale and revoked attestation keys, duplicate
settlement delivery, reversal, operator-key compromise and recovery without the
originating computer. Record recovery time and data-loss results. Obtain an
independent review of cryptography, privacy claims and operator procedures.

## 5. Release with rollback

Pin the deployment to a reviewed commit and adapter versions. Stage a small
non-critical community first. Monitor availability, restore success, evidence
expiry, settlement reconciliation and security reports. Keep the prior compatible
release and encrypted backups until the rollback window closes.

The reference repository does not deploy, custody keys, operate nodes, settle
payments or make legal promises for adopters. Those are explicit operator duties.
