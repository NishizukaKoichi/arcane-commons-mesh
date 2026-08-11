#!/bin/sh
set -eu

required_files="
LICENSE
CONTRIBUTING.md
SECURITY.md
MAINTAINERS.md
docs/ADAPTER_CONTRACTS.md
docs/INCIDENT_RESPONSE.md
docs/OPERATOR_HANDOFF.md
.github/ISSUE_TEMPLATE/operator_adoption.yml
"

test -s README.md || { echo 'handoff: missing README.md' >&2; exit 1; }

for file in $required_files; do
  test -s "$file" || { echo "handoff: missing or empty $file" >&2; exit 1; }
  grep -Fq "$file" README.md || { echo "handoff: README does not link $file" >&2; exit 1; }
done

grep -Fq 'verify:handoff' package.json || { echo 'handoff: package gate missing' >&2; exit 1; }
grep -Fq 'verify:handoff' .github/workflows/integration.yml || { echo 'handoff: CI gate missing' >&2; exit 1; }
grep -Fq 'ConfidentialRuntimeEvidence' docs/ADAPTER_CONTRACTS.md || { echo 'handoff: compute contract undocumented' >&2; exit 1; }
grep -Fq 'SettlementReceipt' docs/ADAPTER_CONTRACTS.md || { echo 'handoff: settlement contract undocumented' >&2; exit 1; }

git diff --check
echo 'verify:handoff PASS — adoption, operations, security and adapter boundaries are present'
