# v0.1 acceptance evidence

| ID | Condition | Evidence |
|---:|---|---|
| 1 | Canonical Pensive repository | resolved mount and Git-root checks |
| 2–9 | all quality/build gates | root package scripts and CI |
| 10–13 | MVP, replicas, outage, corruption | `verify:mvp` steps 3–8 |
| 14 | clean Recovery Kit recovery | step 13: kit identity/key → control-plane latest pointer → process-node catalog → manifest → chunks; stale-kit recovery remains valid after GC |
| 15–17 | no control-plane plaintext/key access | actual local D1 files plus in-memory/process-node storage scans |
| 18–20 | no transfer; equal voting | API route and duplicate-vote tests |
| 21 | no live blockchain | interface/mock source test and source scan |
| 22 | no committed secrets | tracked-file secret scan |
| 23 | no external deployment | local-only verification |
| 24 | honest threat model | `docs/THREAT_MODEL.md` |
| 25 | reproducible demo | README demo and verification commands |

The final gate run records command results and the exact local commit. Passing
these local tests is not an independent security audit.
