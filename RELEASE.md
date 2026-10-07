# Release verification record: authcheck M1a 0.4.2 (historical)

> **Historical record.** This file describes the 0.4.2 release, made before the project was renamed from authcheck to
> TrustWright; identifiers below were updated mechanically by the rename. Its test counts and platform statements are
> 0.4.2 observations. Current state (0.4.3): all seven gates pass on Python 3.12.3, 3.13.16 and 3.14.6 (local run,
> 7 Oct 2026), and CI runs them on 3.12, 3.13 and 3.14. This file is regenerated at the next release (0.5.0).

Implemented against the supplied M1A-BRIEF.md and verified contracts-v0.3.3 archive.
The v1.2 design export was not supplied. Detailed implementation choices and limits
are in README.md and FINDINGS.md.

## Delivered

- Seven stdio MCP tools, four resource types, three prompts.
- FastAPI/PyJWT pack assessment and token-verification recipe.
- Inferred intent, developer form confirmation, separate interactive terminal fallback.
- Server-owned external state with expiring single-use confirmation requests.
- Schema 0.4 migration and report contract with scoped input freshness.
- Unknowns, coverage gaps, historical evidence, redacted output, and no security score.
- Source, installable wheel, CI workflow, pinned Opengrep installer, test fixtures and dependency snapshot.

## Accuracy review

Five correction loops added 19 regression tests and controls. The fixes cover route/evidence
attribution, explicit discovery gaps, strict input and state handling, scanner failures,
and release evidence binding and archive privacy. Reproductions and corrections are recorded
in REVIEW-LOOPS.md; each test is mapped in FINDINGS.md.

The additional verification archive reproduced an attribution overclaim in 0.4.1.
Two correction loops separated dependency references from authentication claims, fixed
historical projection, and hardened baseline symlink and temporary-marker handling.
Seven additional tests cover those boundaries. Drafted intent stays Unknown until the
developer edits and confirms policy; a structural dependency link stays Needs review.
Its origin and unverified authentication semantics are explicit.

The final scoped pass found no further actionable defects in the reviewed paths. This is
not a proof of completeness or security.

## Observed results

| Gate | Result |
|---|---|
| Lint | Passed |
| Trusted demo | Broken token verification accepts expired/forged tokens; fixed recipe passes all four scenarios |
| Contracts + Opengrep 1.30.0 rule tests | Passed: nine example findings, three runs, one pack; exact line matches |
| Baseline regressions | 123/123 rejected for their stated reasons |
| Findings register | 177/177 tests cited, present and passing; no uncited tests |
| M1a acceptance/regressions | 54 passed, including real MCP form elicitation and terminal confirmation |
| Build | Source distribution and wheel built successfully |
| Clean installation | Fresh virtual environment; wheel assets verified outside checkout; all 54 M1a tests passed again |

Machine-readable outcomes and command logs are in release-validation/. SHA256SUMS
covers the files in this ZIP except the checksum list itself. Every release gate is bound
to the tested source digest; build and clean-install gates also bind the wheel digest.
Packaging rejects missing, failed, or stale gate evidence. The external Opengrep
binary is not bundled; its download digest is pinned by tools/install_opengrep.py.

## Limits that remain

POSIX Python 3.11+; Linux x86-64/Python 3.12.14 tested. The permissive-resolve
Python 3.13 edge case is simulated; a full 3.13 runtime suite was not run. Windows users need a POSIX environment
such as WSL. Only the first direct-route FastAPI pack is implemented. No project execution,
behavioral verification, test import, OSV or Gitleaks adapter is exposed in M1a.

An agent with unrestricted shell access as the server's OS user can rewrite state.
Form confirmation trusts the client UI. Reports deliberately omit source text; inspect
the local assessment artifact for original evidence and its reference mapping. No-match
is coverage only, never an assertion of safety.
