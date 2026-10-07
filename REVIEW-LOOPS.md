# Accuracy review — trustwright 0.4.1

> **Historical record** of the 0.4.x review loops, written before the rename from authcheck to TrustWright. Platform statements are as of 0.4.2; since 0.4.3 all seven gates pass on Python 3.12, 3.13 and 3.14 (see README "Install and connect").

The review began from the delivered 0.4.0 source. Changes were limited to concrete failures
and their regression guards; M1b execution/import capabilities were not added.

| Loop | Reproduction and correction | Focused result |
|---|---|---|
| 1 | Seven failing probes: false route detection, duplicate-route evidence borrowing, omitted new endpoint, double-redacted location, dot-dot state containment, non-finite JSON, silently skipped directory errors. | All seven passed after fixes. |
| 2 | Four failing probes: source nosemgrep suppression, missing scan targets reported complete, closed-pipe timeout, state larger than its own read cap. | Eleven accumulated regressions passed. |
| 3 | Malformed requests lost their ID; UTF-16 bypassed the intended wire encoding; stale exit-code logs authorized packaging unrelated content. | Fourteen accumulated regressions passed. |
| 4 | A regression in the first source-span fix rejected a valid stacked route; unsupported route forms were still omitted. Added independent-decorator and unrelated-receiver controls. | Eighteen focused regressions/controls passed. |
| 5 | A valid release could still include a local .env and unrelated root files. Restricted archive contents and added a valid-gate packaging privacy regression. | Nineteen focused regressions/controls passed after correction. |

The final pass revisits attribution, discovery, state/confirmation transitions, input parsing,
scanner failure handling, report projection/freshness, and packaging. The release gates also
rerun the pre-existing tests and install the actual wheel in a fresh environment. See
`release-validation/results.json` for source-bound gate results and the corresponding logs.

The source-span regression was found and corrected during this review; passing one loop was
not treated as proof that its fixes preserved every supported case.

## Explicit boundaries

A successful final review is not a proof that the tool or assessed application is secure.
The unresolved boundaries are unchanged: same-user shell access can alter server state;
form approval trusts the MCP client; dynamic/imported/router-level application wiring and
runtime authorization are not established. M1a performs no behavioral tests of user projects.
The release hashes prevent accidental reuse of stale evidence, not forged attestations by
an attacker who controls the release account.

## Verification archive review — 0.4.2

1. Reproduced both supplied attribution cases on 0.4.1 with Opengrep 1.30.0.
   Database dependency injection inferred authenticated intent, and an explicit agent
   binding produced Wiring found without provenance. See verification-before.log.
   Draft policies now stay Unknown; generic dependency links remain Needs review,
   expose their selection origin, and explicitly leave authentication unverified.
2. Reviewed upgrade paths and the portability patch. Historical structural labels
   are projected conservatively without modifying stored records. Kernel stat rejects
   symlink loops even if non-strict resolution tolerates them; permission errors propagate.
   The leakage regression uses a private per-run temporary directory and restores the
   prior environment even on failure.
3. Re-ran supported positive/negative cases, contracts, baseline regressions, MCP/CLI
   integration, package build and fresh-wheel checks. Final outcomes are recorded in
   release-validation/results.json, bound to the final tested source and wheel.

The unchanged uploaded repro stops at the newly refused Unknown-policy confirmation;
seven named regression tests exercise both corrected cases and the adjacent boundaries
without treating that early stop as proof that the second case passed.

Runtime verification uses Python 3.12.14. Python 3.13's permissive-resolve behavior is
simulated explicitly in a regression; this is not a full Python 3.13 compatibility claim.
The supplied M1a brief is preserved verbatim; its older Wiring found label is superseded
by the conservative 0.4.2 display documented in README.md.
