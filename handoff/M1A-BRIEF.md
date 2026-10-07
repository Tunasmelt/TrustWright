# authcheck M1a: implementation brief

**Baseline:** contracts v0.3.3 (`contracts-v0.3.3.zip`, SHA-256 in the `.sha256` file) and
design spec v1.2 (the "authcheck: Design Specification" doc; export it as Markdown or PDF).
**Scope:** assessment and guidance only. No test generation, no imported results, no execution.

## Acceptance target

One complete workflow through MCP, against the FastAPI demo project from `tools/demo_slice.py`
(checked in as a test fixture):

> Connect through MCP → detect the stack → draft and confirm intent → run the first pack's checks
> → retrieve a recipe → produce a report with current findings, coverage gaps, and unknowns.

M1a is done when every check below passes, plus all five existing release gates.

| # | Step | Tool | Passes when |
|---|---|---|---|
| 1 | Connect | stdio server | Lists the 7 M1a tools, 4 resource types, 3 prompts; works from a fresh clone |
| 2 | Detect | `detect_stack` | Reports fastapi, pyjwt, pwdlib with versions **and their source** (lockfile / environment / manifest), the matching pack, and controls no pack covers |
| 3a | Draft | `draft_intent` | Writes `.authcheck/security-intent.yaml`; every requirement `inferred`; schema-valid |
| 3b | Confirm | `confirm_intent` | Form elicitation records a ledger confirmation bound to the requirement digest and a one-time request id |
| 3c | Confirm (fallback) | `authcheck confirm <request-id>` | Separate CLI process completes the same request; never uses the server's stdio |
| 3d | No confirmation | (none) | Requirement stays Unknown; no check result is reported against it |
| 4 | Assess | `run_checks` | Static rule → *Needs review · Pattern matched*; structural check → *Wiring found · Structurally linked* or *Needs review · Not linked*; checks with no matches recorded as coverage |
| 5 | Guide | `get_recipe` | Returns `verify-token` for the TOKEN-INTEGRITY finding, with tested versions |
| 6 | Report | `get_report` | Header lists all assessment inputs; findings current vs historical; coverage gaps; Unknowns (e.g. unconfirmed `/exports`); response assumptions; `untrusted_text`; limitations; **no score** |

## New regression cases (minimum)

Each must be rejected or handled for its stated reason, in the existing suite style:

- An agent writing `source: confirmed` (or `confirmed: true`) into the intent file confirms nothing.
- A confirmation for an edited policy, or a replayed or unknown request id, is refused.
- Changing the intent digest after a check makes earlier findings **historical**, not current.
- Oversized or malformed tool input fails closed at the MCP boundary (L-12), with a reason.
- Tool output never returns secret values and wraps agent-authored text as `untrusted_text`.
- A report never sums findings into a score and never states "no matches" as a pass.

## Contract changes (through the findings register)

- **New:** report schema (sixth contract), with assessment inputs and the historical rule.
- **Ledger:** confirmations gain `request_id`; a server-side store of pending requests.
- Bump `schema_version` to 0.4, record each change in `FINDINGS.md`, and keep two-way traceability.

## Explicitly out of scope for M1a

`generate_tests`, `run_verification`, `submit_test_results` (M1b) · OSV and Gitleaks adapters,
agent review tools (M2) · `request_human_review` (M3) · anything that executes project code.

## Pinned now

Opengrep engine version in CI (L-07); caps enforced at the MCP boundary (L-12).
