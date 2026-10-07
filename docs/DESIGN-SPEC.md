# TrustWright: Design Specification v1.3 (repository copy)

Status: 7 Oct 2026. Supersedes the "authcheck: Design Specification v1.2" Claude Docs document (5 Oct 2026); the
product was renamed from authcheck to TrustWright. Changes since v1.2 are listed at the end. The current milestone gate
is `acceptance/M1A-GATE-REVISION.md`.

**Implemented versus planned.** Everything here describes 0.4.3 as shipped unless marked **(target 0.5.0)**, which
means the revised M1a gate defines it but it is not built yet. Milestone columns mark later work (M1b–M5).

## Overview

TrustWright is an open-source MCP server that lets coding agents check whether a project's authentication, secrets and
cryptography match the developer's stated security intent, then fix gaps with tested recipes.
**Core rule: no conclusion is ever stronger than its evidence.**

**Product statement.** A stack-agnostic MCP toolkit that checks whether a project's authentication and data protection
match its intended security requirements, and provides tested implementation patterns for supported stacks.

**Who it serves.** Beginner developers who don't know how to implement auth correctly (they start from recipes), and
existing projects or repositories that need a guardrail assessment (they start from assessment).

**Workflow.** Detect the stack → draft security intent (every policy starts Unknown) → the developer confirms intent →
run checks → report findings, coverage gaps and Unknowns → retrieve a recipe → (from M1b) verify the fix.

## Design principles

| # | Principle | In practice |
|---|---|---|
| 1 | No conclusion stronger than its evidence | Display labels derived from evidence, never written freely; every non-confirmed finding states its limitations |
| 2 | Intent before assessment; unknown is never permission | An unconfirmed requirement yields Unknown, never a pass or a violation |
| 3 | Static rules triage, behavior proves | Pattern matches flag for review; violations need tests with positive and negative controls |
| 4 | Bind evidence to the exact claim | Finding → requirement → template → every scenario; no cherry-picking; an authentication test cannot prove ownership |
| 5 | Trust is granted, never claimed | Only the server-owned ledger grants Reproduced, Confirmed intent or Human reviewed |
| 6 | Seal content, not pointers | Each ledger entry stores a digest of the exact content it vouches for |
| 7 | Interpret under declared assumptions | A recorded status means something only under the template's response assumptions |
| 8 | Agent-writable input is untrusted wherever it lands | Trace every input to where it is executed, read or parsed; type, escape, cap, refuse |
| 9 | Fail closed | Crashes, timeouts, malformed input and engine errors become reported failures, never passes |
| 10 | Isolate what you execute | Allowlisted environment, no project test config, timeouts, and (from M1b) a sandbox |
| 11 | Every fix leaves a test that names its reason | Regressions assert why they reject; register and suite trace both ways |

## Architecture

```
 Coding agent (MCP client) ──MCP over stdio──▶ TrustWright server (local, Python) ◀── Developer confirms intent
                                               │  tools · resources · prompts — no tool can grant trust
                                               │  Core: contracts, validator, loader, renderer, digests
                                               │  Packs (declarative): rules, templates, recipes, samples
                                               │  Scanners (wrapped, pinned): Opengrep 1.30.0; Gitleaks, OSV (M2)
                                               │  Sandbox runner (M1b): container, no network, caps
                                               │  ★ Trust ledger: server-owned, outside the workspace, content-bound
                                               ▼
                         Workspace (agent-writable, untrusted): project code + .trustwright/
```

A stack-neutral core does the reasoning, declarative packs supply stack knowledge, wrapped scanners do matching, and
(from M1b) a sandbox runs project code. Trust lives in one place: the server-owned ledger.

## Contracts

| Contract | Question | Rules that matter most |
|---|---|---|
| Security intent | What must be protected, from whom? | Policies `public`, `authenticated`, `role`, `owner_of`, `unknown`; provenance `confirmed`/`inferred` granted only by the ledger; one route, one declaration |
| Finding | What was observed, how, and what does it support? | Each method cites only its own evidence type; only behavioral tests or human review can pass; workspace-relative locations only |
| Pack manifest | What does a pack support and what can it prove? | Checks declare `establishes` / `cannot_establish` and ship should-match and should-not-match samples with exact lines |
| Verification run | What ran, where, with what result? | Agent-run results stay Reported; passed/failed scenarios must record a real status |
| Trust ledger | What has the server itself observed? | Observed runs (record digest), intent confirmations (requirement digest and request id), human attestations (subject digest) |
| Report | What is true for the current inputs? | Header lists every assessment input; anything computed from different inputs is historical; no score |

## Display labels

| Display | Means |
|---|---|
| Issue found · Confirmed | A specific-violation rule matched, or an advisory applies to a resolved version |
| Issue found · Reproduced | A server-observed test showed an unauthorized request was granted |
| Check passed · Reproduced | A server-observed test passed every scenario, positive and negative |
| Test passed · Reported | The agent ran the tests; the server did not observe them |
| Needs review · Structurally linked | The route references a dependency; the reference does not establish authentication (`authentication_semantics: unverified`) |
| Needs review · Not linked | The expected reference was not found; not a violation |
| Needs review · Pattern matched | A suspicious pattern was flagged |
| Needs review · Agent assessed | The agent's interpretation, with a cited location (M2) |
| Check passed · Human reviewed | A ledger-backed human attestation (M3) |
| Unknown · Intent missing | The requirement is not confirmed by the developer |
| Unknown · Not assessed **(target 0.5.0)** | Confirmed intent with no applicable or resolvable check; carries a reason |

## Trust and threat model

| Actor | Trust | Contained by |
|---|---|---|
| Server | Trusted; grants trust states | Fails closed; its own inputs typed, capped, refused when malformed |
| Developer | Trusted for intent | Confirms through form elicitation or `trustwright confirm`, bound to requirement digest and one-time request id |
| Coding agent | Untrusted writer | Can only claim trust; schemas, evidence binding and digests reject overclaims |
| Project code | Untrusted, assumed non-adversarial | Never executed in M1a; from M1b only in the sandbox |
| Pack authors | Reviewed contributors | No server hooks; templates run only in the sandbox; pack digest recorded |
| Report consumers | Receivers | Agent text labelled untrusted, capped, kept apart from server facts |

**Not guaranteed:** against a same-user local process (L-01); against adversarial project code under test (L-10); that
free text is truthful (L-13); that a confirmation came from a human. Form elicitation trusts the client (L-14), and the
CLI's terminal check proves a terminal exists, not that a person approved: an agent with shell access can drive it
through a pseudo-terminal. Human-only confirmation needs a channel outside the agent's authority; until then the
ledger's confirmation records the channel, not a verified person.

## MCP surface

Local stdio server, one workspace root, bounded frames (64 KiB) at the boundary. Tools: 7 in M1a, 3 in M1b, 2 in M2,
1 in M3.

| Tool | Does | Milestone |
|---|---|---|
| `detect_stack` | Frameworks, auth libraries, versions and their source, applicable packs, uncovered controls | M1a |
| `draft_intent` | Writes `.trustwright/security-intent.yaml` from discovered routes; every policy `unknown`, every requirement `inferred` | M1a |
| `confirm_intent` | Form elicitation, or a one-time request id for `trustwright confirm` | M1a |
| `validate_intent` | Schema and integrity; effective server-recorded confirmations | M1a |
| `run_checks` | Pack static rules and structural checks on a bounded snapshot; no execution | M1a |
| `get_recipe` | Vetted implementation pattern with tested versions | M1a |
| `get_report` | Report for the current inputs | M1a |
| `generate_tests`, `run_verification`, `submit_test_results` | Test bundles; sandboxed runs (refuse without a sandbox); imported results (always Reported) | M1b |
| `get_review_tasks` / `submit_evidence` | Agent-assisted review where no check applies | M2 |
| `request_human_review` | Developer attestation | M3 |

Resources: `trustwright://controls`, `trustwright://schemas/{name}`, `trustwright://packs/{id}`,
`trustwright://recipes/{pack}/{id}`. Prompts: `assess-project`, `add-auth`, `fix-finding`.

## Verification (M1b, summary)

Three stages: **Prepare** (package index only, pinned hash-verified wheels only; no package or project code runs),
**Snapshot** (copy under the snapshot policy, digest exactly that copy), **Test** (no network; the only stage where
project, dependency and pack test code execute). No unsandboxed fallback. Wheels-only avoids build hooks; it does not
make dependencies trustworthy. Imported agent-run results are always Reported. Detailed sandbox controls will be
specified in the M1b brief. Note for runtime work: from FastAPI 0.141, `include_router` keeps routes inside a private
`_IncludedRouter`, so code that walks `app.routes` for `APIRoute` objects sees none.

## Report contract

Header: report id, time, every assessment input (code, intent, confirmations, check configuration, packs, dependencies,
configuration digests; engine identity; advisory status; **(target 0.5.0)** the interpreter version). Findings with display
labels; a finding computed from different inputs is historical. Coverage: checks with no matches ("does not establish
safety"), controls no pack covers, discovery gaps with reasons, and **(target 0.5.0)** every declared requirement
either as a finding or an Unknown with a reason (in 0.4.3 an unassessed confirmed requirement appears only as an
unreferenced coverage row). Response assumptions, `untrusted_text`, limitations. No score.

## Packs

Packs contain only Opengrep rules, typed test templates, recipes, samples and a manifest; no hooks or scripts. Accepted
only if every check declares `establishes`/`cannot_establish`, ships exact-line samples including near-misses, every
template declares typed placeholders, denied statuses, response assumptions and positive and negative controls, all
paths resolve inside the pack, and contracts and regressions pass.

**First pack `fastapi-pyjwt-pwdlib`:** static rule `verify_signature: False` (triage only); structural check "route
references a dependency"; recipe for token verification (pinned algorithms, required `exp`/`aud`/`sub`, generic 401);
test template (valid, missing, expired, forged token; no redirects followed). **(target 0.5.0)** `APIRouter` discovery,
composed prefixes and `Annotated` aliases (see the gate); 0.4.3 discovers only `@app.<method>` routes declared in the
same file as `app = FastAPI()`. Not yet: ownership template, password-storage checks.

## Quality system

Seven release gates, each bound to the source digest (and the wheel digest for build and clean-room): lint, demo (real
execution of the slice), contracts and rules, regressions (each rejected for its stated reason), register
(traceability), build, clean-room. Process for every change: reproduce, fix the root cause, add a regression that names
its reason, record it in the register, run all gates.

## Limitations

| ID | Limitation | Status |
|---|---|---|
| L-01 | A same-user local process can rewrite server state | M5: separate OS user or signed entries |
| L-02 | Static rules are pattern-local | Inherent; triage only |
| L-03 | Router- and app-level dependencies unresolved | Unresolved in 0.4.3. **(target 0.5.0)** statically resolvable forms; dynamic routing reported unresolved |
| L-04 | Redirect-based auth flows are Unknown | M4: separate template |
| L-05 | ASVS mapping is chapter-level | M4 |
| L-06 | Consistency checks are heuristics | Inherent; never above Reported |
| L-07 | Rule behavior can drift between engine versions | M1a: engine pinned |
| L-08 | No ownership test template | M2 |
| L-09 | Project code executed unsandboxed | Closed in M1b by the sandbox; M1a executes none |
| L-10 | Adversarial project code can lie under test | Inherent to in-process testing; narrowed by M1b, M5 |
| L-11 | Env allowlist strips app configuration | M1b: declared synthetic variables |
| L-12 | Size caps only at `load()` | M1a: caps at the MCP boundary |
| L-13 | Agent text reaches other agents | Mitigated; cannot be closed by the server |
| L-14 | Confirmation channels do not prove a human | Documented boundary (form trusts the client; CLI trusts the terminal) |
| L-15 | Source builds, editable, local or VCS dependencies cannot be verified | Verification yields Unknown |
| R-01 | A dependency reference does not establish authentication | Explicit limitation; enforcement belongs to verification |

**Non-goals:** offensive tooling; auditing other MCP servers; novel cryptography; operating encryption for the user;
an overall score; rebuilding generic SAST or secret scanning.

## Roadmap

| Milestone | Adds | Gate |
|---|---|---|
| M1a (current) | Stdio server, assessment and guidance, no execution (0.4.3); router discovery, aliases, per-requirement Unknowns **(target 0.5.0)** | `acceptance/M1A-GATE-REVISION.md` G1–G6 and all release gates |
| M1b | Sandboxed verification, imported results | Broken code reproduced, fixed code passes, no network |
| M2 | Ownership tests, agent review, OSV and Gitleaks | Cross-user access reproduced on samples and clean on fixed ones |
| M3 | Second stack (Next.js, Better Auth), human review | Same workflow passes without unregistered core changes |
| M4 | Public release: ASVS requirement mapping, benchmark | Benchmark and false-positive rate published, docs complete |
| M5 | Hardening (L-01, L-10) | Closed or explicitly re-accepted |

## Key decisions

Open source, stack-agnostic MCP tools for agents · stack-neutral core with reviewed declarative packs · developer
declares intent, agent may only draft it (inferring intent from code is circular) · confirmation by form elicitation or
a separate CLI, bound to digest and request id · behavioral tests prove, static rules triage · wrap Opengrep, Gitleaks
and OSV with own rules (registry rules are not redistributable) · server-owned ledger with content-bound digests ·
sandbox or no Reproduced result · wheels-only dependency preparation · M1 split into M1a/M1b · imported results always
Reported · isolated test runs · typed, escaping template renderer · no overall score · one combined pack until the second
stack · FastAPI first, Next.js second · local stdio server in Python.

## Changes since v1.2

1. Renamed to TrustWright (package, CLI, `.trustwright/`, `TRUSTWRIGHT_*` variables, `trustwright://` URIs).
2. "Wiring found · Structurally linked" removed (0.4.2): structural links display *Needs review · Structurally linked*
   with `authentication_semantics: unverified` and the binding origin.
3. Every drafted policy starts `unknown` (0.4.2).
4. **Planned (target 0.5.0):** L-03 moves into M1a for statically resolvable routing; "Unknown · Not assessed" added;
   distinct discovery reasons.
5. L-14 restated: neither confirmation channel proves a human.
