# Changelog

## Unreleased (toward 0.5.0)

- T-03 (TW-04): every declared requirement appears once in `get_report`; confirmed requirements no check assessed
  are *Unknown · Not assessed* with a reason. Endpoint coverage rows carry the requirement reference.
- T-04 (TW-05): discovery problems carry distinct reasons; `source_parse_error` names the interpreter version.
- Report contract 0.5.0 (TW-06). Fixture checksums checked by the test suite (TW-03).

## 0.4.3: renamed to TrustWright

- Project renamed from authcheck to **TrustWright**: package `trustwright`, CLI `trustwright`, distribution
  `trustwright-mcp`, workspace folder `.trustwright/`, state directory `~/.local/share/trustwright`, environment
  variables `TRUSTWRIGHT_STATE_DIR` and `TRUSTWRIGHT_OPENGREP`, resource URIs `trustwright://`.
- No behavior change. Report schema and pack versions stay 0.4.2. `handoff/` keeps the original brief verbatim.
- Acceptance fixtures added under `acceptance/` for the revised M1a gate (see `acceptance/M1A-GATE-REVISION.md`).
- Added `AGENTS.md`, `docs/DESIGN-SPEC.md` (v1.3), `.gitattributes` (LF line endings) and a CI matrix for Python 3.12, 3.13 and 3.14.
- Register rows TW-01 and TW-02 in `FINDINGS.md`.

## 0.4.2: verification corrections

- Draft all endpoint policies as Unknown; dependency injection does not infer authentication.
- Structural links remain Needs review and expose binding source plus unverified auth semantics.
- Apply conservative display to old structural reports without rewriting stored history.
- Detect symlink loops independently of Python non-strict resolution behavior.
- Isolate regression leakage markers per run and restore environment on failure.
- Seven new regression tests. Report schema version 0.4.2.

## 0.4.1: iterative accuracy review

- Bind structural evidence to one direct FastAPI declaration, its source span and receiver.
- Expose undeclared endpoints and unsupported routing as discovery gaps; report schema revision 0.4.1.
- Correct shared-location redaction and canonicalize external state paths before checking containment.
- Disable source scanner suppressions, require complete target coverage, normalize timeout failures, and cap state before writes.
- Reject numeric overflow and UTF-16 protocol frames; preserve request IDs on malformed tool calls.
- Bind release outcomes to source and wheel hashes, with tamper rejection and a valid control.
- Add 19 focused regressions/controls and record each in FINDINGS.md.


## 0.4.0: M1a assessment and guidance server

- Seven stdio MCP tools, four resource types and three prompts; checked-in FastAPI acceptance fixture.
- Form elicitation and separate interactive CLI confirmation, with expiring single-use request IDs and external atomic state.
- Schema 0.4 migration, unique confirmation request IDs and sixth report contract with scoped input freshness.
- Opengrep 1.30.0 static/structural assessment; no-match coverage, unknown intent, and no overall score.
- Project code is never imported or executed by the server. Scanner receives bundled rules and a bounded copy.
- Repository text is withheld from MCP responses; redacted projections carry opaque references and untrusted_text. Original evidence stays in a local artifact.
- Runtime boundary/process limits, pinned installer/CI, wheel asset packaging, and a fresh-environment MCP test gate.
- New regression cases are listed individually under M1-01 through M1-09 in FINDINGS.md; the register checker runs both suites.
- No M1b execution, test generation or result-import tooling is exposed. The legacy demo remains a trusted release test.


## 0.3.3: iterated self-review to convergence

Six loops over a fixed checklist (parsing, execution, substitution, filesystem, outputs, cost),
stopping when a full pass found nothing new. Loops 5–9 found 14 issues (3 High); loop 10 was clean.
Every issue was reproduced first; see `FINDINGS.md` (P5-01 to P9-02).

**Execution (the test runner)**
- Generated tests are isolated from the project's own test setup: `--noconftest`, an isolated ini,
  and no third-party plugin autoload. A common FastAPI `conftest.py` that fakes login had made
  correct code report as a critical breach (High).
- Allowlisted environment: the server's secrets no longer reach project code (High).
- Timeouts: a hanging project is killed with its whole process group and the run fails closed (High).
- Results XML is size-capped and may not declare a DTD.
- Tokens are forged with the standard library; the generated test imports nothing from the project's
  namespace. The recorded command is now exactly what ran.

**Parsing (the loader)**
- One error contract: every malformed document raises `LoadError` with a reason, never another type.
- Refused: YAML anchors and aliases (a 294-byte alias bomb took 6.8 s), duplicate keys, non-scalar keys,
  documents over 1 MB, deep nesting, invalid UTF-8, lone surrogates, and JSON `NaN`/`Infinity`.

**Contracts**
- Every unconstrained string in every schema (77) refuses control characters and has a length cap,
  closing terminal-spoofing claims such as an erased line reprinted as "Check passed · Reproduced".
- Single-pass rule-parameter substitution; FIFOs and other non-regular files refused in workspaces;
  no temporary rule configs left behind.

**Process**
- 28 new regression cases (123 total), including genuine executions and two byte/structural fuzzers.
- One self-diagnosis corrected in the open (P9-02) after the suite showed the errors came from the app.
- Five new accepted limitations documented (L-09 to L-13), led by unsandboxed execution (L-09).
- Pack and template 0.3.3. `schema_version` stays 0.3.

## 0.3.2: self-review pass (execution safety and robustness)

A self-review targeting what the server will execute, malformed input, and unconstrained inputs.
Every issue was reproduced first; see `FINDINGS.md` (P4-01 to P4-06).

- **Template injection fixed (High).** A crafted endpoint path executed arbitrary code when the
  generated test ran (proven with a real run). New `tools/render.py`: placeholders are typed in
  `pack.yaml` (`python_string`, `identifier`, `module_path`, `http_method`, `http_status`); strings are
  emitted as escaped literals, never pasted inside quotes; the output must parse and keep the
  template's structure. Intent paths are restricted to URL path characters as defense in depth.
- **Validator never crashes.** A dangling attestation reference crashed it (found by fuzzing). Fixed,
  plus a top-level guard that reports internal errors as failures ("failing closed").
- **Evidence locations confined to the workspace.** Absolute, traversal, and drive paths rejected by
  schema and independently by the validator.
- **One route, one declaration.** Overlapping endpoints (same method and normalized path, or `ANY`)
  rejected.
- **Integrity:** inverted line ranges and duplicate ledger confirmations rejected.
- **Accurate error messages:** tagged-union schema failures are explained with the alternative the
  item declares, fixing misleading messages from the 0.3 change.
- 18 new regression cases (95 total), including a deterministic fuzz case and a fail-closed case.
  Pack and template 0.3.2. Contract schemas gain `placeholders` (pack manifest) and tighter path
  patterns (intent, finding); `schema_version` stays 0.3.

## 0.3.1: observation interpretation and snapshot coverage

A review of 0.3 found two issues. Both were reproduced with real executions before fixing.

- **Redirects produced false "Reproduced" violations.** The test client followed redirects, so a
  correctly protected endpoint that sends unauthenticated users to a public `/login` page recorded
  that page's 200, and the validator accepted a genuine, server-observed run as a critical
  violation. The template now uses `follow_redirects=False` and records the endpoint's own first
  response; a 3xx is not evaluated and yields Unknown, with a specific explanation. Templates must
  now declare `response_assumptions`, and behavioral findings carry them as limitations.
  Lesson: content-bound digests preserve an observation; they do not prove the observation means
  what the template assumes.
- **Symlinks could point at unhashed content.** A link into `.trustwright/results/`, `.git/`, or a
  directory containing an excluded area left the digest unchanged when the target's content
  changed. Symlinks are now refused when their fully resolved target is excluded, contains an
  excluded area, escapes the workspace, or loops. Legitimate in-workspace links still digest
  (checked by a suite control).
- 7 new regression cases (77 total) and a fourth suite control (legitimate symlinks).
- **Phase close:** `FINDINGS.md` consolidates every finding from three review rounds and our own
  work, with root causes, fixes, and guarding tests; `tools/check_register.py` enforces two-way
  traceability between the register and the suite. Verified by a clean-room run from the packaged
  archive. No contract changes.

## 0.3.0: content-bound trust

A review of 0.2 found that the trust ledger authenticated pointers (a run ID, a finding ID,
artifact hashes, a policy) rather than the content of the conclusions. Seven mutations and a
symlink change were accepted. All eight were reproduced before fixing and are now regression tests.

**Principle: every ledger entry stores a digest of the exact content it vouches for, and the
validator recomputes it.**

### Fixes
- **Observed runs:** the ledger stores `record_digest`, a digest of the whole run document:
  every scenario outcome, observed status, intent reference, template identity, consistency
  check, snapshot, and artifact hash. Rewriting results without the server's observation fails.
- **Human attestations:** bound by `subject_digest` to the finding's conclusion, scope,
  limitations, severity, requirement, and the reviewed code snapshot (`reviewed_tree_digest`).
  Flipping the conclusion or editing limitations voids the review.
- **Intent confirmations:** `requirement_digest` replaces `policy_digest` and also covers the
  endpoint's method and path plus any resource or role the policy references. Moving an endpoint
  or redefining `owner_field` voids the confirmation.
- **Structural evidence:** the check gained a `method` parameter, and evidence must name the
  finding's own endpoint method and path. Samples now include near-misses (wrong method, wrong
  path, wrong dependency) that must not match; verified on Opengrep 1.30.0.
- **Security failure vs assertion failure:** templates declare `denied_statuses`. A violation now
  requires an unauthorized request that was *granted* (2xx) while every authorized request was
  granted. A different refusal (403 instead of 401) is an assertion mismatch; 5xx is an error.
  Both are Unknown, not violations.
- **Observed statuses are required and real:** passed/failed scenarios must record an integer
  status (schema and validator, independently). The template records the actual response status
  via `record_property`, so the runner no longer infers it. Closes 0.2 open question 7.
- **Workspace digest v2** (`sha256-sorted-entries-v2`): symlinks are recorded by target rather
  than skipped, so retargeting one changes the digest; symlinks escaping the workspace are refused.

### Test-suite corrections
- **Logic tests now reseal the ledger.** With content-bound runs, any edit to an observed run is
  caught by the digest, which would have made the security-logic tests pass for the wrong reason.
  Logic cases (`*`) re-sign the ledger to simulate a genuine observation, so the reasoning itself
  is exercised; tamper cases leave it untouched.
- **Every case asserts its expected reason.** A rejection for another reason counts as a failure
  (WRONG-REASON). This surfaced one usability bug: oneOf schema failures reported a generic message,
  so the validator now reports the most specific sub-error.
- 70 cases (17 v0.1, 27 review-1, 8 trust, 12 review-2, 2 digest, 4 harness), with three controls:
  the baseline validates, a well-behaved fake engine passes, and resealing unmodified runs is a no-op.

## 0.2.0: validator hardening

An external review of 0.1 found that the validator did not enforce several of its
central guarantees: 11 contract mutations and a scanner failure exit were accepted.
All were reproduced before fixing, and each is now a permanent regression test.

### Corrections to 0.1 claims
- **"Exit codes are checked properly" was false.** 0.1 caught non-JSON crashes, but an engine
  exiting non-zero with well-formed JSON still passed. Now: exit 0 required, output structure
  validated, and exact expected rule IDs and lines asserted.
- **"A static rule can only produce a violation" was too rigid.** Checks now declare
  `specific_violation` or `suspicious_pattern`; suspicious matches display as
  *Needs review · Pattern matched*.
- **`pyjwt-decode-without-algorithms` was a false positive by design.** PyJWT >=2 raises
  DecodeError without `algorithms`, so the code fails closed. Rule removed.
- **`verify_signature: False` is triage, not proof.** Unverified decodes have legitimate uses
  (reading `iss` to pick a key). The violation is now established by a behavioral
  forged-token test (F-007), not by the pattern.
- A candidate replacement rule (`"none"` in the algorithms list) was tested first and dropped:
  PyJWT 2.15 rejects alg=none tokens either way.

### Evidence binding
- Evidence is required (`minItems: 1`), and each method may cite only its own evidence type.
- A cited pack check must support the finding's control.
- Behavioral evidence is bound end to end: finding control and requirement → template control
  and `supported_policies` → scenarios. Authentication tests can no longer prove ownership.
- No cherry-picking: a finding must cite every scenario run for its requirement.
- Run scenarios must match the template exactly (role, principal, expected status, testcase name,
  template version).
- Outcome consistency: `passed` requires observed == expected; `failed` requires a mismatch.
- `satisfied`/`violated` require all four consistency checks present and passing.
- `violated` requires a failed negative control **and** passing positive controls; errors and
  skips cannot support a violation (broken app or runner ≠ security failure).
- Confirmed advisories need a resolved version, an advisory ID, and a trusted version source.

### Trust boundary (new contract: trust ledger)
- Server-owned records grant trust; documents can only claim it. Reproduction requires a ledger
  entry whose tree digest, test-artifact hash, and results hash all match.
- Intent confirmation requires a ledger entry whose policy digest matches the current policy;
  editing a policy invalidates its confirmation.
- Human review requires a ledger attestation bound to that finding.

### Integrity
- Unique IDs enforced everywhere (colliding entries previously overwrote each other).
- Policy/control compatibility, resource references, and role references validated.
- Pack paths must resolve inside the pack directory, including through symlinks.
- date-time formats enforced; the validator refuses to start if they would be silently ignored.
- `tree_digest` algorithm specified (`sha256-sorted-file-hashes-v1`, see `tools/digest.py`).

### Tooling
- `tools/demo_slice.py` executes the slice for real and emits the example runs and ledger entries.
  Example runs are no longer hand-written.
- `tools/test_regressions.py`: 56 cases (17 ported, 27 from the review, 8 trust, 4 harness),
  with two controls: the baseline must validate, and a well-behaved fake engine must pass.
