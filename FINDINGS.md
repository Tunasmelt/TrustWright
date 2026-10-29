# Findings register

Covers the contracts phase (closed at v0.3.3), the M1a implementation (0.4.x) and later reviews. Sections are chronological; IDs are never reused.

Every issue found while building and reviewing the contracts: three external review rounds
plus self-review passes iterated to convergence, and issues found during our own work. Each fixed finding names the regression tests that
guard it; `tools/check_register.py` verifies that every test named here exists and passes.

**Status:** all findings are fixed or explicitly accepted as limitations. The contracts are
frozen for the MCP skeleton; changes from here go through this register.

Legend: **Fixed** = fixed and guarded by tests. **Accepted** = known limitation, documented,
not a defect for this phase. **Deferred** = requirement carried into the MCP phase.

---

## Design guarantees (v0.1, enforced from the start)

Not findings: these are the original guarantees the contracts were designed around. Listed so that
every test in the suite is traceable to a documented reason.

| ID | Guarantee | Regression tests | Status |
|---|---|---|---|
| G-01 | Structural evidence never establishes a pass, and its absence never establishes a violation. | `structural_link_claims_pass`, `structural_absence_claims_violation` | Enforced |
| G-02 | Agent review never establishes a pass and always displays as agent-assessed. | `agent_review_claims_pass`, `agent_review_relabelled_confirmed` | Enforced |
| G-03 | Unknown or unconfirmed intent yields Unknown only, and cannot be tested as if confirmed. | `unknown_intent_becomes_violation`, `unknown_intent_silently_permitted`, `inferred_intent_tested_as_confirmed` | Enforced |
| G-04 | A pass requires every cited scenario to pass, with positive and negative controls. | `pass_despite_failed_scenario`, `missing_positive_control` | Enforced |
| G-05 | Structural checks are pack-defined; agents supply only regex-validated parameter values. | `agent_invented_structural_check`, `structural_param_injection` | Enforced |
| G-06 | Ownership is always a separate requirement from authentication. | `ownership_without_authentication` | Enforced |
| G-07 | Every non-confirmed finding states its limitations. | `missing_limitations_on_non_confirmed` | Enforced |
| G-08 | A pack check cannot claim more than its kind can establish. | `pack_check_overstates_capability` | Enforced |

## Self-found during v0.1 build

| ID | Sev | Finding | Fix (version) | Regression tests | Status |
|---|---|---|---|---|---|
| S-01 | High | A crashed scanner produced no JSON, which the harness read as "0 matches", silently passing every should-not-match test. | Engine failure detected (0.1); superseded by the full exit-code policy in R1-04. | `failure_exit_with_perfect_json`, `success_exit_missing_errors_list` | Fixed |
| S-02 | Low | Opengrep removed Semgrep's `--metrics` flag; rule tests failed. | Engine-specific flags (0.1). | Covered by `validate.py --run-rules` | Fixed |
| S-03 | Med | Packaging pipeline used `\| tail`, masking a failing exit code; a broken build was zipped. | Fail-fast (`set -e`, no piping) for every release run (0.1). | Release procedure | Fixed |

## Review 1 (of v0.1)

| ID | Sev | Finding | Root cause | Fix (version) | Regression tests | Status |
|---|---|---|---|---|---|---|
| R1-01 | High | A "Confirmed" finding could have no evidence, or cite a check for a different control. | Evidence optional; no control↔check binding. | Evidence required and type-checked per method; cited check must support the finding's control (0.2). | `confirmed_issue_with_no_evidence`, `static_finding_with_no_evidence`, `control_swapped_jwt_evidence_kept` | Fixed |
| R1-02 | High | Authentication tests were accepted as proof of ownership; roles, principals, and template version unchecked. | Scenarios not bound to the finding's requirement or the template. | Finding → requirement → template (`supported_policies`) → scenarios bound end to end; scenarios must match the template exactly (0.2). | `authn_tests_prove_ownership`, `scenarios_retargeted_at_ownership`, `positive_negative_roles_swapped`, `template_version_99`, `principal_changed` | Fixed |
| R1-03 | High | A finding could cherry-pick passing scenarios; contradictory statuses and failed consistency checks were accepted. | Coverage checked per run, not per claim; "any" consistency check sufficed. | Must cite every scenario for its requirement; outcome/status consistency; all consistency checks required (0.2). | `cherry_pick_only_passing_positive`, `observed_200_expected_401_marked_passed`, `violated_while_all_cited_passed`, `failed_consistency_check_with_pass`, `consistency_check_omitted`, `violation_when_positive_control_fails`, `violation_resting_on_runner_error` | Fixed |
| R1-04 | High | Scanner exit code never enforced; match lines unchecked. The 0.1 README claim that exit codes were checked was false. | Only JSON parsing was guarded. | Exit 0 required, output structure validated, exact rule IDs and lines asserted (0.2). | `failure_exit_with_perfect_json`, `success_exit_wrong_lines`, `success_exit_missing_errors_list`, `success_exit_engine_reported_errors` | Fixed |
| R1-05 | High | Trust levels were self-declared: a run could promote itself to "reproduced". | Documents asserted their own trust. | Server-owned trust ledger (0.2), made content-bound in 0.3 (see R2-01). | `run_self_promoted_to_reproduced`, `ledger_entry_removed`, `agent_run_claims_reproduced`, `finding_upgrades_reported_run` | Fixed |
| R1-06 | Med | `decode-without-algorithms` flagged code PyJWT ≥2 already rejects; `verify_signature: False` was treated as proof of a bypass. | Rules claimed more than a pattern can show. | Rule removed (verified empirically); the remaining rule is triage (`suspicious_pattern`), with violations proven by behavioral tests (0.2). | `suspicious_pattern_promoted_to_confirmed`, `static_rule_claims_pass` | Fixed |
| R1-07 | Med | Duplicate IDs overwrote entries; policy/control, resource, and role references unchecked; pack paths could escape; advisories confirmable without version or ID; date-times unenforced; no demo runner. | Missing integrity checks. | All added (0.2); validator refuses to start if date-time checking is unavailable. | `duplicate_finding_ids`, `duplicate_run_ids`, `duplicate_requirement_ids`, `authn_control_given_owner_policy`, `policy_references_missing_resource`, `pack_path_escapes_via_dotdot`, `pack_file_symlink_escape`, `advisory_confirmed_without_version_or_id`, `advisory_confirmed_unchecked`, `advisory_confirmed_from_unpinned_manifest`, `invalid_date_time` | Fixed |
| S-04 | Med | (Self, during R1-06) The candidate replacement rule ("`none` in algorithms") would also have been a false positive: PyJWT 2.15 rejects alg=none either way. | Same overclaim pattern. | Tested before adding; not shipped (0.2). | n/a (never shipped) | Fixed |

## Review 2 (of v0.2)

| ID | Sev | Finding | Root cause | Fix (version) | Regression tests | Status |
|---|---|---|---|---|---|---|
| R2-01 | High | Observed results could be rewritten (failed → passed) without invalidating the ledger. | Ledger bound artifact hashes, not the parsed record. | `record_digest` over the entire run record (0.3). | `observed_results_rewritten_ledger_untouched`, `observed_run_results_swapped`, `observed_run_workspace_changed` | Fixed |
| R2-02 | High | A human attestation stayed valid after its conclusion was flipped. | Attestation bound a finding ID, not its content. | `subject_digest` over conclusion, scope, limitations, severity, requirement, reviewed snapshot (0.3). | `attested_conclusion_flipped`, `attested_limitations_removed`, `attested_snapshot_swapped`, `human_review_without_ledger_attestation`, `attestation_reused_for_other_finding` | Fixed |
| R2-03 | High | A confirmed requirement survived moving its endpoint to `/admin/secrets`; structural evidence could name an unrelated path. | Confirmation covered the policy only; structural params unbound. | `requirement_digest` covers method, path, and referenced definitions; structural check gains `method` and must match the endpoint (0.3). | `confirmed_endpoint_moved`, `confirmed_endpoint_method_changed`, `owner_field_redefined_after_confirmation`, `structural_path_unrelated`, `structural_method_mismatch`, `requirement_self_confirmed`, `policy_edited_after_confirmation` | Fixed |
| R2-04 | High | Any negative-control mismatch (403, 500) counted as a reproduced violation. | Test assertion failure conflated with security failure. | Violation requires an unauthorized request that was *granted* (2xx) with all positive controls granted; templates declare `denied_statuses` (0.3). | `negative_403_counted_as_violation`, `negative_500_counted_as_violation` | Fixed |
| R2-05 | Med | A reproduced pass validated with no observed statuses. | Equality checked only when a status existed. | Observed status required (schema and validator independently); template records the real status via `record_property` (0.3). | `reproduced_pass_without_observations` | Fixed |
| R2-06 | Med | Retargeting a symlink left the workspace digest unchanged. | Symlinks skipped. | Digest v2 records links by target; escaping links refused (0.3). | `symlink_retarget_changes_digest`, `workspace_symlink_escape_refused` | Fixed |
| S-05 | High | (Self) With content-bound runs, every edit to an observed run was caught by the digest, so security-logic tests passed without exercising the logic. | Tests asserted rejection, not its reason. | Logic tests reseal the ledger; every case asserts its expected reason; WRONG-REASON counts as failure (0.3). | Whole suite (`*` cases) | Fixed |
| S-06 | Low | (Self, found by S-05) Schema `oneOf` failures reported a generic message, so developers could not see what was wrong. | Top-level error reported. | Most specific sub-error reported (0.3). | `advisory_confirmed_without_version_or_id` | Fixed |

## Review 3 (of v0.3)

| ID | Sev | Finding | Root cause | Fix (version) | Regression tests | Status |
|---|---|---|---|---|---|---|
| R3-01 | High | A correctly protected endpoint that redirects to a public `/login` was reported as a reproduced violation. | Test client followed redirects and recorded the login page's 200. An authentic observation was misinterpreted. | No redirects followed; 3xx yields Unknown with an explanation; templates declare `response_assumptions`, carried by findings (0.3.1). | `redirect_to_public_login_not_a_violation` (genuine server-observed execution) | Fixed |
| R3-02 | High | A symlink into `.trustwright/results/`, `.git/`, or a directory containing an excluded area hid content changes from the digest. | Link recorded, target content excluded. | Links refused if the resolved target is excluded, contains an excluded area, escapes, or loops (0.3.1). | `symlink_to_excluded_results_file`, `symlink_to_git_internals`, `dir_symlink_to_ancestor_of_excluded`, `symlink_chain_into_excluded`, `dir_symlink_to_workspace_root`, `symlink_cycle` | Fixed |
| R3-03 | Note | Historical passes could appear to describe current code. | No report contract yet. | Requirement for `get_report`: every report states its assessed snapshot, every finding the snapshot it was established on. | To be added with the report contract | Deferred |

## Pass 4: self-review of v0.3.1

Focus: what the server will execute, robustness under malformed input, and unconstrained inputs.
Method: targeted exploits, plus a fuzzer (~11,500 mutated bundles across three seeds).

| ID | Sev | Finding | Root cause | Fix (version) | Regression tests | Status |
|---|---|---|---|---|---|---|
| P4-01 | High | A crafted endpoint path in the intent file executed arbitrary code when the generated test ran (proven with a real run). In controlled-runner mode the server itself would execute it. | Template placeholders pasted raw into Python source; `method`, `app_module`, `app_object`, and status also injectable. | `tools/render.py`: every placeholder has a declared type; strings emitted as escaped literals via `repr`, other types strictly validated; rendered module must parse and keep the template's top-level shape. Intent paths restricted to URL path characters (0.3.2). | `template_injection_runs_nothing`, `template_injection_other_placeholders_refused`, `intent_path_with_code_rejected`, `template_placeholder_undeclared` | Fixed |
| P4-02 | Med | The validator crashed (`StopIteration`) on a human-review finding with a dangling requirement reference. Found by fuzzing. | Attestation digest computed for a reference already known not to resolve. | Digest skipped for unresolvable refs; digest helpers raise clear errors; top-level guard reports any internal error as a failure ("failing closed"), never a crash or a pass (0.3.2). | `attestation_with_dangling_requirement`, `attestation_with_dangling_endpoint`, `validator_never_crashes_fuzz`, `fail_closed_on_internal_error` | Fixed |
| P4-03 | Med | Evidence locations accepted absolute, traversal, and drive paths (`/etc/shadow`, `../../.ssh/id_rsa`). The server will read cited lines, so a security tool could be pointed at secrets. | Location paths unconstrained. | Workspace-relative paths enforced by schema and, independently, by the validator (0.3.2). | `citation_absolute_path`, `citation_traversal_path`, `scope_location_traversal`, `citation_windows_drive_path`, `location_check_without_schema` | Fixed |
| P4-04 | Med | One route could be declared twice with conflicting confirmed policies (public and authenticated). | No route uniqueness. | One declaration per route: method plus normalized path (`{param}` names and trailing slashes ignored); `ANY` overlaps every method (0.3.2). | `same_route_confirmed_public_and_authenticated`, `same_route_param_renamed_trailing_slash`, `any_method_overlaps_specific_method` | Fixed |
| P4-05 | Low | Inverted line ranges and duplicate ledger confirmations were accepted. | Missing integrity checks. | Both rejected (0.3.2). | `inverted_line_range`, `duplicate_ledger_confirmation` | Fixed |
| P4-06 | Low | (Found by the expected-reason checks) The v0.3 "most specific error" fix chose the wrong alternative for evidence items, telling a developer who cited `/etc/shadow` to add a `pack_id`. | `best_match` ignored the `type` tag that says which alternative an item is. | Tagged-union failures are explained using the declared alternative (0.3.2). | `citation_absolute_path`, `citation_traversal_path`, `citation_windows_drive_path` | Fixed |

## Loops 5–10: iterated self-review to convergence

Stopping rule: iterate until one full pass over a fixed checklist finds zero new reproducible issues.
Checklist (trace every agent-writable input to where it is executed, read, or parsed):
**parsing**, **execution**, **substitution**, **filesystem**, **outputs**, and from loop 10, **cost**.
Loops 5–9 each found issues; loop 10 found none.

| ID | Sev | Finding | Root cause | Fix (version) | Regression tests | Status |
|---|---|---|---|---|---|---|
| P5-01 | Med | A 294-byte YAML intent file took 6.8 s of CPU (alias bomb); one more level would take over a minute. | Anchors/aliases allowed in agent-writable documents; no size cap. | Loader refuses anchors and aliases; 1 MB document cap; deep nesting refused (0.3.3). | `yaml_alias_bomb_refused`, `oversized_document_refused`, `deeply_nested_json_refused` | Fixed |
| P5-02 | High | The test subprocess inherited the server's whole environment: project code read a planted API key. | `env={**os.environ, ...}`. | Allowlisted environment only (0.3.3). | `test_subprocess_gets_no_server_secrets` (genuine run) | Fixed |
| P5-03 | Low | Sequential substitution let a path value containing `__DEPENDENCY__` be rewritten after passing its regex. | Placeholders replaced one after another. | Single-pass substitution (0.3.3). | `rule_params_substituted_in_one_pass` | Fixed |
| P5-04 | Low | A FIFO named `auth.py` was silently left out of the workspace digest. | Non-regular files skipped. | Refused (0.3.3). | `non_regular_file_refused` | Fixed |
| P5-05 | Low | Rule tests left temp configs (with agent-supplied values) in `/tmp`. | `delete=False`. | Scoped temporary directory (0.3.3). | `rule_tests_leave_no_temp_files` | Fixed |
| P6-01 | Med | Free text accepted terminal escapes and unbounded length: a claim could erase its line and print a fake "Check passed · Reproduced". | Unconstrained strings. | Every unconstrained string in every schema (77) now refuses control characters and has a length cap (0.3.3). | `claim_with_terminal_escape`, `limitation_with_terminal_escape`, `scope_ref_with_carriage_return`, `oversized_claim`, `intent_rationale_with_escape`, `structural_param_control_chars` | Fixed |
| P6-02 | High | No timeouts: a project with an infinite loop hung the runner indefinitely; scans had no timeout either. | Unbounded waits. | Test timeout kills the whole process group and fails closed; scanner timeout (0.3.3). | `hanging_project_is_killed` (genuine run) | Fixed |
| P6-03 | Low | Results XML (written by project code) had no size cap. Entity-expansion bombs were already refused by expat 2.6.1, but only by virtue of the library version. | Unbounded parse; reliance on library defaults. | 10 MB cap; DTDs and entities refused outright (0.3.3). | `oversized_results_refused`, `results_with_dtd_refused` | Fixed |
| P7-01 | Med | Duplicate keys resolved silently last-wins in YAML and JSON: a reader sees one policy, the parser uses another. | Parser defaults. | Duplicate keys refused in both formats (0.3.3). | `yaml_duplicate_key_refused`, `json_duplicate_key_refused`, `yaml_python_tag_refused` | Fixed |
| P7-02 | High | **Correct code reported as a critical breach:** a common FastAPI `conftest.py` that fakes login via `dependency_overrides` leaked into the generated tests (forged tokens got 200). Project `addopts` could also deselect tests. | Generated tests ran inside the project's pytest setup. | `--noconftest`, an isolated ini (`-c`), and plugin autoload disabled (0.3.3). | `project_conftest_cannot_fake_login`, `project_addopts_cannot_deselect_tests`, `third_party_pytest_plugins_disabled` (genuine runs) | Fixed |
| P7-03 | Low | The recorded command dropped `-p` (since 0.2), so the audit record did not match what ran. | `cmd[5:]` slice. | Exact command recorded (0.3.3). | `recorded_command_matches_executed` | Fixed |
| P8-01 | Med | The loader had no error contract: 7 malformed inputs raised 6 exception types, one from the loop-7 duplicate-key check itself (unhashable keys). Reads used the platform locale. | Unwrapped parser errors; implicit encoding. | Every failure is `LoadError` with a reason; strict UTF-8; scalar keys only (0.3.3). | `loader_error_contract`, `loader_byte_fuzz` | Fixed |
| P8-02 | Low | JSON `NaN`/`Infinity` accepted; canonical digests would then contain non-JSON tokens other implementations cannot verify. | Python's JSON defaults. | Refused (0.3.3). | `loader_error_contract` | Fixed |
| P9-01 | Med | A lone surrogate (`\ud800`) passed the loader and the validator, then crashed the digest. | No Unicode validity check. | Refused at load and, for object input, at the start of `validate()` (0.3.3). | `lone_surrogate_refused_at_load`, `lone_surrogate_refused_in_validate` | Fixed |
| P9-02 | Low | Hardening: the generated test imported `jwt` from the same namespace as the project. The probe's errors turned out to come from the *app* (correctly failing closed), so the original diagnosis was half wrong; the coupling is removed anyway. | Shared import namespace. | Tokens forged with the standard library; rendered test imports only stdlib, the test client, and the app (0.3.3). | `generated_test_imports_nothing_from_the_project_namespace` | Fixed |
| L10 | n/a | **Loop 10: clean.** 13 schema regexes vs 1 MB adversarial strings (slowest 32 ms); 3,000 endpoints + 3,000 findings in 4.2 s; 1,646 structural and 3,000 byte-level fuzz cases with zero failures. | | Convergence reached. | Covered by the fuzz cases above | Fixed |

---

## Accepted limitations

| ID | Limitation | Why accepted now | Mitigation / plan |
|---|---|---|---|
| L-01 | An agent with unrestricted shell access on the same account as the server can rewrite the ledger itself. | The ledger defends against documents promoting themselves, not a hostile local process. | MCP server keeps the ledger in its own data directory; stronger guarantees need a separate OS user or signed entries. |
| L-02 | Static rules are pattern-local: options via `**kwargs` or built elsewhere are missed. | Declared per check in `cannot_establish`; static rules are triage only. | Behavioral tests establish violations. |
| L-03 | Router- and app-level FastAPI dependencies are not resolved. | Shows as *Needs review · Not linked*: noisy but never a false pass. | First pack improvement. **Status (0.4.3):** still unresolved; statically resolvable forms are in scope for the revised M1a gate (TW-02, target 0.5.0). |
| L-04 | Redirect-based auth flows are Unknown under the current template. | Correct by design after R3-01. | A separate template with its own response assumptions. |
| L-05 | ASVS mapping is chapter-level. | Needs the published ASVS 5.0 text. | Map before the first public release. |
| L-06 | Consistency checks are heuristics. | They never raise a result above *Reported*. | Only server observation grants *Reproduced*. |
| L-07 | Rule behavior can drift between engine versions. | Tested on Opengrep 1.30.0. | Pin the engine version in CI. |
| L-08 | No ownership (AUTHZ-OWNERSHIP) behavioral template. | Ownership currently relies on agent or human review. | Next template: user A requests user B's record (negative) and their own (positive). |
| L-09 | The controlled runner executes project code unsandboxed (filesystem, network, processes). | Inherent to behavioral testing; environment, timeouts, and pytest config are now contained. | MCP phase: run in a container or sandbox with no network by default. **Status (0.4.3):** the M1a server executes no project code; closed in M1b by the sandbox. |
| L-10 | Adversarial project code can subvert in-process tests (e.g. a `sitecustomize.py`, or app code that detects test runs). | The threat model is a non-adversarial project with an agent writing documents; the snapshot of exactly what ran is recorded for audit. | Out-of-process black-box testing against a running server is the stronger design for later. |
| L-11 | The allowlisted environment strips app configuration (e.g. `DATABASE_URL`), so some apps cannot start under test; they fail closed (Unknown). | Safe default after P5-02. | Per-project, explicitly declared environment allowlist. |
| L-12 | Size caps apply to files read via `load()`; documents handed in as objects are trusted to come from the server. Digest time scales with workspace size. | The server constructs those objects itself. | Enforce caps at the MCP boundary too. **Status (0.4.0):** mitigated by the 64 KiB frame limit and file, tree, result, timeout and concurrency bounds (M1-06). |
| L-13 | Free text written by an agent will reach other agents through reports (prompt-injection channel). Control characters and size are now constrained, but content cannot be validated. | Requires the report contract. | Deferred to `get_report`: mark agent-authored fields as untrusted data. **Status (0.4.0):** mitigated by withholding repository text (M1-05); cannot be closed by the server. |
| L-14 | Neither confirmation channel proves a human: form elicitation trusts the client UI, and the CLI's terminal check can be satisfied by an agent with shell access through a pseudo-terminal. | Human-only confirmation needs an approval channel outside the agent's authority. | Documented boundary; the ledger should record the channel, not a verified person (revised gate, R-02). |
| L-15 | Projects needing source builds, editable, local or VCS dependencies cannot be verified. | Building them runs package code. | Verification yields Unknown; a separate restricted build stage after M3. |
| R-01 | A dependency reference does not establish authentication: linking `get_db` displays exactly like linking `get_current_user`. | Structural evidence is a reference only (`authentication_semantics: unverified`). | Explicit limitation; enforcement is established by behavioral verification (M1b). |

## Verification at close

- Fuzzing: ~15,700 structural bundles (five seeds) and ~3,500 byte-corrupted documents, zero failures.
- `tools/demo_slice.py` re-executes the slice (now through the typed renderer): broken auth accepts expired and forged tokens (200);
  the fixed recipe passes all four scenarios; the redirect variant records 307s.
- `tools/validate.py --run-rules`: 9 findings, 3 runs, 1 pack valid; Opengrep 1.30.0 exact-line rule tests pass.
- `tools/test_regressions.py`: 123/123 rejected for their stated reasons, with four controls
  (baseline valid, honest fake engine passes, reseal is a no-op, legitimate symlinks digest).
- `tools/check_register.py`: every test named in this register exists and passes, and every
  suite test is cited here (full traceability in both directions).
- Clean-room run from the packaged zip, with no reliance on the working directory.

## M1a implementation (0.4.0)

These changes extend the frozen baseline through this register. Schema version 0.4 introduces
a sixth contract (report), a one-time request ID in confirmations, and form/terminal confirmation
channels. Existing 0.3 ledgers are not silently migrated. The server owns its fresh external store.

| ID | Finding / guarantee | Implementation | Regression tests | Status |
|---|---|---|---|---|
| M1-01 | Workspace provenance must not grant confirmation. | Effective provenance is derived from matching server ledger entries, regardless of claimed source. Additional flags fail schema validation. | `test_forged_confirmation`, `test_extra_confirmation_flag`, `test_unconfirmed_not_structurally_assessed` | Fixed |
| M1-02 | Confirmation needs a one-time, content-bound, expiring developer request. | Exact intent and requirement digests; atomic consumption; 15-minute expiry; no model approval parameter; unique ledger request IDs. | `test_changed_confirmation_policy`, `test_confirmation_replay`, `test_unknown_confirmation`, `test_expired_confirmation`, `test_declined_confirmation`, `test_unknown_policy`, `test_schema_migration`, `test_request_id_unique_in_contract` | Fixed |
| M1-03 | Findings must become historical when assessed inputs change. | Sixth schema plus semantic equality checks cover code, intent, confirmations, pack assets, manifests, configuration, scanner identity and explicit check bindings. Advisory state is explicitly not queried. | `test_intent_change_stales_assessment`, `test_dependency_change_stales_assessment` | Fixed |
| M1-04 | No-match or absent scanner must not create a pass or a score. | Coverage-only no-match; no scanner produces not_run; all M1a findings remain Unknown with evidence-specific labels; report forbids extra score field. | `test_no_match_is_coverage`, `test_engine_missing_never_passes` | Fixed |
| M1-05 | Arbitrary source text could carry secrets or instructions into MCP output. | Source snippets, project labels, route strings and dependency names are withheld; opaque references map to a local assessment; untrusted_text explicitly describes suppressed fields. Nonstandard version values are omitted. | `test_secret_and_untrusted_text_withheld`, `test_nonstandard_dependency_value_withheld` | Fixed |
| M1-06 | MCP and scanner input/output need bounded failure behavior. | 64 KiB frame limit before parsing, duplicate/depth/Unicode checks, typed tool schemas, process deadline/output caps and generic sanitized errors. | `test_boundary_duplicate_and_depth`, `test_mcp_oversize_boundary`, `test_mcp_malformed_boundary`, `test_scanner_failures_are_not_no_match` | Fixed |
| M1-07 | Assessment must never import or execute the project or follow workspace symlinks. | Static AST/manifest detection; bundled rules scan a bounded source copy; no project interpreter, test hooks, scanner config, or source code execution. State must be outside root. | `test_project_code_not_executed`, `test_paths_and_symlinks_refused` | Fixed |
| M1-08 | Auth UI and fallback must work across the actual protocol boundary. | Seven tools, one resource plus three resource templates, three prompts; form elicitation; separate TTY-only CLI; developer approval bound to exact request. | `test_mcp_end_to_end`, `test_mcp_fallback_pending`, `test_noninteractive_cli_refused`, `test_cli_interactive_confirmation` | Fixed |
| M1-09 | Version presence is not runtime observation. | Source attribution, exact lockfile precedence, conflict handling, unresolved import-only versions; no runtime imports. | `test_lockfile_source_and_conflict` | Fixed |

### M1a limits and release decisions

- L-07 is mitigated by the pinned Opengrep 1.30.0 binary, pinned SHA-256 Linux installer, CI and runtime version check. The scanner is external, not bundled.
- L-12 is mitigated for this stdio implementation by frame, file, tree, result, timeout and concurrency bounds. One server handles one tool at a time; multiple independent server processes are not globally rate limited.
- L-13 is mitigated by withholding repository text rather than merely tagging instructions. MCP reports are projections: opaque paths/parameters are not the original source evidence. Validate original findings before projecting; inspect `.trustwright/last-assessment.json` locally. This is not a guarantee against malicious clients or arbitrary data deliberately placed in protocol IDs.
- L-14: form confirmation trusts the client UI. It names the one-based endpoint and requirement position in the exact intent file and its digest; the developer must inspect that policy before approving. The CLI displays the exact JSON-escaped policy in a terminal. Neither establishes human identity against a malicious client or same-user shell attacker.
- L-15: source builds and sandboxed execution remain outside M1a. The legacy demo executes only its own generated fixtures as a release test; the MCP server never exposes it.
- State uses a permission-restricted, atomically replaced JSON document guarded by a POSIX file lock, rather than a log. Request consumption and ledger updates commit together. Root identity is derived from its canonical path, independent of code digest. Moving the project requires fresh confirmation.
- This first implementation targets POSIX Python 3.11+; CI and the supplied installer target Linux x86-64. Windows support is not claimed.

## Post-release accuracy loops (0.4.1)

| ID | Sev | Reproduced failure and narrow correction | Regression tests | Status |
|---|---|---|---|---|
| A1-01 | High | Any get-like decorator was treated as a FastAPI route, and duplicate declarations could borrow a different handler's dependency. Recognize direct local FastAPI instances; require one route candidate; bind matches to its source, handler span and captured receiver. | `test_non_fastapi_decorator_not_a_route`, `test_duplicate_route_cannot_borrow_wiring`, `test_same_handler_unrelated_decorator_cannot_supply_link` | Fixed |
| A1-02 | Med | New endpoints absent from intent, unsupported route syntax and unreadable directory walks could disappear. Report explicit discovery gaps and fail closed on traversal errors. Report contract revision is 0.4.1; other contracts remain 0.4. | `test_undeclared_new_endpoint_is_visible`, `test_unsupported_route_forms_are_discovery_gaps`, `test_unreadable_tree_is_not_silently_skipped` | Fixed |
| A1-03 | Med | Shared location dictionaries were hashed twice during report projection, breaking local reference mapping. Break aliases before independent field redaction. | `test_projection_preserves_shared_location_identity` | Fixed |
| A1-04 | High | A state path containing dot-dot could resolve back into the agent-writable workspace after the lexical containment check. Canonicalize before enforcing containment, after rejecting symlink components. | `test_state_dotdot_cannot_enter_workspace` | Fixed |
| A2-01 | Med | Source nosemgrep comments suppressed bundled checks and an empty scanned-target set appeared complete. Disable source suppression and version checks; require exact scanned-target coverage and no skipped rules. | `test_source_comment_cannot_suppress_scan`, `test_scanner_missing_target_is_not_completed` | Fixed |
| A2-02 | Med | A child closing both pipes before hanging raised an unclassified TimeoutExpired. Normalize it to scanner_timeout while retaining process-group cleanup. | `test_scanner_closed_pipes_timeout_has_reason` | Fixed |
| A2-03 | Med | State could be written larger than its own read cap, making later operations fail. Enforce the cap before replacing the prior state. | `test_state_size_failure_preserves_prior_state` | Fixed |
| A3-01 | Med | Numeric overflow produced infinity and UTF-16 bytes passed the UTF-8 JSON boundary. Validate finite numbers and decode UTF-8 explicitly. | `test_numeric_overflow_is_invalid_json`, `test_utf16_frame_is_refused` | Fixed |
| A3-02 | Med | Malformed tool arguments lost a valid request ID, leaving clients unable to correlate the error. Preserve bounded valid IDs in error responses. | `test_malformed_request_keeps_request_id` | Fixed |
| A3-03 | High | Old successful exit codes authorized packaging changed source and an unrelated wheel. Bind every release gate to tested source; bind build/clean-room gates to the wheel hash; packaging refuses missing or stale bindings. | `test_release_requires_source_bound_gates` | Fixed |
| A4-01 | Med | The first source-span correction falsely marked a valid stacked decorator as unlinked. Accept the handler's full decorator span while independently checking receiver and method/path. Reset decorator-only dependencies for each route. | `test_stacked_routes_remain_structurally_linked`, `test_stacked_decorators_keep_independent_dependencies` | Fixed |

The source/wheel release binding detects accidental stale evidence; it is not cryptographic
attestation against a same-user adversary who can rewrite both the code and the gate records.
Direct local construction is deliberately conservative: imported apps, routers, dynamic registration
and unsupported syntax are not inferred as verified routes. These remain declared discovery limitations.


| ID | Sev | Reproduced failure and correction | Regression tests | Status |
|---|---|---|---|---|
| A5-01 | High | Release packaging recursively included a local .env and unrelated private notes even with valid source-bound gates. Restrict top-level release content and exclude credential filenames/directories. This is not a general secret detector for source or logs. | `test_release_excludes_local_credentials` | Fixed |

## Uploaded verification review (0.4.2)

| ID | Status | Finding and correction | Regression tests |
|---|---|---|---|
| V-01 | Fixed | Dependencies inferred authentication and a caller-selected DB dependency looked like auth wiring. Draft Unknown; generic structural result stays Needs review with source and unverified semantics. | `test_dependencies_do_not_infer_authentication`, `test_supplied_dependency_link_is_not_authentication`, `test_discovered_dependency_retains_unverified_origin` |
| V-02 | Fixed | Old structural display could survive an upgrade. Reproject labels conservatively, preserve stored evidence. | `test_legacy_structural_projection_cannot_keep_wiring_claim` |
| V-03 | Fixed | Digest cycle rejection depended on non-strict Path.resolve raising. Kernel stat detects cycles; only missing-target errors permit lexical resolution. | `test_symlink_cycle_refused_with_permissive_resolve`, `test_symlink_resolution_permission_errors_propagate`, `test_dangling_symlink_digest_remains_supported` |
| V-04 | Fixed | Fixed /tmp marker allowed interference across baseline runs. Use private per-run directory; restore environment and clean on failure. | `test_subprocess_gets_no_server_secrets` |

## 0.4.3: rename and revised M1a gate

| ID | Change | Basis | Regression tests | Status |
|---|---|---|---|---|
| TW-01 | Renamed authcheck to TrustWright (package, CLI, `.trustwright/`, `TRUSTWRIGHT_*`, `trustwright://`); no behavior change. | Mechanical rename; example runs regenerated by the demo gate. | Whole suite: all seven release gates on Python 3.12.3, 3.13.16 and 3.14.6 | Done |
| TW-02 | Revised M1a gate adopted: T-01 to T-06 in scope, with two fixtures verified against FastAPI's runtime routes and OpenAPI. | `acceptance/M1A-GATE-REVISION.md` | To be added with each item's implementation | Open |
| TW-03 | `acceptance/fastapi-template/expected-inventory.csv` was committed with LF endings, but its pinned SHA-256 is of the CRLF bytes Python's csv module wrote, so `sha256sum -c` failed on every fresh checkout. Marked `-text` in `.gitattributes` so Git stores the pinned bytes; fixture checksums are now checked in the test suite. | `.gitattributes` `eol=lf` normalized a CRLF fixture | `test_acceptance_fixture_bytes_match_checksums` | Fixed |
| TW-04 | T-03: a confirmed requirement that no check assessed (route not resolved, binding unresolved, no applicable check, scanner unavailable) was absent from the report, and unconfirmed requirements appeared twice (in the stored assessment and in `unknowns`). Each requirement now appears exactly once: a finding with its `intent_ref`, *Unknown · Intent missing*, or *Unknown · Not assessed* with a `not_assessed:*` reason. Endpoint coverage rows carry `endpoint_ref` and `requirement_ref`. | Revised gate G3 | `test_every_requirement_reported_exactly_once`, `test_confirmed_requirement_on_unresolved_route_is_not_assessed`, `test_confirmed_public_requirement_has_no_applicable_check` | Fixed |
| TW-05 | T-04: every discovery problem was one opaque file reference reported as `source_parse_error`/`route_discovery_incomplete`, including APIRouter files that parse. Each problem now has a distinct reason (`source_parse_error` with `python_version`, `unsupported_route_form`, `unresolved_dynamic_route`); `unresolved_import`, `unresolved_prefix` and `binding_unresolved` are defined for T-01/T-02. | Revised gate G4 | `test_discovery_problems_have_distinct_reasons`, `test_router_file_is_not_reported_as_parse_error` | Fixed |
| TW-06 | Contract change for TW-04/TW-05: report `schema_version` 0.5.0; finding method `not_assessed` with `assessment_gap` evidence and display status `not_assessed` (both finding schema copies); discovery-gap reason enum replaced (`route_discovery_incomplete` removed); optional coverage `endpoint_ref`/`requirement_ref`. Discovery identity in the configuration digest is now `direct-fastapi-v2`, so assessments made before the change become historical. | AGENTS.md rule 7 | Covered by the TW-04 and TW-05 tests, which pass only if every generated report validates against report schema 0.5.0 | Fixed |
