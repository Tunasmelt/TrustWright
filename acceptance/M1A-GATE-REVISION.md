# M1a gate revision (TrustWright, formerly authcheck): useful coverage on a normally structured FastAPI project

Adopts the bounded scope agreed on 7 Oct 2026: T-01 to T-04 move into M1a. Structural results keep their current
meaning: a dependency *reference*, never authentication behavior. Everything below is checked against the two fixtures
in `acceptance/`, whose inventories were verified against FastAPI itself (evidence bundle: `authcheck-m1a-gate-revision.zip`, produced against authcheck 0.4.2 before the rename).

## Scope (as decided)

| Item | M1a decision |
|---|---|
| T-01 Router discovery | Statically resolvable `APIRouter` imports, nested `include_router`, composed prefixes. Unresolved dynamic routing reported explicitly. |
| T-02 Dependency aliases | Supported `Annotated` aliases, including imported ones. Establishes references, not authentication. |
| T-03 Missing requirements | Every declared requirement stays visible, including **Unknown · Not assessed**. |
| T-04 Error reasons | Distinct reasons for syntax errors, unsupported routing, unresolved imports, ambiguous bindings. |

## Pass criteria

**G1. Template snapshot** (`acceptance/fastapi-template`, commit `f27b472`; 23 pairs in `expected-inventory.csv`)
- All 23 (method, full path) pairs are discovered, with no extras: `app.frontend(...)` is not an API route.
- The prefix `settings.API_V1_STR` resolves to `/api/v1` and is labelled as an overridable default, or is reported as
  `unresolved_prefix` with router-local paths still matched. It is never silently dropped.
- `POST /api/v1/private/users/` is marked conditional (`FASTAPI_ENV == "development"`).
- On Python ≥3.14: 17 endpoints have a dependency reference matching `runtime_dependency_tree` (12 via the imported
  `CurrentUser` alias, 6 via decorator `dependencies=`, 1 using both); 6 have none.
- On Python <3.14: `backend/app/api/deps.py` (PEP 758 syntax) is reported as `source_parse_error` with the interpreter
  version. The 12 alias endpoints are reported as unresolved because the alias source is unparseable, never as
  "not linked". Routes are still discovered, because `deps.py` declares none.

**G2. Independent fixture** (`acceptance/router-patterns`; 13 cases in `expected-inventory.csv`)

*Counting:* a **case** is a row of `expected-inventory.csv` (13: P01–P13). A **mounted pair** is a (method, path) the
running app serves: 11 by default, 12 with `ENABLE_DEBUG=1`. P13 is never mounted. `measure_discovery.py` counts
conditional routes as expected, so its denominator is 12.
- P01–P09: discovered with the exact effective method and path, and the dependency references listed.
- P09: the computed decorator `dependencies=` is reported unresolved; the include-level dependency is still found.
- P10–P11 (loop plus env prefix): reported as an unresolved dynamic route and an unresolved prefix. No paths invented.
- P12: marked conditional. P13: not reported as mounted.

**G3. Every requirement visible.** With intent declared for all 23 template endpoints, the report holds exactly one
entry per requirement: a finding with its `intent_ref`, or an Unknown with a reason (`intent_missing`,
`not_assessed:route_not_resolved`, `not_assessed:dependency_binding_unresolved`, `not_assessed:no_applicable_check`).
Coverage rows carry the requirement reference.

**G4. Distinct reasons.** Each G1/G2 unresolved case maps to its own reason code. `source_parse_error` appears only for
a real syntax error.

**G5. Compatibility and consistency (T-05, T-06).**
- Existing seven gates pass on Python 3.12, 3.13 and 3.14.
- Gate `results.json` and report `assessment_inputs` record the interpreter version; today neither does.
- A project whose `requires-python` excludes authcheck's interpreter produces a warning.
- One reference format is used across the report and the local reference map.

**G6. No new claims.** Structural results stay *Needs review · Structurally linked* with
`authentication_semantics: unverified`. Linking `get_db` (P04/P05) is shown exactly like linking `get_current_user`.

## Dispositions of the review items

| Item | Disposition | Evidence |
|---|---|---|
| R-01 | Explicit limitation; references are not enforcement. Optional: show the dependency name inside `untrusted_text` so "Needs review" says what to review. | `v01-residual-py3.13.log` |
| R-02 | Documented boundary. `isatty()` proves a terminal, not a human; human-only confirmation needs a channel outside the agent's authority. The documentation should also cover the stored record: the ledger writes `confirmed_by: "developer"`, which the channel cannot establish. | `r02-pty-confirmation.log` |
| R-03 | Reproduced; see below. | `r03-wire-capture.log` |
| R-04 | Documented path restriction. | |
| R-05 | Clarify the field: whole-file hash, so it means "this file changed since citation". | |

### R-03 reproduction (authcheck 0.4.2, mcp 1.30.0, Python 3.14.6)
1. **Delivery succeeds.** After a 70,117-byte frame with id 7, the server writes
   `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"message_too_large: maximum 65536 bytes"}}`.
2. **The shutdown is intentional.** A follow-up request gets EOF and the server exits with code 0, as the transport code intends.
3. **The failure is in client parsing.** The MCP Python SDK rejects that line (9 validation errors on `id: null`), so
   the agent sees only "Connection closed". The same SDK accepts a `notifications/message` carrying the reason.
   Candidate change, for decision: send that notification and a stderr line before closing. Keep the close.

## Note for future runtime work (M1b)

In FastAPI 0.141, `include_router` no longer copies routes into `app.routes`; the app holds a private
`_IncludedRouter`. Code that walks `app.routes` for `APIRoute` objects sees none. `acceptance/tools/route_oracle.py` handles both
layouts and cross-checks against the public OpenAPI document. Results are identical on FastAPI 0.115.0 and 0.141.1.
