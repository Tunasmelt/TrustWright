# TrustWright (M1a, 0.4.3)

*Formerly authcheck.* Design: [`docs/DESIGN-SPEC.md`](docs/DESIGN-SPEC.md) · current milestone gate: [`acceptance/M1A-GATE-REVISION.md`](acceptance/M1A-GATE-REVISION.md) · agent instructions: [`AGENTS.md`](AGENTS.md)

A local, open-source stdio MCP server for evidence-scoped authentication assessment and
implementation guidance. It implements the supplied M1a brief against the contracts v0.3.3
baseline, with contract changes registered in `FINDINGS.md`.

**M1a assesses source and provides a recipe. It does not execute the project, run tests,
import test results, query advisories, scan secrets, or pronounce a project secure.**

## Install and connect

Python 3.11+ on POSIX is required. Tested: Linux x86-64 with Python 3.12.3, 3.13.16 and 3.14.6, all seven release gates passing on the 0.4.3 tree (local run, 7 Oct 2026); GitHub Actions runs the same gates on 3.12, 3.13 and 3.14 on every push. Python 3.11 is untested. On Windows, use WSL 2 (below).

```bash
python -m venv .venv
.venv/bin/python -m pip install '.[test]'
.venv/bin/python tools/install_opengrep.py "$HOME/.local/bin/opengrep"
```

This installs TrustWright to use it. Contributors use the locked environment instead
(`requirements-dev.lock` plus an editable install); see `AGENTS.md`.

**Windows.** Run TrustWright and its gates inside WSL 2 (Ubuntu): clone into the WSL filesystem (for example `~/src`),
not under `/mnt/c`. The repository's `.gitattributes` keeps LF line endings, which the fixture checksums and exact-line
rule samples require. Codex Cloud and CI run on Linux, so contributing does not require a local Windows setup.

The installer downloads Opengrep **1.30.0** and checks its pinned SHA-256 before installing.
For another platform, install that release separately. The scanner is not included in the ZIP
or Python wheel. Without it, assessment returns explicit `not_run` coverage, never a pass.

Configure your MCP client using absolute paths:

```json
{
  "mcpServers": {
    "trustwright": {
      "command": "/absolute/path/to/trustwright/.venv/bin/python",
      "args": [
        "-I", "-m", "trustwright", "serve",
        "--root", "/absolute/path/to/project",
        "--opengrep", "/absolute/path/to/opengrep"
      ]
    }
  }
}
```

Use Python's isolated mode (`-I`) and a trusted trustwright installation to keep project-side
Python startup configuration out of the server. Each server has exactly one workspace root.
The MCP connection cannot change it or select an executable or arbitrary pack.

## Workflow

1. `detect_stack` identifies supported Python dependencies, their versions and source,
   the applicable pack, and controls without an M1a check. Lockfiles describe resolved
   declarations; they are not an observation of the running environment.
2. `draft_intent` creates `.trustwright/security-intent.yaml`, without overwriting an existing
   file. All requirements start inferred with an unknown policy. Dependencies do not identify
   intended access policy. Review and edit the policy locally before confirmation.
3. `confirm_intent(endpoint_ref, requirement_ref)` requests developer approval through
   **form elicitation**. The form identifies the one-based endpoint/requirement position
   in the intent file, intended policy kind and requirement digest. Inspect that exact
   local policy before approving. This confirms intent, not the implementation.
4. If the client does not support forms, run the returned command in a separate terminal
   opened at the assessed project:

   ```bash
   /absolute/path/to/trustwright/.venv/bin/trustwright confirm confirm-<request-id>
   ```

   It displays the actual policy as JSON-escaped text and requires typing `APPROVE`.
   Pass the same `--root` and `--state-dir` when using non-default locations. Piped input
   is refused. Requests expire after 15 minutes and can be consumed only once.
5. `validate_intent` reports effective confirmation. Writing `source: confirmed` in a file
   grants nothing. Unknown intent never grants permission.
6. `run_checks` runs the bundled static and structural rules on a bounded source copy.
   Optional `bindings` identify a dependency by a pack-validated name, using the endpoint
   and requirement references from the intent tools. A binding cannot supply rule logic. Its origin is recorded as agent-supplied;
   automatic selections are marked static discovery. Neither establishes authentication behavior.
7. `get_recipe` returns the bundled `verify-token` recipe with tested versions.
8. `get_report` returns current evidence, historical evidence, coverage gaps, unknown
   requirements, assumptions and limitations. It never returns a security score.

| Observation | Display / treatment |
|---|---|
| Unverified JWT decode pattern | Needs review · Pattern matched |
| Declared route references the selected dependency | Needs review · Structurally linked; authentication unverified |
| Pack check runs but finds no selected dependency link | Needs review · Not linked |
| Unknown or unconfirmed intent | Unknown · Intent missing; endpoint checks do not apply |
| Static rule has no matches | Coverage only; not a pass |
| Scanner, parsing or binding unavailable | Explicit error/not_run coverage |

A dependency reference is not proof of authentication. No M1a method establishes a pass or
a reproduced violation. The legacy contract examples include stronger evidence methods,
but those methods are not exposed as tools in this release.

## Interface

**Seven tools:** `detect_stack`, `draft_intent`, `confirm_intent`, `validate_intent`,
`run_checks`, `get_recipe`, `get_report`.

**Four resource types:** `trustwright://controls`, `trustwright://schemas/{name}`,
`trustwright://packs/{id}`, `trustwright://recipes/{pack}/{id}`. The first is a concrete resource;
the other three are MCP resource templates. Schema names omit `.schema.json`.

**Three prompts:** `assess-project`, `add-auth`, `fix-finding`.

## Evidence, freshness and privacy

Six contracts live in `schemas/`. The report contract is now `0.5.0`; the other
schema-version-bearing documents remain `0.4`. The report contract contains assessment inputs and current/historical sections. Confirmation
entries additionally require a unique `request_id` and the form/CLI channel. The finding
schema adds one method, `not_assessed`; report projections embed it.

Every declared requirement appears in a report exactly once: a finding carrying its
`intent_ref`, or an Unknown. Unconfirmed requirements are *Unknown · Intent missing*. A
confirmed requirement no check assessed is *Unknown · Not assessed* with a reason
(`not_assessed:route_not_resolved`, `…:dependency_binding_unresolved`,
`…:no_applicable_check`, `…:check_not_run` or `…:no_current_assessment`). Endpoint coverage
rows carry `endpoint_ref` and `requirement_ref`. Discovery gaps name a distinct reason;
`source_parse_error` includes the interpreter's `python_version`, because parseability
depends on it.

Each assessment records digests of Python source, intent, effective confirmation records,
pack files, dependency manifests, scanner version/binary, server configuration and explicit
check bindings. A current assessment must match all these inputs exactly. Changing them
makes earlier evidence historical. Advisory status is explicitly `not_queried`, not fresh.
Freshness is limited to this stated source/manifest scope: deployment configuration and
runtime behavior are not assessed.

Repository-origin prose, names, source lines, route strings and dependency function names
are withheld from MCP responses. Reports provide opaque references and `untrusted_text`
markers rather than echoing those values. Original, validated findings and the reference
mapping are available locally in `.trustwright/last-assessment.json`. Public evidence fields
with opaque paths/parameters are **redacted projections**, not independently re-runnable
rule inputs. The bundled recipe and catalogue are trusted package content.

This is not a secret detector. It does not make secrets already present in a user's prompt,
client-supplied protocol identifiers, logs outside trustwright, or the agent's own file reads
safe. Do not put credentials in tool arguments.

## State and execution boundaries

- State defaults to `~/.local/share/trustwright/<workspace-id>/state.json`; override with
  `--state-dir` or `TRUSTWRIGHT_STATE_DIR`. It must be outside the assessed workspace.
- Workspace identity is a digest of its canonical path, not its changing contents. A move
  requires fresh confirmation. State directories/files use 0700/0600 permissions, atomic
  replacement and a POSIX file lock. Request consumption and ledger updates commit together.
- This protects against workspace documents inventing evidence. It does not isolate the
  ledger from an agent with unrestricted shell access as the same OS user, or prove that
  an elicitation response came from a human rather than a malicious MCP client.
- The server statically reads source/manifests; it never imports the app or runs its hooks.
  Opengrep runs only bundled rules against copied source with a restricted environment.
  It is not an OS sandbox, and no OS-level network isolation is claimed.
- Runtime caps: 64 KiB input frames; 1 MB per source/intent document; 20 MB / 500 selected
  files; 10,000 traversed entries; 100 discovered routes; 1 MB scanner output; 60-second
  scanner calls; a 180-second assessment scheduling budget (one in-flight scan may finish
  after the budget); one tool operation at a time. Oversized frames close the session.
- Symlinks in selected files/directories and special files are refused. Credentials (`.env*`,
  key/certificate files and common credential directories), dependencies, generated output,
  `.git` and `.trustwright` metadata are excluded. These exclusions are not a proof that source
  files contain no secrets.
- History retains the last 10 assessments and returns at most 5 historical entries. Large
  outputs fail closed with a limit reason; report pagination is not implemented.

The first pack supports only direct FastAPI route patterns plus PyJWT misuse triage. Dynamic
routing, router prefixes, app/router dependencies, ownership checks, other frameworks and
behavioral verification remain gaps. Packs ship code recipes/templates but no server hooks;
M1a does not render or execute the test templates.

## Verification and release gates

```bash
export PATH="$HOME/.local/bin:$PATH"
export TRUSTWRIGHT_OPENGREP="$HOME/.local/bin/opengrep"
.venv/bin/python -m ruff check trustwright tests setup.py tools/install_opengrep.py tools/clean_room.py tools/release_support.py tools/release.py tools/package_release.py
.venv/bin/python tools/demo_slice.py
.venv/bin/python tools/validate.py --run-rules
.venv/bin/python tools/test_regressions.py
.venv/bin/python tools/check_register.py
.venv/bin/python -m build
.venv/bin/python tools/clean_room.py
```

`tools/release.py` runs the seven release gates in this order, bound to the source digest: lint (ruff), demo,
contract/rule validation, baseline regression suite, two-way findings-register check, wheel build, and clean-room
installation. The register check also runs
the new pytest suite: protocol integration, terminal approval, confirmation tampering,
boundary limits, privacy, input freshness and scanner failure handling. `clean_room.py`
installs the built wheel in a fresh virtual environment, checks its bundled assets from
outside the source tree, and reruns the M1a suite. The trusted demo is a release harness
that executes its own generated fixtures; it is never an MCP tool.

The CI workflow runs these gates with the pinned scanner. Run new tests directly with
`.venv/bin/python -m pytest -q tests`.

For a distributable release, run `.venv/bin/python tools/release.py`, then
`.venv/bin/python tools/package_release.py`. Packaging requires every gate to be bound
to the current source and the build/clean-room gates to the exact wheel. Bare successful
exit codes or stale logs no longer authorize packaging.

## Layout and provenance

- `trustwright/`: transport, seven-tool server, service, state, static discovery and scanner adapter.
- `schemas/`, `catalogue/`, `packs/`: contracts and bundled declarative assets.
- `tests/fixtures/fastapi/`: checked-in broken demo application, derived from the baseline demo.
- `tools/`: retained contract/release harness plus installer and clean-room check.
- `FINDINGS.md`: changes and regression traceability in both directions.
- `docs/DESIGN-SPEC.md`: design specification; marks what 0.4.3 implements versus what the revised M1a gate targets.
- `acceptance/`: revised M1a gate, two pinned fixtures with FastAPI-verified inventories, and measurement tools.
- `AGENTS.md`: contributor and coding-agent rules, locked setup and commands.
- `CHANGELOG.md`: changes from the baseline.

Baseline archive SHA-256:
`7886e7db064a94da181a4e90e633fe8891bbaba00c79eb2376789815428ff576`.
The supplied M1a brief is included under `handoff/`. The v1.2 design export was not in the
handoff, so no claim is made to have independently checked its full text.

MIT-licensed trustwright source; third-party components retain their own licenses.

## Accuracy review in 0.4.1

Five correction loops added 19 adversarial regressions and positive controls. They cover
route attribution, omitted discovery gaps, projection identity, state containment and capacity,
scanner suppression/completeness/timeouts, malformed protocol input, and stale release evidence.
See `REVIEW-LOOPS.md` and findings A1-01 through A5-01. Static route discovery now recognizes
only direct module-level FastAPI construction; unresolved routing appears as an explicit gap.

## Verification review in 0.4.2

The uploaded verification reproduced dependency-to-authentication misattribution. Draft
intent now stays Unknown; structural evidence records binding origin and unverified
authentication semantics. Older stored structural findings are projected conservatively
without rewriting their history. Existing confirmations are still intent approvals only.
The digest helper detects symlink cycles independently of non-strict Path.resolve behavior,
and the release-only leakage test uses an isolated temporary directory and restores its
environment on failure. Seven new regressions cover the changed boundaries.
