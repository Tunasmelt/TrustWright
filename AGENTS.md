# TrustWright: instructions for coding agents

TrustWright is a local stdio MCP server that checks whether a project's authentication matches the developer's
declared security intent and reports exactly what its evidence supports. **Core rule: no conclusion is ever stronger
than its evidence.** Read `docs/DESIGN-SPEC.md` for the design and `acceptance/M1A-GATE-REVISION.md` for the current
milestone gate before changing behavior.

## Environment

Contributor setup: a locked environment with an editable install. It runs with network; the agent phase may not have it. To only *use* TrustWright, follow README "Install and connect" (`pip install '.[test]'`).

```bash
pip install -r requirements-dev.lock
pip install -e . --no-deps
python tools/install_opengrep.py "$HOME/.local/bin/opengrep"   # pinned 1.30.0, SHA-256 checked
export PATH="$HOME/.local/bin:$PATH"
```

Tested: Linux x86-64 with Python 3.12.3, 3.13.16 and 3.14.6, all seven release gates passing on the 0.4.3 tree (local run, 7 Oct 2026); GitHub Actions runs the same gates on 3.12, 3.13 and 3.14 on every push. Python 3.11 is untested. On Windows, work inside WSL 2. Report the interpreter version (`python -VV`) with every result.

## Commands

| Purpose | Command | Notes |
|---|---|---|
| Application tests | `python -m pytest -q tests` | about 2 min |
| Baseline regressions | `python tools/test_regressions.py` | must print `123/123` (or the new total) |
| All seven release gates | `python tools/release.py` | about 6 min; lint, demo, contracts, regressions, register, build, clean-room |
| Package | `python tools/package_release.py` | only after `release.py` passes |

`release.py` fails with `release_source_binding: source changed during gate` if a gate modifies inputs. If you changed
anything the demo regenerates, run `python tools/demo_slice.py` once, commit the regenerated `examples/`, then rerun.

## Rules (each exists because breaking it once shipped a real defect)

1. **No overclaiming.** Display labels are derived from evidence, never written freely. A static match is
   *Needs review*. A structural link is a dependency *reference* (`authentication_semantics: unverified`), never proof
   of authentication. "No matches" is coverage, never a pass. No overall score.
2. **Reproduce first.** Every fix starts with a test that fails for the stated reason, then passes. Regression cases
   assert *why* they reject; a rejection for a different reason is a failure.
3. **Register everything.** Each fix or accepted limitation gets a row in `FINDINGS.md` (ID, severity, finding,
   regression test names, status). `tools/check_register.py` enforces two-way traceability. Use new IDs; never reuse one.
4. **Never weaken tests.** Do not delete, skip, loosen, or re-expect an existing test or regression case to make a
   change pass. If you believe one is wrong, stop and explain it in the PR.
5. **Agent-writable input is untrusted.** Workspace files, the intent file and tool arguments are typed, size-capped,
   and refused when malformed. In M1a, project code is parsed only: never imported, executed, or installed.
6. **Fail closed.** Errors, timeouts and malformed input become reported failures or Unknowns with a specific reason.
7. **Contracts change through the register.** A schema change bumps its `schema_version` and is recorded in `FINDINGS.md`.
8. **Untrusted text stays labelled.** Repository-derived strings in MCP output go inside `untrusted_text`; secret
   values are never returned.

## Protected paths

- `handoff/`: historical brief; do not edit.
- `acceptance/*/` fixture sources and `SHA256SUMS`: read-only inputs. A change to an `expected-inventory.csv` needs
  output from `acceptance/tools/route_oracle.py` as evidence in the PR.

## Out of scope for M1a

`generate_tests`, `run_verification`, `submit_test_results` (M1b); OSV and Gitleaks adapters and agent review tools
(M2); `request_human_review` (M3); anything that executes project code.

## Every pull request includes

1. What changed and why, referencing register IDs.
2. Before/after evidence: the failing reproduction and the passing run.
3. Each command run, with interpreter version and exit code, pasted from the actual output.
4. The `release.py` gate summary, or the specific reason it was not run.
5. Remaining limitations. Never state a result without the log line that shows it.
