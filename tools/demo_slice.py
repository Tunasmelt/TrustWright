"""Run the first vertical slice for real and emit contract documents.

    python tools/demo_slice.py           # writes examples/verification-run.*.json + trust-ledger runs

Variants: "fixed" (the recipe), "broken" (signature verification disabled),
"redirect" (correctly protected, but sends unauthenticated users to a public
/login page; used by the regression suite).

Three runs against a throwaway FastAPI app built from the pack's recipe:
  RUN-001  broken auth (signature verification disabled), observed by the server
  RUN-002  fixed auth, run as if by an agent  -> evidence stays "reported"
  RUN-003  fixed auth, observed by the server -> eligible for "independently_reproduced"

Only server-observed runs get a trust-ledger entry. That is the boundary: a
document can claim anything, but only the ledger grants reproduction.
"""
from __future__ import annotations

import json
import os
import signal
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from render import render  # noqa: E402
from digest import (TREE_ALGORITHM, attestation_subject_digest, requirement_digest,  # noqa: E402
                    run_record_digest, sha256_file, tree_digest)

ROOT = Path(__file__).resolve().parent.parent
PACK_DIR = ROOT / "packs" / "fastapi-pyjwt-pwdlib"
PACK = yaml.safe_load((PACK_DIR / "pack.yaml").read_text())
TEMPLATE = next(t for t in PACK["test_templates"] if t["id"] == "authn-endpoint")
INTENT_REF = {"endpoint_id": "read-document", "requirement_id": "read-document-authn"}
ENV = {"JWT_KEY": "demo-key-not-a-secret-0123456789abcdef", "JWT_AUDIENCE": "docs-api"}

APP = '''from typing import Annotated
from fastapi import Depends, FastAPI
from auth import get_current_user

app = FastAPI()

@app.get("/documents/{doc_id}")
def read_document(doc_id: int, user: Annotated[dict, Depends(get_current_user)]):
    return {"id": doc_id, "owner": user["id"]}
'''


def test_environment(root: Path) -> dict:
    """Allowlisted environment for executing project code. The server's own environment
    (API keys, tokens, cloud credentials) must never reach the code under test."""
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(root), "LANG": "C.UTF-8",
            "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",  # no third-party plugins altering collection or outcomes
            **ENV}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_workspace(root: Path, variant: str) -> Path:
    recipe = (PACK_DIR / "recipes" / "verify_token.py").read_text()
    app = APP
    if variant == "broken":
        recipe = recipe.replace('options={"require": ["exp", "aud", "sub"]}', 'options={"verify_signature": False}')
        assert '"verify_signature": False' in recipe, "broken variant was not applied"
    elif variant == "redirect":
        before = recipe
        recipe = recipe.replace(
            'status_code=status.HTTP_401_UNAUTHORIZED,\n        detail="Invalid or missing credentials",\n        headers={"WWW-Authenticate": "Bearer"},',
            'status_code=307,\n        headers={"Location": "/login"},')
        assert recipe != before, "redirect variant was not applied"
        app += '\n\n@app.get("/login")\ndef login_page():\n    return {"page": "public login form"}\n'
    elif variant != "fixed":
        raise ValueError(f"unknown variant {variant!r}")
    (root / "auth.py").write_text(recipe)
    (root / "app.py").write_text(app)
    tests = root / ".trustwright" / "tests"
    tests.mkdir(parents=True)
    test_file = tests / "test_read_document_authn.py"
    test_file.write_text(render((PACK_DIR / TEMPLATE["file"]).read_text(), TEMPLATE["placeholders"], {
        "app_module": "app", "app_object": "app", "concrete_path": "/documents/1",
        "test_key": ENV["JWT_KEY"], "test_audience": ENV["JWT_AUDIENCE"],
        "method": "get", "expect_ok_status": 200}))
    (root / ".trustwright" / "results").mkdir(parents=True)
    return test_file


MAX_RESULTS_BYTES = 10_000_000
TEST_TIMEOUT_SECONDS = 120


class RunnerError(RuntimeError):
    """The run cannot produce trustworthy results; no run document is emitted (fail closed)."""


def parse_junit(path: Path) -> dict:
    """testcase name -> (outcome, observed_status). The status comes from the
    <property name="observed_status"> the test recorded, never from inference.
    The file is written by project code, so it is size-capped and may not declare a DTD
    (JUnit never needs one; this removes entity expansion regardless of the expat version)."""
    size = path.stat().st_size
    if size > MAX_RESULTS_BYTES:
        raise RunnerError(f"results file is {size} bytes; the limit is {MAX_RESULTS_BYTES}")
    raw = path.read_bytes()
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise RunnerError("results file declares a DTD or entities; refusing to parse")
    out = {}
    for tc in ET.fromstring(raw).iter("testcase"):
        props = {p.get("name"): p.get("value") for p in tc.iter("property")}
        observed = int(props["observed_status"]) if props.get("observed_status", "").isdigit() else None
        if tc.find("failure") is not None:
            outcome = "failed"
        elif tc.find("error") is not None:
            outcome = "error"
        elif tc.find("skipped") is not None:
            outcome = "skipped"
        else:
            outcome = "passed"
        if outcome in {"passed", "failed"} and observed is None:
            outcome = "error"  # a status assertion without a recorded status is not evidence
        out[tc.get("name")] = (outcome, observed)
    return out


def execute(run_id: str, variant: str, server_observed: bool) -> tuple[dict, dict | None]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        test_file = build_workspace(root, variant)
        (test_file.parent / "trustwright-pytest.ini").write_text("[pytest]\n")
        digest_before, file_count = tree_digest(root)
        results = root / ".trustwright" / "results" / f"{run_id}.xml"
        # Isolated from the project's own test setup: its conftest.py (e.g. a fixture that fakes
        # login via dependency_overrides) and its pytest config (addopts) must not alter these tests.
        # Recorded command is exactly what ran (everything after the interpreter prefix).
        ini = test_file.parent / "trustwright-pytest.ini"  # written before the snapshot, so it is covered
        cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--noconftest",
               "-c", str(ini.relative_to(root)), "--rootdir", str(test_file.parent.relative_to(root)),
               str(test_file.relative_to(root)), f"--junitxml={results.relative_to(root)}"]
        # New session, so a timeout kills the whole process group (project code may spawn children).
        proc = subprocess.Popen(cmd, cwd=root, env=test_environment(root), stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            returncode = proc.wait(timeout=TEST_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise RunnerError(f"tests exceeded {TEST_TIMEOUT_SECONDS}s and were killed; no results recorded") from None
        if returncode not in (0, 1):  # 1 = tests failed; anything else = runner failure
            raise RunnerError(f"pytest failed to run (exit {returncode})")
        digest_after, _ = tree_digest(root)
        cases = parse_junit(results)
        names = {s["junit_testcase"] for s in TEMPLATE["scenarios"]}
        scenarios = []
        for s in TEMPLATE["scenarios"]:
            outcome, observed = cases.get(s["junit_testcase"], ("error", None))
            scenarios.append({
                "id": s["id"], "intent_ref": INTENT_REF, "control_role": s["control_role"],
                "principal": s["principal"], "expect_status": s["expect_status"],
                "observed_status": observed,
                "outcome": outcome, "junit_testcase": s["junit_testcase"]})
        test_sha, results_sha = sha256_file(test_file), sha256_file(results)
        run = {
            "schema_version": "0.4", "run_id": run_id, "created_at": now(),
            "workspace_snapshot": {"head_commit": None, "has_uncommitted_changes": True,
                "tree_digest": {"algorithm": TREE_ALGORITHM, "value": digest_before,
                                "file_count": file_count, "includes_untracked": True}},
            "test_artifact": {"path": str(test_file.relative_to(root)), "sha256": test_sha,
                "template": {"pack_id": PACK["pack_id"], "template_id": TEMPLATE["id"],
                             "template_version": TEMPLATE["template_version"]}},
            "runner": {"kind": "controlled_runner" if server_observed else "agent_reported",
                       "command": " ".join(["pytest", *cmd[3:]]), "observed_by_server": server_observed,
                       "environment": {"python": sys.version.split()[0],
                                       "fastapi": __import__("fastapi").__version__,
                                       "pyjwt": __import__("jwt").__version__}},
            "results_artifact": {"format": "junit_xml", "path": str(results.relative_to(root)),
                                 "sha256": results_sha,
                                 "modified_at": datetime.fromtimestamp(results.stat().st_mtime, timezone.utc)
                                 .strftime("%Y-%m-%dT%H:%M:%SZ")},
            "consistency_checks": [
                {"check": "results_newer_than_test_artifact", "passed": results.stat().st_mtime >= test_file.stat().st_mtime},
                {"check": "testcase_names_match_template", "passed": set(cases) == names},
                {"check": "testcase_count_matches_template", "passed": len(cases) == len(names)},
                {"check": "snapshot_matches_current_workspace", "passed": digest_before == digest_after}],
            "evidence_validation": "independently_reproduced" if server_observed else "reported",
            "scenarios": scenarios}
        # The ledger authenticates the whole normalized record, not just artifact bytes.
        ledger_entry = ({"run_id": run_id, "record_digest": run_record_digest(run), "observed_at": now()}
                        if server_observed else None)
        return run, ledger_entry


if __name__ == "__main__":
    ex = ROOT / "examples"
    for old in ex.glob("verification-run.*.json"):
        old.unlink()
    ledger_path = ex / "trust-ledger.json"
    ledger = {"schema_version": "0.4", "observed_runs": [], "intent_confirmations": [], "human_attestations": []}
    tree_by_run = {}
    for run_id, variant, observed, label in (("RUN-001", "broken", True, "broken-observed"),
                                             ("RUN-002", "fixed", False, "fixed-reported"),
                                             ("RUN-003", "fixed", True, "fixed-observed")):
        run, entry = execute(run_id, variant, observed)
        (ex / f"verification-run.{run_id.lower()}.json").write_text(json.dumps(run, indent=2) + "\n")
        if entry:
            ledger["observed_runs"].append(entry)
        tree_by_run[run_id] = run["workspace_snapshot"]["tree_digest"]["value"]
        print(f"{run_id} ({label}): " + ", ".join(f"{s['id']}={s['outcome']}/{s['observed_status']}" for s in run["scenarios"]))

    # Intent confirmations: as if captured from the developer via URL elicitation.
    intent = yaml.safe_load((ex / "security-intent.yaml").read_text())
    for ep in intent["endpoints"]:
        for r in ep["requirements"]:
            if r["provenance"]["source"] == "confirmed" and r["policy"]["kind"] != "unknown":
                ledger["intent_confirmations"].append({
                    "endpoint_id": ep["id"], "requirement_id": r["id"],
                    "requirement_digest": requirement_digest(intent, ep["id"], r["id"]),
                    "request_id": "confirm-" + requirement_digest(intent, ep["id"], r["id"])[:32],
                    "confirmed_by": r["provenance"]["by"], "confirmed_at": r["provenance"]["at"],
                    "channel": "mcp_form_elicitation"})

    # Human attestation for F-009: bound to the finding's content and the reviewed snapshot (fixed code).
    findings_path = ex / "findings.json"
    findings = json.loads(findings_path.read_text())
    f9 = next(f for f in findings if f["id"] == "F-009")
    f9["evidence"][0]["reviewed_tree_digest"] = tree_by_run["RUN-003"]
    findings_path.write_text(json.dumps(findings, indent=2) + "\n")
    ledger["human_attestations"].append({
        "attestation_id": "ATT-001", "finding_id": "F-009", "reviewer": "harris",
        "subject_digest": attestation_subject_digest(f9, intent), "attested_at": now()})
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n")
