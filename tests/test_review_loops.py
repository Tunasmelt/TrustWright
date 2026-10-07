"""Adversarial regressions discovered after the 0.4.0 release."""

from conftest import choose_fixture_intent
import json
from pathlib import Path

import pytest

from trustwright.project import routes, snapshot
from trustwright.safety import Refused, strict_json
from trustwright.state import State


def confirmed(service):
    service.draft_intent()
    draft = choose_fixture_intent(service)
    r = next(x for x in draft["requirements"] if x["policy_kind"] == "authenticated")
    p = service.prepare_confirmation(r["endpoint_ref"], r["requirement_ref"])
    service.finish_confirmation(p["request_id"], True, "cli_prompt")
    return r


def test_non_fastapi_decorator_not_a_route():
    found, _ = routes({"cache.py": b'@cache.get("/secret")\ndef cached():\n    pass\n'})
    assert found == [], "an arbitrary get decorator is not a FastAPI endpoint"


def test_duplicate_route_cannot_borrow_wiring(service):
    confirmed(service)
    p = service.root / "app.py"
    p.write_text(
        p.read_text()
        + '\n@app.get("/documents/{doc_id}")\ndef alternate(doc_id: int):\n    return {}\n'
    )
    service.run_checks()
    report = service.get_report()
    assert not any(
        x["finding"]["method"] == "structural_check" for x in report["current"][0]["findings"]
    )
    assert any(x["reason"] == "route_binding_ambiguous" for x in report["current"][0]["coverage"])


def test_undeclared_new_endpoint_is_visible(service):
    confirmed(service)
    p = service.root / "app.py"
    p.write_text(p.read_text() + '\n@app.get("/new-private")\ndef new_endpoint():\n    return {}\n')
    report = service.get_report()
    assert any(x["reason"] == "endpoint_not_declared" for x in report["discovery_gaps"])


def test_projection_preserves_shared_location_identity(service):
    loc = {"path": "auth.py", "start_line": 1}
    f = service.make_finding(
        "TOKEN-INTEGRITY",
        "static_rule",
        {
            "type": "rule_match",
            "validation": "rule_matched",
            "pack_id": "fastapi-pyjwt-pwdlib",
            "check_id": "token-verify-disabled",
            "location": loc,
        },
        {"kind": "function", "ref": "auth.py", "locations": [loc]},
        limitations=["Pattern only"],
    )
    projected = service.public_finding(f)["finding"]
    assert (
        projected["scope"]["locations"][0]["path"]
        == projected["evidence"][0]["location"]["path"]
        == "source/" + service.ref("auth.py") + ".py"
    )
    assert f["scope"]["locations"][0]["path"] == "auth.py"


def test_state_dotdot_cannot_enter_workspace(service):
    # Lexical '..' bypasses the original parent membership test.
    base = service.root.parent / "outside" / ".." / "project" / "owned-state"
    with pytest.raises(Refused, match="state_must_be_outside_workspace"):
        State(service.root, base)


def test_numeric_overflow_is_invalid_json():
    with pytest.raises(Refused, match="non-finite"):
        strict_json(b'{"value":1e9999}')


def test_unreadable_tree_is_not_silently_skipped(service, monkeypatch):
    def broken_walk(root, **kwargs):
        if kwargs.get("onerror"):
            kwargs["onerror"](PermissionError("cannot traverse"))
        return iter(())

    monkeypatch.setattr("trustwright.project.os.walk", broken_walk)
    with pytest.raises(Refused, match="workspace_traversal_failed"):
        snapshot(service.root)


def test_source_comment_cannot_suppress_scan(service):
    from trustwright.scanner import scan
    from trustwright.contracts import PACK

    assert service.engine, "release tests require the pinned real scanner"
    hits = scan(
        service.engine,
        {
            "bad.py": b'import jwt\nx=jwt.decode(token, options={"verify_signature":False}) # nosemgrep\n'
        },
        PACK["checks"][0],
    )
    assert len(hits) == 1, "repository comments must not silently disable a bundled check"


def test_scanner_missing_target_is_not_completed(service, monkeypatch):
    from trustwright import scanner
    from trustwright.contracts import PACK

    monkeypatch.setattr(
        scanner,
        "bounded_process",
        lambda *a, **k: b'{"results":[],"errors":[],"paths":{"scanned":[]}}',
    )
    with pytest.raises(Refused, match="scanner_incomplete_coverage"):
        scanner.scan("unused", {"auth.py": b"pass\n"}, PACK["checks"][0])


def test_scanner_closed_pipes_timeout_has_reason(tmp_path):
    import sys
    from trustwright.scanner import bounded_process

    with pytest.raises(Refused, match="scanner_timeout"):
        bounded_process(
            [sys.executable, "-c", "import os,time;os.close(1);os.close(2);time.sleep(20)"],
            tmp_path,
            timeout=0.1,
        )


def test_state_size_failure_preserves_prior_state(service):
    before = service.state.read()
    original = service.state.file.read_bytes()
    with pytest.raises(Refused, match="state_size_limit"):
        with service.state.transaction() as d:
            d["oversized"] = "x" * 8_000_001
    assert service.state.file.read_bytes() == original
    assert service.state.read() == before


def test_malformed_request_keeps_request_id(service):
    from test_protocol import raw_exchange

    response = raw_exchange(
        service,
        b'{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"get_report","arguments":"wrong-type"}}\n',
    )
    assert response["id"] == 17, (
        "valid request ID must receive its own error, not hang until timeout"
    )


def test_utf16_frame_is_refused():
    with pytest.raises(Refused, match="invalid bounded JSON"):
        strict_json('{"value":1}'.encode("utf-16"))


def test_release_requires_source_bound_gates(tmp_path):
    import shutil
    import subprocess
    import sys

    root = tmp_path / "release"
    (root / "tools").mkdir(parents=True)
    (root / "release-validation").mkdir()
    (root / "trustwright").mkdir()
    (root / "dist").mkdir()
    original = Path(__file__).resolve().parents[1] / "tools"
    for name in ("package_release.py", "release_support.py"):
        if (original / name).exists():
            shutil.copyfile(original / name, root / "tools" / name)
    (root / "trustwright/__init__.py").write_text('__version__="0.4.1"\n')
    (root / "pyproject.toml").write_text('[project]\nversion="0.4.1"\n')
    (root / "dist/trustwright_mcp-0.4.1-py3-none-any.whl").write_bytes(b"old wheel")
    names = ["lint", "demo", "contracts", "regressions", "register", "build", "clean-room"]
    (root / "release-validation/results.json").write_text(
        json.dumps([{"gate": n, "exit_code": 0} for n in names])
    )
    result = subprocess.run(
        [sys.executable, str(root / "tools/package_release.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0 and "release_source_binding" in result.stderr, (
        "exit codes alone must not authorize a release"
    )

    # Valid binding control, followed by independent source and wheel tampering.
    import importlib.util
    import hashlib

    spec = importlib.util.spec_from_file_location(
        "release_support_test", original / "release_support.py"
    )
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    source = support.source_digest(root)
    wheel = root / "dist/trustwright_mcp-0.4.1-py3-none-any.whl"
    records = [
        {
            "gate": n,
            "exit_code": 0,
            "source_digest": source,
            "wheel_digest": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        }
        for n in names
    ]
    support.check_release(root, records)
    original_source = (root / "trustwright/__init__.py").read_bytes()
    (root / "trustwright/__init__.py").write_bytes(original_source + b"# edited after tests\n")
    with pytest.raises(ValueError, match="release_source_binding"):
        support.check_release(root, records)
    (root / "trustwright/__init__.py").write_bytes(original_source)
    wheel.write_bytes(b"changed wheel")
    with pytest.raises(ValueError, match="release_wheel_binding"):
        support.check_release(root, records)


def test_stacked_decorators_keep_independent_dependencies():
    source = b"""from fastapi import FastAPI, Depends
app=FastAPI()
@app.get("/one", dependencies=[Depends(auth)])
@app.get("/two")
def handler():
    pass
"""
    found, _ = routes({"app.py": source})
    assert next(r for r in found if r["path"] == "/one")["dependency"] == "auth"
    assert next(r for r in found if r["path"] == "/two")["dependency"] is None


def test_stacked_routes_remain_structurally_linked(service):
    p = service.root / "app.py"
    p.write_text(
        p.read_text().replace(
            '@app.get("/documents/{doc_id}")',
            '@app.post("/documents/{doc_id}")\n@app.get("/documents/{doc_id}")',
        )
    )
    service.draft_intent()
    draft = choose_fixture_intent(service)
    for r in draft["requirements"]:
        if r["policy_kind"] == "authenticated":
            request = service.prepare_confirmation(r["endpoint_ref"], r["requirement_ref"])
            service.finish_confirmation(request["request_id"], True, "cli_prompt")
    service.run_checks()
    report = service.get_report()
    links = [
        x["finding"]["display"]["status"]
        for x in report["current"][0]["findings"]
        if x["finding"]["method"] == "structural_check"
    ]
    assert links == ["structurally_linked", "structurally_linked"]


def test_unsupported_route_forms_are_discovery_gaps():
    source = b'from fastapi import FastAPI\napp=FastAPI()\n@app.api_route("/x",methods=["GET"])\ndef x():\n    pass\n'
    found, errors = routes({"app.py": source})
    assert found == [] and errors, "unsupported route syntax must be visible as a discovery gap"


def test_same_handler_unrelated_decorator_cannot_supply_link(service):
    import yaml

    p = service.root / "app.py"
    p.write_text("""from fastapi import FastAPI, Depends
app=FastAPI()
@cache.get("/x", dependencies=[Depends(auth)])
@app.get("/x")
def h():
    pass
""")
    service.draft_intent()
    intent = yaml.safe_load(service.intent_path.read_text())
    intent["endpoints"][0]["requirements"][0]["policy"] = {"kind": "authenticated"}
    service.intent_path.write_text(yaml.safe_dump(intent))
    r = service.validate_intent()["requirements"][0]
    pending = service.prepare_confirmation(r["endpoint_ref"], r["requirement_ref"])
    service.finish_confirmation(pending["request_id"], True, "cli_prompt")
    service.run_checks(
        bindings=[{k: r[k] for k in ("endpoint_ref", "requirement_ref")} | {"dependency": "auth"}]
    )
    report = service.get_report()
    links = [
        x["finding"]
        for x in report["current"][0]["findings"]
        if x["finding"]["method"] == "structural_check"
    ]
    assert len(links) == 1 and links[0]["display"]["status"] == "not_linked"


def test_release_excludes_local_credentials(tmp_path):
    import hashlib
    import importlib.util
    import shutil
    import subprocess
    import sys
    import zipfile

    root = tmp_path / "release"
    (root / "tools").mkdir(parents=True)
    (root / "release-validation").mkdir()
    (root / "trustwright").mkdir()
    (root / "dist").mkdir()
    original = Path(__file__).resolve().parents[1] / "tools"
    for name in ("package_release.py", "release_support.py"):
        shutil.copyfile(original / name, root / "tools" / name)
    (root / "trustwright/__init__.py").write_text('__version__="0.4.1"\n')
    (root / "pyproject.toml").write_text('[project]\nversion="0.4.1"\n')
    wheel = root / "dist/trustwright_mcp-0.4.1-py3-none-any.whl"
    wheel.write_bytes(b"test wheel")
    (root / ".env").write_text("SECRET=must-not-ship")
    (root / "private-notes.txt").write_text("private material")
    spec = importlib.util.spec_from_file_location(
        "release_support_privacy", original / "release_support.py"
    )
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    records = [
        {
            "gate": n,
            "exit_code": 0,
            "source_digest": support.source_digest(root),
            "wheel_digest": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        }
        for n in sorted(support.EXPECTED)
    ]
    (root / "release-validation/results.json").write_text(json.dumps(records))
    r = subprocess.run(
        [sys.executable, str(root / "tools/package_release.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    with zipfile.ZipFile(tmp_path / "trustwright-m1a-v0.4.1.zip") as z:
        assert "trustwright-m1a/.env" not in z.namelist()
        assert "trustwright-m1a/private-notes.txt" not in z.namelist()
