"""Regressions from the supplied 0.4.1 verification archive."""

import errno
from pathlib import Path
import pytest
import yaml
from trustwright.safety import Refused


def db_project(service, multiple=True):
    (service.root / "app.py").write_text("""from fastapi import Depends, FastAPI
app = FastAPI()
def get_db():
    yield {}
def get_settings():
    return {}
@app.get("/admin/users")
def users(db=Depends(get_db), config=Depends(get_settings)):
    return {}
""")
    if not multiple:
        p = service.root / "app.py"
        p.write_text(p.read_text().replace(", config=Depends(get_settings)", ""))
    return service.draft_intent()["requirements"][0]


def test_dependencies_do_not_infer_authentication(service):
    req = db_project(service, multiple=False)
    assert req["policy_kind"] == "unknown"
    with pytest.raises(Refused, match="unknown_policy_cannot_be_confirmed"):
        service.prepare_confirmation(req["endpoint_ref"], req["requirement_ref"])


def test_supplied_dependency_link_is_not_authentication(service):
    req = db_project(service)
    intent = yaml.safe_load(service.intent_path.read_text())
    intent["endpoints"][0]["requirements"][0]["policy"] = {"kind": "authenticated"}
    service.intent_path.write_text(yaml.safe_dump(intent))
    p = service.prepare_confirmation(req["endpoint_ref"], req["requirement_ref"])
    service.finish_confirmation(p["request_id"], True, "cli_prompt")
    service.run_checks(
        bindings=[
            {k: req[k] for k in ("endpoint_ref", "requirement_ref")} | {"dependency": "get_db"}
        ]
    )
    findings = [
        x["finding"]
        for a in service.get_report()["current"]
        for x in a["findings"]
        if x["finding"]["method"] == "structural_check"
    ]
    assert len(findings) == 1
    f = findings[0]
    assert f["result"] == "unknown"
    assert f["display"] == {"outcome": "needs_review", "status": "structurally_linked"}
    assert f["evidence"][0]["binding_source"] == "agent_supplied"
    assert f["evidence"][0]["authentication_semantics"] == "unverified"
    assert any("not evidence" in x for x in f["limitations"])


def test_discovered_dependency_retains_unverified_origin(service):
    from conftest import choose_fixture_intent

    service.draft_intent()
    r = next(
        x
        for x in choose_fixture_intent(service)["requirements"]
        if x["policy_kind"] == "authenticated"
    )
    p = service.prepare_confirmation(r["endpoint_ref"], r["requirement_ref"])
    service.finish_confirmation(p["request_id"], True, "cli_prompt")
    service.run_checks()
    f = next(
        x["finding"]
        for x in service.get_report()["current"][0]["findings"]
        if x["finding"]["method"] == "structural_check"
    )
    assert f["display"]["outcome"] == "needs_review"
    assert f["evidence"][0]["binding_source"] == "static_discovery"
    assert f["evidence"][0]["authentication_semantics"] == "unverified"


def test_symlink_cycle_refused_with_permissive_resolve(tmp_path, monkeypatch):
    from digest import _resolve_link

    link = tmp_path / "cycle"
    link.symlink_to("cycle")
    monkeypatch.setattr(Path, "resolve", lambda self, **kwargs: self)
    with pytest.raises(RuntimeError, match="symlink loop"):
        _resolve_link(link)


def test_symlink_resolution_permission_errors_propagate(tmp_path, monkeypatch):
    import digest

    def denied(*args, **kwargs):
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(digest.os, "stat", denied)
    with pytest.raises(PermissionError):
        digest._resolve_link(tmp_path / "link")


def test_dangling_symlink_digest_remains_supported(tmp_path):
    from digest import tree_digest

    (tmp_path / "dangling").symlink_to("absent")
    _, count = tree_digest(tmp_path)
    assert count == 1


def test_legacy_structural_projection_cannot_keep_wiring_claim(service):
    f = service.make_finding(
        "AUTHN-ENDPOINT",
        "structural_check",
        {
            "type": "structural_link",
            "validation": "structurally_linked",
            "pack_id": "fastapi-pyjwt-pwdlib",
            "check_id": "route-depends-on",
            "params": {"method": "get", "path": "/x", "dependency": "get_db"},
        },
        {"kind": "endpoint", "ref": "endpoint"},
        limitations=["Legacy evidence"],
    )
    f["display"] = {"outcome": "wiring_found", "status": "structurally_linked"}
    projected = service.public_finding(f)["finding"]
    assert projected["display"]["outcome"] == "needs_review"
    assert projected["evidence"][0]["binding_source"] == "legacy_unspecified"
    assert projected["evidence"][0]["authentication_semantics"] == "unverified"
    assert f["display"]["outcome"] == "wiring_found", "projection must not rewrite stored history"
