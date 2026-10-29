"""Revised M1a gate G3/G4: every declared requirement is visible once; discovery problems keep distinct reasons."""

from conftest import choose_fixture_intent
import platform

import yaml

from trustwright.contracts import digest
from trustwright.project import routes


def confirm(service, policy_kind):
    r = next(x for x in service.validate_intent()["requirements"] if x["policy_kind"] == policy_kind)
    pending = service.prepare_confirmation(r["endpoint_ref"], r["requirement_ref"])
    service.finish_confirmation(pending["request_id"], True, "cli_prompt")
    return r


def entries(report):
    found = [x["finding"] for x in report["unknowns"]]
    if report["current"]:
        found += [x["finding"] for x in report["current"][0]["findings"]]
    by_ref = {}
    for f in found:
        if f["intent_ref"]:
            key = (f["intent_ref"]["endpoint_id"], f["intent_ref"]["requirement_id"])
            by_ref.setdefault(key, []).append(f)
    return by_ref


def entry(report, r):
    found = entries(report).get((r["endpoint_ref"], r["requirement_ref"]), [])
    assert len(found) == 1, f"requirement must be reported exactly once, found {len(found)}"
    return found[0]


def not_assessed_reason(f):
    assert f["display"] == {"outcome": "unknown", "status": "not_assessed"}
    return f["evidence"][0]["reason"]


def test_every_requirement_reported_exactly_once(service):
    service.draft_intent()
    choose_fixture_intent(service)
    confirmed = confirm(service, "authenticated")
    requirements = service.validate_intent()["requirements"]
    report = service.get_report()
    assert set(entries(report)) == {(r["endpoint_ref"], r["requirement_ref"]) for r in requirements}
    assert not_assessed_reason(entry(report, confirmed)) == "not_assessed:no_current_assessment"
    service.run_checks()
    report = service.get_report()
    for r in requirements:
        f = entry(report, r)
        if r["status"] != "confirmed":
            assert f["display"] == {"outcome": "unknown", "status": "intent_missing"}


def test_confirmed_requirement_on_unresolved_route_is_not_assessed(service):
    service.draft_intent()
    choose_fixture_intent(service)
    r = confirm(service, "authenticated")
    app = service.root / "app.py"
    app.write_text(app.read_text().replace('@app.get("/documents/{doc_id}")', '@router.get("/documents/{doc_id}")'))
    service.run_checks()
    report = service.get_report()
    assert not_assessed_reason(entry(report, r)) == "not_assessed:route_not_resolved"
    rows = [c for c in report["current"][0]["coverage"] if c.get("requirement_ref") == r["requirement_ref"]]
    assert [c["reason"] for c in rows] == ["route_not_resolved"]
    assert rows[0]["endpoint_ref"] == r["endpoint_ref"]


def test_confirmed_public_requirement_has_no_applicable_check(service):
    service.draft_intent()
    intent = yaml.safe_load(service.intent_path.read_text())
    exports = next(ep for ep in intent["endpoints"] if ep["path"] == "/exports")
    exports["requirements"][0]["policy"] = {"kind": "public"}
    service.intent_path.write_text(yaml.safe_dump(intent))
    r = confirm(service, "public")
    service.run_checks()
    assert not_assessed_reason(entry(service.get_report(), r)) == "not_assessed:no_applicable_check"


def test_discovery_problems_have_distinct_reasons():
    sources = {
        "api.py": b'from fastapi import APIRouter\nrouter = APIRouter()\n@router.get("/items")\ndef items():\n    pass\n',
        "broken.py": b"def broken(:\n    pass\n",
        "dynamic.py": b'from fastapi import FastAPI\napp = FastAPI()\nPATH = "/x"\n@app.get(PATH)\ndef x():\n    pass\n',
        "multi.py": b'from fastapi import FastAPI\napp = FastAPI()\n@app.api_route("/y", methods=["GET"])\ndef y():\n    pass\n',
    }
    _, errors = routes(sources)
    by_file = {file: [e for e in errors if e["scope_ref"] == routes_ref(file)] for file in sources}
    assert [e["reason"] for e in by_file["api.py"]] == ["unsupported_route_form"]
    assert [e["reason"] for e in by_file["dynamic.py"]] == ["unresolved_dynamic_route"]
    assert [e["reason"] for e in by_file["multi.py"]] == ["unsupported_route_form"]
    assert by_file["broken.py"] == [
        {"scope_ref": routes_ref("broken.py"), "reason": "source_parse_error", "python_version": platform.python_version()}
    ]


def test_router_file_is_not_reported_as_parse_error(service):
    (service.root / "api.py").write_text(
        'from fastapi import APIRouter\nrouter = APIRouter()\n@router.get("/items")\ndef items():\n    pass\n'
    )
    service.draft_intent()
    service.run_checks()
    report = service.get_report()
    reasons = {g["reason"] for g in report["discovery_gaps"]}
    discovery = [c for c in report["current"][0]["coverage"] if c["check_id"] == "route-discovery"]
    assert "unsupported_route_form" in reasons and "source_parse_error" not in reasons
    assert [c["reason"] for c in discovery] == ["unsupported_route_form"]


def routes_ref(file):
    return "file-" + digest(file)[:16]
