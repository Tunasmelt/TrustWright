"""Reference validator, contracts v0.3.2.

This is a *contract consistency* validator. It checks that every document is
well formed, that evidence is bound to the exact claim it supports, and that no
trust level exceeds what the server-owned ledger grants. It does not itself
observe execution or read artifacts; the server does that and records the
results in the trust ledger.

Usage:
    python tools/validate.py              # contracts + invariants
    python tools/validate.py --run-rules  # also run every pack check on its samples
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

sys.path.insert(0, str(Path(__file__).resolve().parent))
from digest import attestation_subject_digest, requirement_digest, run_record_digest  # noqa: E402
from render import TYPES as PLACEHOLDER_TYPES, placeholders as template_placeholders  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TRUSTED_VERSION_SOURCES = {"lockfile", "environment", "pinned_manifest"}
REQUIRED_CONSISTENCY_CHECKS = {"results_newer_than_test_artifact", "testcase_names_match_template",
                               "testcase_count_matches_template", "snapshot_matches_current_workspace"}
POLICIES_BY_CONTROL = {"AUTHN-ENDPOINT": {"public", "authenticated", "unknown"},
                       "AUTHZ-OWNERSHIP": {"owner_of", "unknown"},
                       "AUTHZ-ROLE": {"role", "unknown"}}
CHECK_ESTABLISHES = {"static_rule": {"specific_violation", "suspicious_pattern"},
                     "structural_check": {"structural_link"}}

# Fail closed: without a date-time format checker, jsonschema silently accepts any string.
_probe = Draft202012Validator({"type": "string", "format": "date-time"},
                              format_checker=Draft202012Validator.FORMAT_CHECKER)
if _probe.is_valid("not-a-date"):
    raise RuntimeError("date-time format is not enforced; install rfc3339-validator")


MAX_DOCUMENT_BYTES = 1_000_000
SCAN_TIMEOUT_SECONDS = 120


class LoadError(ValueError):
    pass


class _NoAliasLoader(yaml.SafeLoader):
    """SafeLoader that refuses anchors and aliases. Agent-writable documents never need them,
    and a few hundred bytes of nested aliases can expand to 10^8+ elements (alias bomb)."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise LoadError(f"YAML aliases are not allowed (line {self.peek_event().start_mark.line + 1})")
        event = self.peek_event()
        if getattr(event, "anchor", None):
            raise LoadError(f"YAML anchors are not allowed (line {event.start_mark.line + 1})")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        # Duplicate keys resolve silently last-wins: a reader sees one value, the parser uses another.
        seen = set()
        for key_node, _ in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                raise LoadError(f"mapping keys must be plain scalars (line {key_node.start_mark.line + 1})")
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise LoadError(f"duplicate key {key!r} (line {key_node.start_mark.line + 1})")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _no_duplicate_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise LoadError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _check_unicode(obj, where="document"):
    """Every string must encode as UTF-8: JSON escapes can smuggle lone surrogates, which pass
    parsing and schemas but crash any later digest or output step."""
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError:
            raise LoadError(f"{where} contains text that is not valid Unicode (lone surrogate)") from None
    elif isinstance(obj, dict):
        for k, val in obj.items():
            _check_unicode(k, where); _check_unicode(val, where)
    elif isinstance(obj, list):
        for val in obj:
            _check_unicode(val, where)


def _no_nonstandard_constants(name):
    raise LoadError(f"non-standard JSON constant {name} is not allowed")


def load(path: Path):
    """Error contract: returns a document or raises LoadError with a reason. Never any other exception."""
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > MAX_DOCUMENT_BYTES:
            raise LoadError(f"{path.name} is {size} bytes; the limit is {MAX_DOCUMENT_BYTES}")
        text = path.read_bytes().decode("utf-8")  # strict, and independent of the platform locale
        if path.suffix in {".yaml", ".yml"}:
            doc = yaml.load(text, Loader=_NoAliasLoader)
        else:
            doc = json.loads(text, object_pairs_hook=_no_duplicate_pairs, parse_constant=_no_nonstandard_constants)
        _check_unicode(doc, path.name)
        return doc
    except LoadError:
        raise
    except RecursionError:
        raise LoadError(f"{path.name} is nested too deeply") from None
    except UnicodeDecodeError as e:
        raise LoadError(f"{path.name} is not valid UTF-8 (byte {e.start})") from None
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        raise LoadError(f"{path.name} could not be parsed: {str(e).splitlines()[0]}") from None
    except (ValueError, TypeError, OSError) as e:
        raise LoadError(f"{path.name} could not be loaded: {type(e).__name__}: {str(e)[:120]}") from None


def _schema(name: str) -> Draft202012Validator:
    return Draft202012Validator(load(ROOT / "schemas" / f"{name}.schema.json"),
                                format_checker=Draft202012Validator.FORMAT_CHECKER)


def _schema_errors(name: str, doc, label: str) -> list[str]:
    out = []
    for e in _schema(name).iter_errors(doc):
        # oneOf/anyOf failures say only "not valid under any of the given schemas";
        # report the most specific sub-error so the reason is actionable.
        while e.context:
            e = best_match(_discriminated(e))
        out.append(f"{label}: {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}")
    return out


def _discriminated(e):
    """For a tagged union (alternatives distinguished by a "type" const), explain the failure
    with the alternative the instance declares itself to be, not whichever looks closest."""
    branches = e.schema.get("oneOf") or e.schema.get("anyOf") if isinstance(e.schema, dict) else None
    tag = e.instance.get("type") if isinstance(e.instance, dict) else None
    if branches and tag is not None:
        matching = {i for i, b in enumerate(branches)
                    if isinstance(b, dict) and b.get("properties", {}).get("type", {}).get("const") == tag}
        chosen = [c for c in e.context if c.relative_schema_path and c.relative_schema_path[0] in matching]
        if chosen:
            return chosen
    return e.context


def _granted(status) -> bool:
    return isinstance(status, int) and 200 <= status < 300


def _duplicates(label: str, ids) -> list[str]:
    return [f"duplicate {label} id {i!r}" for i, n in Counter(ids).items() if n > 1]


# ------------------------------------------------------------------ display

def derive_display(f: dict, checks: dict) -> tuple[str, str]:
    """Outcome first, then evidence status. Never stronger than the evidence."""
    method, result = f["method"], f["result"]
    validations = {e["validation"] for e in f["evidence"]}

    if method == "static_rule":
        return ("issue_found", "confirmed") if result == "violated" else ("needs_review", "pattern_matched")
    if method == "dependency_advisory":
        return ("issue_found", "confirmed") if result == "violated" else ("unknown", "version_unresolved")
    if method == "structural_check":
        return (("needs_review", "structurally_linked") if validations == {"structurally_linked"}
                else ("needs_review", "not_linked"))
    if method == "agent_review":
        return ("needs_review", "agent_assessed")
    if method == "intent_review":
        return ("unknown", "intent_missing")
    if method == "not_assessed":
        return ("unknown", "not_assessed")
    if method == "behavioral_test":
        status = "reproduced" if validations == {"independently_reproduced"} else "reported"
        if result == "violated":
            return ("issue_found", status)
        if result == "satisfied":
            return ("check_passed" if status == "reproduced" else "test_passed", status)
        return ("needs_review", status)
    if method == "human_review":
        return ({"violated": "issue_found", "satisfied": "check_passed"}.get(result, "needs_review"),
                "human_reviewed")
    raise ValueError(f"unhandled method {method}")


# ------------------------------------------------------------------ context

class Context:
    """Indexes built once, after schema validation and uniqueness checks."""

    def __init__(self, bundle: dict, ledger: dict):
        self.intent, self.ledger = bundle["intent"], ledger
        self.controls = {c["id"]: c for c in bundle["controls"]}
        self.runs = {r["run_id"]: r for r in bundle["runs"]}
        self.packs = {m["pack_id"]: (m, Path(d)) for m, d in bundle["packs"]}
        self.checks = {(pid, c["id"]): c for pid, (m, _) in self.packs.items() for c in m["checks"]}
        self.templates = {(pid, t["id"]): t for pid, (m, _) in self.packs.items()
                          for t in m.get("test_templates", [])}
        self.reqs = {(ep["id"], r["id"]): r for ep in self.intent["endpoints"] for r in ep["requirements"]}
        self.confirmations = {(c["endpoint_id"], c["requirement_id"]): c for c in ledger["intent_confirmations"]}
        self.observed = {o["run_id"]: o for o in ledger["observed_runs"]}
        self.attestations = {a["attestation_id"]: a for a in ledger["human_attestations"]}

    def confirmed(self, ref: tuple) -> bool:
        """Effective confirmation: the file says confirmed AND the server recorded it for this exact
        endpoint (method, path), requirement, policy, and referenced resource or role."""
        req = self.reqs.get(ref)
        if req is None or req["provenance"]["source"] != "confirmed" or req["policy"]["kind"] == "unknown":
            return False
        conf = self.confirmations.get(ref)
        return conf is not None and conf["requirement_digest"] == requirement_digest(self.intent, *ref)


# ------------------------------------------------------------------ intent

def _route_key(path: str) -> str:
    """'/documents/{doc_id}/' and '/documents/{id}' are the same route."""
    path = re.sub(r"\{[^}]*\}", "{}", path)
    return path.rstrip("/") or "/"


def check_intent(ctx: Context) -> list[str]:
    errs, intent = [], ctx.intent
    seen: dict = {}
    for ep in intent["endpoints"]:
        key = _route_key(ep["path"])
        for other_id, other_method in seen.get(key, []):
            if "ANY" in (ep["method"], other_method) or ep["method"] == other_method:
                errs.append(f"intent {ep['id']}: {ep['method']} {ep['path']} overlaps endpoint {other_id}; "
                            "one route must have one declaration")
        seen.setdefault(key, []).append((ep["id"], ep["method"]))
    principals = {p["id"]: p for p in intent["principals"]}
    resources = {r["id"] for r in intent.get("resources", [])}
    for ep in intent["endpoints"]:
        kinds = {r["policy"]["kind"] for r in ep["requirements"]}
        for r in ep["requirements"]:
            where, pol = f"intent {ep['id']}/{r['id']}", r["policy"]
            ctrl = ctx.controls.get(r["control_id"])
            if ctrl is None:
                errs.append(f"{where}: unknown control {r['control_id']}")
                continue
            if ctrl["scope"] != "endpoint":
                errs.append(f"{where}: {r['control_id']} is codebase-scoped")
            allowed = POLICIES_BY_CONTROL.get(r["control_id"])
            if allowed is not None and pol["kind"] not in allowed:
                errs.append(f"{where}: policy {pol['kind']} is not valid for {r['control_id']}")
            if pol["kind"] == "owner_of" and pol["resource"] not in resources:
                errs.append(f"{where}: resource {pol['resource']!r} is not declared")
            if pol["kind"] == "role" and principals.get(pol["role"], {}).get("kind") != "role":
                errs.append(f"{where}: role {pol['role']!r} is not a declared role principal")
            ref = (ep["id"], r["id"])
            if r["provenance"]["source"] == "confirmed" and pol["kind"] != "unknown" and not ctx.confirmed(ref):
                errs.append(f"{where}: marked confirmed, but the trust ledger has no confirmation matching its current endpoint, policy, and definitions")
        if "owner_of" in kinds and not kinds & {"authenticated", "role"}:
            errs.append(f"intent {ep['id']}: owner_of needs a separate authentication requirement")
        if "public" in kinds and kinds - {"public", "unknown"}:
            errs.append(f"intent {ep['id']}: public conflicts with other access requirements")
    return errs


# ------------------------------------------------------------------ packs

def _contained(pack_dir: Path, rel: str) -> bool:
    try:
        (pack_dir / rel).resolve().relative_to(pack_dir.resolve())  # resolve() follows symlinks
        return True
    except ValueError:
        return False


def check_packs(ctx: Context) -> list[str]:
    errs = []
    for pid, (pack, pack_dir) in ctx.packs.items():
        errs += _duplicates(f"check in {pid}", [c["id"] for c in pack["checks"]])
        errs += _duplicates(f"template in {pid}", [t["id"] for t in pack.get("test_templates", [])])
        files = [c["rule_file"] for c in pack["checks"]]
        files += [c["samples"][k] for c in pack["checks"] for k in ("should_match", "should_not_match")]
        files += [x["file"] for x in pack.get("recipes", []) + pack.get("test_templates", [])]
        for f in files:
            if not _contained(pack_dir, f):
                errs.append(f"pack {pid}: path {f!r} escapes the pack directory")
            elif not (pack_dir / f).is_file():
                errs.append(f"pack {pid}: missing file {f!r}")
        for c in pack["checks"]:
            if c["establishes"] not in CHECK_ESTABLISHES[c["kind"]]:
                errs.append(f"pack check {c['id']}: {c['kind']} cannot establish {c['establishes']}")
            if c["control_id"] not in ctx.controls:
                errs.append(f"pack check {c['id']}: unknown control {c['control_id']}")
            if _contained(pack_dir, c["rule_file"]) and (pack_dir / c["rule_file"]).is_file():
                if c["rule_id"] not in {r["id"] for r in load(pack_dir / c["rule_file"])["rules"]}:
                    errs.append(f"pack check {c['id']}: rule {c['rule_id']} not in {c['rule_file']}")
        for t in pack.get("test_templates", []):
            errs += _duplicates(f"scenario in template {t['id']}", [s["id"] for s in t["scenarios"]])
            if _contained(pack_dir, t["file"]) and (pack_dir / t["file"]).is_file():
                used = template_placeholders((pack_dir / t["file"]).read_text())
                if used != set(t["placeholders"]):
                    errs.append(f"pack template {t['id']}: file uses placeholders {sorted(used)}, declares {sorted(t['placeholders'])}")
            for s in t["scenarios"]:
                if s["control_role"] == "negative_control" and s["expect_status"] not in t["denied_statuses"]:
                    errs.append(f"pack template {t['id']}/{s['id']}: negative control must expect a denied status")
                if s["control_role"] == "positive_control" and not _granted(s["expect_status"]):
                    errs.append(f"pack template {t['id']}/{s['id']}: positive control must expect a 2xx status")
            allowed = POLICIES_BY_CONTROL.get(t["control_id"], set())
            if not set(t["supported_policies"]) <= allowed:
                errs.append(f"pack template {t['id']}: policies {t['supported_policies']} invalid for {t['control_id']}")
    return errs


# ------------------------------------------------------------------ runs

def check_runs(ctx: Context) -> list[str]:
    errs = []
    for run_id, run in ctx.runs.items():
        errs += _duplicates(f"scenario in {run_id}", [s["id"] for s in run["scenarios"]])
        t = run["test_artifact"]["template"]
        tmpl = ctx.templates.get((t["pack_id"], t["template_id"]))
        if tmpl is None:
            errs.append(f"{run_id}: template {t['template_id']} not in pack {t['pack_id']}")
            continue
        if t["template_version"] != tmpl["template_version"]:
            errs.append(f"{run_id}: template version {t['template_version']} != pack {tmpl['template_version']}")
        spec = {s["id"]: s for s in tmpl["scenarios"]}
        by_ref: dict = {}
        for s in run["scenarios"]:
            where = f"{run_id}/{s['id']}"
            exp = spec.get(s["id"])
            if exp is None:
                errs.append(f"{where}: scenario not defined by template {tmpl['id']}")
                continue
            for key in ("control_role", "principal", "expect_status", "junit_testcase"):
                if s[key] != exp[key]:
                    errs.append(f"{where}: {key} {s[key]!r} differs from template {exp[key]!r}")
            obs = s.get("observed_status")
            if s["outcome"] in {"passed", "failed"} and not isinstance(obs, int):
                errs.append(f"{where}: {s['outcome']} without a recorded observed status")
            elif s["outcome"] == "passed" and obs != s["expect_status"]:
                errs.append(f"{where}: passed, but observed {obs} != expected {s['expect_status']}")
            elif s["outcome"] == "failed" and obs == s["expect_status"]:
                errs.append(f"{where}: failed, but observed status equals expected")
            ref = (s["intent_ref"]["endpoint_id"], s["intent_ref"]["requirement_id"])
            req = ctx.reqs.get(ref)
            if req is None:
                errs.append(f"{where}: intent_ref {ref} does not resolve")
                continue
            if not ctx.confirmed(ref):
                errs.append(f"{where}: tests target a requirement without server-recorded confirmation")
            if req["control_id"] != tmpl["control_id"] or req["policy"]["kind"] not in tmpl["supported_policies"]:
                errs.append(f"{where}: template {tmpl['id']} cannot verify {req['control_id']}/{req['policy']['kind']}")
            by_ref.setdefault(ref, set()).add(s["id"])
        for ref, ids in by_ref.items():
            if ids != set(spec):
                errs.append(f"{run_id}: {ref} runs {sorted(ids)}, template requires {sorted(spec)}")

        # Trust is granted by the ledger, never by the document.
        obs = ctx.observed.get(run_id)
        claims_server = (run["evidence_validation"] == "independently_reproduced"
                         or run["runner"]["kind"] == "controlled_runner" or run["runner"]["observed_by_server"])
        if claims_server:
            if obs is None:
                errs.append(f"{run_id}: claims server observation, but the trust ledger has no record of it")
            elif obs["record_digest"] != run_record_digest(run):
                errs.append(f"{run_id}: run record differs from the server's observation "
                            "(outcomes, statuses, references, snapshot, or artifacts were changed)")
    return errs


# ------------------------------------------------------------------ findings

def _check_behavioral(f: dict, e: dict, ctx: Context, fid: str) -> list[str]:
    errs = []
    run = ctx.runs.get(e["run_id"])
    if run is None:
        return [f"{fid}: run {e['run_id']} not found"]
    if e["validation"] != run["evidence_validation"]:
        errs.append(f"{fid}: claims {e['validation']} but run is {run['evidence_validation']}")
    t = run["test_artifact"]["template"]
    tmpl = ctx.templates.get((t["pack_id"], t["template_id"]))
    if tmpl is None:
        return errs + [f"{fid}: run template not found"]
    ref = (f["intent_ref"] or {}).get("endpoint_id"), (f["intent_ref"] or {}).get("requirement_id")
    req = ctx.reqs.get(ref)
    if tmpl["control_id"] != f["control_id"]:
        errs.append(f"{fid}: template verifies {tmpl['control_id']}, finding claims {f['control_id']}")
    if req is not None and req["policy"]["kind"] not in tmpl["supported_policies"]:
        errs.append(f"{fid}: template cannot verify policy {req['policy']['kind']}")

    # No cherry-picking: cite the complete scenario set run for this requirement.
    for_ref = {s["id"]: s for s in run["scenarios"]
               if (s["intent_ref"]["endpoint_id"], s["intent_ref"]["requirement_id"]) == ref}
    if set(e["scenario_ids"]) != set(for_ref) or not for_ref:
        errs.append(f"{fid}: must cite all scenarios run for {ref} ({sorted(for_ref)}), cites {sorted(e['scenario_ids'])}")
        return errs
    cited = [for_ref[i] for i in e["scenario_ids"]]
    checks_ok = ({c["check"] for c in run["consistency_checks"]} >= REQUIRED_CONSISTENCY_CHECKS
                 and all(c["passed"] for c in run["consistency_checks"]))
    pos = [s for s in cited if s["control_role"] == "positive_control"]
    neg = [s for s in cited if s["control_role"] == "negative_control"]
    if f["result"] in {"satisfied", "violated"} and not checks_ok:
        errs.append(f"{fid}: {f['result']} requires every consistency check present and passing")
    if f["result"] == "satisfied" and any(s["outcome"] != "passed" for s in cited):
        errs.append(f"{fid}: satisfied, but not every cited scenario passed")
    if f["result"] == "violated":
        # Security failure = an unauthorized request was GRANTED (2xx) while every authorized
        # request was granted too. A different refusal (e.g. 403 vs 401) is an assertion
        # mismatch; 5xx, errors, and skips mean the app or runner is broken. Those are unknown.
        bypass = [s for s in neg if s["outcome"] == "failed" and _granted(s.get("observed_status"))]
        if not bypass:
            failed = [s for s in neg if s["outcome"] == "failed"]
            refused = [s["id"] for s in failed if s.get("observed_status") in tmpl["denied_statuses"]]
            redirected = [s["id"] for s in failed if isinstance(s.get("observed_status"), int) and 300 <= s["observed_status"] < 400]
            detail = ""
            if refused:
                detail += f" ({', '.join(refused)} refused with a different status: assertion mismatch, not a bypass)"
            if redirected:
                detail += f" ({', '.join(redirected)} redirected (3xx): not evaluated by this template, so Unknown)"
            errs.append(f"{fid}: violated requires a negative control whose request was granted (2xx){detail}")
        if any(s["outcome"] != "passed" or not _granted(s.get("observed_status")) for s in pos):
            errs.append(f"{fid}: violated requires every positive control to pass with a granted response")
        if any(s["outcome"] in {"error", "skipped"} for s in cited):
            errs.append(f"{fid}: violated cannot rest on errored or skipped scenarios")
    return errs


def _locations(f: dict):
    yield from f["scope"].get("locations", [])
    for e in f["evidence"]:
        if "location" in e:
            yield e["location"]


def check_findings(findings: list, ctx: Context) -> list[str]:
    errs = []
    for f in findings:
        fid = f["id"]
        for loc in _locations(f):
            parts = loc["path"].replace("\\", "/").split("/")
            if loc["path"].startswith(("/", "\\")) or ".." in parts or re.match(r"[A-Za-z]:", loc["path"]):
                errs.append(f"{fid}: location {loc['path']!r} is outside the workspace")
            if loc.get("end_line") is not None and loc["end_line"] < loc["start_line"]:
                errs.append(f"{fid}: location {loc['path']} ends (line {loc['end_line']}) before it starts ({loc['start_line']})")
        ctrl = ctx.controls.get(f["control_id"])
        if ctrl is None:
            errs.append(f"{fid}: unknown control {f['control_id']}")
            continue
        if ctrl["scope"] == "endpoint" and f["intent_ref"] is None:
            errs.append(f"{fid}: endpoint-scoped control needs intent_ref")
        if ctrl["scope"] == "codebase" and f["intent_ref"] is not None:
            errs.append(f"{fid}: codebase-scoped control must not reference intent")
        if f["intent_ref"]:
            ref = (f["intent_ref"]["endpoint_id"], f["intent_ref"]["requirement_id"])
            req = ctx.reqs.get(ref)
            if req is None:
                errs.append(f"{fid}: intent_ref {ref} does not resolve")
            else:
                if req["control_id"] != f["control_id"]:
                    errs.append(f"{fid}: control differs from the referenced requirement")
                confirmed = ctx.confirmed(ref)
                if not confirmed and f["method"] != "intent_review":
                    errs.append(f"{fid}: requirement {ref} lacks server-recorded confirmation; only intent_review applies")
                if confirmed and f["method"] == "intent_review":
                    errs.append(f"{fid}: intent_review used on a confirmed requirement")

        for e in f["evidence"]:
            if e["type"] in {"rule_match", "structural_link"}:
                check = ctx.checks.get((e["pack_id"], e["check_id"]))
                if check is None:
                    errs.append(f"{fid}: check {e['check_id']} not defined in pack {e['pack_id']}")
                    continue
                if check["control_id"] != f["control_id"]:
                    errs.append(f"{fid}: check {check['id']} supports {check['control_id']}, finding claims {f['control_id']}")
                if check["kind"] != f["method"]:
                    errs.append(f"{fid}: check kind {check['kind']} does not match method {f['method']}")
                if f["method"] == "static_rule":
                    need = "specific_violation" if f["result"] == "violated" else "suspicious_pattern"
                    if check["establishes"] != need:
                        errs.append(f"{fid}: result {f['result']} needs a {need} check; {check['id']} is {check['establishes']}")
                declared = {p["name"]: p["pattern"] for p in check.get("params", [])}
                supplied = e.get("params", {})
                if set(supplied) != set(declared):
                    errs.append(f"{fid}: params {sorted(supplied)} != declared {sorted(declared)}")
                if e["type"] == "structural_link" and f["intent_ref"]:
                    ep = next((x for x in ctx.intent["endpoints"] if x["id"] == f["intent_ref"]["endpoint_id"]), None)
                    if ep is not None:
                        if ep["method"] == "ANY":
                            errs.append(f"{fid}: structural evidence needs a concrete endpoint method, not ANY")
                        elif supplied.get("method") != ep["method"].lower() or supplied.get("path") != ep["path"]:
                            errs.append(f"{fid}: structural evidence targets {supplied.get('method')} {supplied.get('path')}, "
                                        f"but the finding's endpoint is {ep['method']} {ep['path']}")
                for k, v in supplied.items():
                    if k in declared and not re.fullmatch(declared[k], v):
                        errs.append(f"{fid}: param {k}={v!r} rejected by pack pattern")
            elif e["type"] == "advisory" and f["result"] == "violated":
                if e["validation"] != "advisory_matched" or e["version_source"] not in TRUSTED_VERSION_SOURCES:
                    errs.append(f"{fid}: violated advisory needs a matched advisory on a trusted version source")
            elif e["type"] == "verification_run":
                errs += _check_behavioral(f, e, ctx, fid)
            elif e["type"] == "human_attestation":
                att = ctx.attestations.get(e["attestation_id"])
                if att is None or att["finding_id"] != fid or att["reviewer"] != e["reviewer"]:
                    errs.append(f"{fid}: attestation {e['attestation_id']} is not in the trust ledger for this finding")
                elif f["intent_ref"] and (f["intent_ref"]["endpoint_id"], f["intent_ref"]["requirement_id"]) not in ctx.reqs:
                    pass  # dangling intent_ref already reported above; nothing to compare against
                elif att["subject_digest"] != attestation_subject_digest(f, ctx.intent):
                    errs.append(f"{fid}: finding content differs from what {att['reviewer']} attested "
                                "(conclusion, scope, limitations, requirement, or reviewed snapshot changed)")

        derived = derive_display(f, ctx.checks)
        stored = (f["display"]["outcome"], f["display"]["status"])
        if derived != stored:
            errs.append(f"{fid}: display {stored} but evidence supports {derived}")
        if derived != ("issue_found", "confirmed") and not f["limitations"]:
            errs.append(f"{fid}: must state limitations")
    return errs


# ------------------------------------------------------------------ rule tests

def substitute_params(text: str, values: dict) -> str:
    """One pass, so a value containing another placeholder (e.g. a path of '/__DEPENDENCY__')
    is inserted literally and never re-substituted."""
    return re.sub(r"__([A-Z][A-Z0-9_]*)__",
                  lambda m: values[m.group(1).lower()] if m.group(1).lower() in values else m.group(0), text)


def run_rule_tests(pack: dict, pack_dir: Path, engine: str | None = None) -> list[str]:
    engine = engine or shutil.which("opengrep") or shutil.which("semgrep")
    if engine is None:
        return ["--run-rules: neither opengrep nor semgrep is installed"]
    errs = []
    for c in pack["checks"]:
        samples, label = c["samples"], f"rule {c['rule_id']}"
        rules = load(pack_dir / c["rule_file"])
        rules["rules"] = [r for r in rules["rules"] if r["id"] == c["rule_id"]]
        text = yaml.safe_dump(rules, sort_keys=False)
        if c["kind"] == "structural_check":
            declared = {p["name"]: p["pattern"] for p in c.get("params", [])}
            supplied = samples.get("params", {})
            if set(supplied) != set(declared) or any(not re.fullmatch(declared[k], v) for k, v in supplied.items()):
                errs.append(f"{label}: sample params missing or invalid")
                continue
            text = substitute_params(text, supplied)
        # P5-05: rule configs (which can contain agent-supplied values) live only for the scan.
        with tempfile.TemporaryDirectory() as scratch:
            config = Path(scratch) / "rule.yaml"
            config.write_text(text)
            errs += _scan_samples(c, samples, label, pack_dir, engine, config)
    return errs


def _scan_samples(c, samples, label, pack_dir, engine, config) -> list[str]:
    errs = []
    for key in ("should_match", "should_not_match"):
        telemetry = [] if Path(engine).name == "opengrep" else ["--metrics=off"]
        try:
            out = subprocess.run([engine, "scan", *telemetry, "--config", str(config), "--json", "-q",
                                  str(pack_dir / samples[key])], capture_output=True, text=True,
                                 timeout=SCAN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            errs.append(f"{label}: {key}: engine exceeded {SCAN_TIMEOUT_SECONDS}s and was stopped")
            continue
        # Policy: exit 0 and well-formed output, or the test fails. A crash or a
        # failure exit must never read as "0 matches" or as a valid result.
        if out.returncode != 0:
            errs.append(f"{label}: {key}: engine exited {out.returncode}")
            continue
        try:
            data = json.loads(out.stdout)
        except json.JSONDecodeError:
            errs.append(f"{label}: {key}: engine output is not JSON")
            continue
        if (not isinstance(data, dict) or not isinstance(data.get("results"), list)
                or not isinstance(data.get("errors"), list)):
            errs.append(f"{label}: {key}: engine output missing results/errors lists")
            continue
        if data["errors"]:
            errs.append(f"{label}: {key}: engine reported errors")
            continue
        try:
            hits = sorted(r["start"]["line"] for r in data["results"]
                          if str(r["check_id"]).split(".")[-1] == c["rule_id"])
            other = [r for r in data["results"] if str(r["check_id"]).split(".")[-1] != c["rule_id"]]
        except (KeyError, TypeError):
            errs.append(f"{label}: {key}: malformed result entries")
            continue
        if other:
            errs.append(f"{label}: {key}: unexpected results from other rules")
        expected = sorted(samples["expected_lines"]) if key == "should_match" else []
        if hits != expected:
            errs.append(f"{label}: {key}: matched lines {hits}, expected {expected}")
    return errs


# ------------------------------------------------------------------ main

def validate(bundle: dict, ledger: dict, *, run_rules: bool = False, engine: str | None = None) -> list[str]:
    """Fail closed: an unexpected internal error is reported as a failure, never raised or passed."""
    try:
        return _validate(bundle, ledger, run_rules=run_rules, engine=engine)
    except Exception as e:  # noqa: BLE001
        return [f"internal validator error (failing closed): {type(e).__name__}: {e}"]


def _validate(bundle: dict, ledger: dict, *, run_rules: bool = False, engine: str | None = None) -> list[str]:
    # Documents may also arrive as objects (from the server), not only via load().
    for label, doc in (("intent", bundle.get("intent")), ("ledger", ledger), ("findings", bundle.get("findings")),
                       ("runs", bundle.get("runs"))):
        try:
            _check_unicode(doc, label)
        except LoadError as e:
            return [str(e)]
    errs = _schema_errors("security-intent", bundle["intent"], "intent")
    errs += _schema_errors("trust-ledger", ledger, "ledger")
    for f in bundle["findings"]:
        errs += _schema_errors("finding", f, f.get("id", "finding"))
    for r in bundle["runs"]:
        errs += _schema_errors("verification-run", r, r.get("run_id", "run"))
    for m, _ in bundle["packs"]:
        errs += _schema_errors("pack-manifest", m, f"pack {m.get('pack_id')}")
    if errs:
        return errs  # cross-checks assume schema-valid documents

    intent = bundle["intent"]
    errs += _duplicates("finding", [f["id"] for f in bundle["findings"]])
    errs += _duplicates("run", [r["run_id"] for r in bundle["runs"]])
    errs += _duplicates("pack", [m["pack_id"] for m, _ in bundle["packs"]])
    errs += _duplicates("control", [c["id"] for c in bundle["controls"]])
    errs += _duplicates("endpoint", [e["id"] for e in intent["endpoints"]])
    errs += _duplicates("requirement", [r["id"] for e in intent["endpoints"] for r in e["requirements"]])
    errs += _duplicates("principal", [p["id"] for p in intent["principals"]])
    errs += _duplicates("resource", [r["id"] for r in intent.get("resources", [])])
    errs += _duplicates("ledger confirmation request", [c["request_id"] for c in ledger["intent_confirmations"]])
    errs += _duplicates("ledger run", [o["run_id"] for o in ledger["observed_runs"]])
    errs += _duplicates("attestation", [a["attestation_id"] for a in ledger["human_attestations"]])
    errs += _duplicates("ledger confirmation", [f"{c['endpoint_id']}/{c['requirement_id']}" for c in ledger["intent_confirmations"]])
    if errs:
        return errs  # indexes would silently overwrite colliding entries

    ctx = Context(bundle, ledger)
    errs += check_intent(ctx)
    errs += check_packs(ctx)
    if run_rules and not errs:
        for pack, pack_dir in ctx.packs.values():
            errs += run_rule_tests(pack, pack_dir, engine)
    errs += check_runs(ctx)
    errs += check_findings(bundle["findings"], ctx)
    return errs


def load_examples() -> tuple[dict, dict]:
    ex = ROOT / "examples"
    bundle = {
        "controls": load(ROOT / "catalogue" / "controls.yaml")["controls"],
        "intent": load(ex / "security-intent.yaml"),
        "findings": load(ex / "findings.json"),
        "runs": [load(p) for p in sorted(ex.glob("verification-run.*.json"))],
        "packs": [(load(m), m.parent) for m in sorted((ROOT / "packs").glob("*/pack.yaml"))],
    }
    return bundle, load(ex / "trust-ledger.json")


if __name__ == "__main__":
    bundle, ledger = load_examples()
    problems = validate(bundle, ledger, run_rules="--run-rules" in sys.argv)
    for p in problems:
        print("FAIL", p)
    if problems:
        sys.exit(1)
    ctx = Context(bundle, ledger)
    for f in bundle["findings"]:
        o, s = derive_display(f, ctx.checks)
        print(f"{f['id']}  {f['control_id']:<20} {o.replace('_', ' ').capitalize()} · {s.replace('_', ' ')}")
    print(f"\nOK: {len(bundle['findings'])} findings, {len(bundle['runs'])} runs, {len(bundle['packs'])} pack(s) valid")
