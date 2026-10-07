"""M1a application service; all project text is untrusted input."""

import copy
import hashlib
import json
import shutil
import time
from pathlib import Path

import yaml

from . import __version__
from .contracts import (
    PACK,
    PACK_DIR,
    PACK_ID,
    bundle,
    digest,
    load,
    requirement_digest,
    validator,
)
from .project import EXCLUDED, detect, routes, snapshot
from .safety import Refused, atomic_write, read_regular
from .scanner import engine_identity, scan
from .state import State, now

LIMITATIONS = [
    "M1a performs static assessment and guidance; no project execution, behavioral verification, secret scanning, or advisory lookup.",
    "No rule match is not a pass. Structural wiring does not prove authentication or authorization.",
    "Only direct FastAPI route declarations and pack-defined wiring forms are inspected; router prefixes, app/router dependencies, dynamic routes, and other stacks are uncovered.",
    "Confirmation trusts the developer-facing client or terminal. Same-user shell access can alter server state.",
    "Snapshots cover Python source and supported dependency files, excluding credential files, build/dependency directories and .trustwright metadata. They do not describe deployment configuration.",
    "Repository-authored text and source excerpts are withheld from MCP output; opaque references can be mapped using the local intent and assessment artifacts.",
]


class Service:
    def __init__(self, root, state_dir=None, engine=None):
        raw = Path(root).absolute()
        for p in (raw, *raw.parents):
            if p.is_symlink():
                raise Refused("workspace_symlink_refused")
        self.root = raw.resolve()
        if not self.root.is_dir():
            raise Refused("workspace_not_directory")
        self.state = State(self.root, state_dir)
        self.engine = str(Path(engine).resolve()) if engine else shutil.which("opengrep")
        self.intent_path = self.root / ".trustwright/security-intent.yaml"

    def read_intent(self):
        read_regular(self.intent_path)
        try:
            intent = load(self.intent_path)
        except Exception:
            raise Refused("intent_document_malformed") from None
        if list(validator._schema("security-intent").iter_errors(intent)):
            raise Refused("intent_schema_invalid")
        # File provenance never grants trust. Normalize it before semantic checks.
        normalized = copy.deepcopy(intent)
        for ep in normalized["endpoints"]:
            for r in ep["requirements"]:
                r["provenance"]["source"] = "inferred"
        if validator.validate(bundle(normalized), self.state.read()["ledger"]):
            raise Refused("intent_semantics_invalid")
        return intent

    def effective(self, intent, ledger):
        intent = copy.deepcopy(intent)
        confirmations = {
            (c["endpoint_id"], c["requirement_id"]): c for c in ledger["intent_confirmations"]
        }
        for ep in intent["endpoints"]:
            for r in ep["requirements"]:
                c = confirmations.get((ep["id"], r["id"]))
                matched = (
                    c
                    and c["requirement_digest"] == requirement_digest(intent, ep["id"], r["id"])
                    and r["policy"]["kind"] != "unknown"
                )
                r["provenance"]["source"] = "confirmed" if matched else "inferred"
        return intent

    def detect_stack(self):
        return detect(snapshot(self.root))

    def draft_intent(self):
        if self.intent_path.exists():
            raise Refused("intent_already_exists: edit the existing file locally")
        entries, errors = routes(snapshot(self.root))
        if not entries:
            raise Refused("no_supported_routes: create an intent document using the schema")
        endpoints = []
        seen = set()
        for route in entries:
            key = (route["method"], route["path"])
            if key in seen:
                continue
            seen.add(key)
            eid = "route-" + digest(key)[:12]
            endpoints.append(
                dict(
                    id=eid,
                    method=route["method"],
                    path=route["path"],
                    requirements=[
                        dict(
                            id=eid + "-authn",
                            control_id="AUTHN-ENDPOINT",
                            policy={"kind": "unknown"},
                            provenance=dict(
                                source="inferred",
                                by="trustwright",
                                at=now(),
                                rationale="Static route discovery; developer must choose intended policy.",
                            ),
                        )
                    ],
                )
            )
        intent = dict(
            schema_version="0.4",
            project={"name": "workspace"},
            unconfirmed_policy="report_as_unknown",
            principals=[
                {"id": "anonymous", "kind": "anonymous"},
                {"id": "user", "kind": "user"},
            ],
            endpoints=endpoints,
        )
        if validator.validate(bundle(intent), self.state.read()["ledger"]):
            raise Refused("draft_invalid")
        self.intent_path.parent.mkdir(exist_ok=True, mode=0o700)
        atomic_write(self.intent_path, yaml.safe_dump(intent, sort_keys=False).encode())
        return {
            "written": ".trustwright/security-intent.yaml",
            "requirements": self.requirement_summary(intent),
            "discovery_errors": errors,
            "status": "inferred",
            "limitations": LIMITATIONS[2:3],
        }

    def requirement_summary(self, intent):
        # IDs generated by us can be returned; arbitrary agent-authored IDs are mapped to references.
        return [
            {
                "endpoint_ref": self.ref(ep["id"]),
                "requirement_ref": self.ref(r["id"]),
                "control_id": r["control_id"],
                "policy_kind": r["policy"]["kind"],
                "status": r["provenance"]["source"],
                "untrusted_text": {
                    "source": "security-intent",
                    "text": "[Repository-authored labels and route text withheld; inspect the local intent file.]",
                },
            }
            for ep in intent["endpoints"]
            for r in ep["requirements"]
        ]

    @staticmethod
    def ref(value):
        return "ref-" + digest(value)[:20]

    def resolve(self, intent, endpoint_ref, requirement_ref):
        for ep in intent["endpoints"]:
            for r in ep["requirements"]:
                if self.ref(ep["id"]) == endpoint_ref and self.ref(r["id"]) == requirement_ref:
                    return ep, r
        raise Refused("requirement_not_found")

    def validate_intent(self):
        intent = self.read_intent()
        ledger = self.state.read()["ledger"]
        effective = self.effective(intent, ledger)
        forged = any(
            r["provenance"]["source"] == "confirmed" and er["provenance"]["source"] != "confirmed"
            for ep, eep in zip(intent["endpoints"], effective["endpoints"])
            for r, er in zip(ep["requirements"], eep["requirements"])
        )
        return {
            "valid": not forged,
            "reason": "untrusted_confirmation_claim" if forged else "valid",
            "intent_digest": digest(intent),
            "requirements": self.requirement_summary(effective),
        }

    def prepare_confirmation(self, endpoint_ref, requirement_ref):
        intent = self.read_intent()
        ep, r = self.resolve(intent, endpoint_ref, requirement_ref)
        if r["policy"]["kind"] == "unknown":
            raise Refused("unknown_policy_cannot_be_confirmed: edit intended policy first")
        request_id = self.state.request(intent, ep["id"], r["id"])
        return {
            "request_id": request_id,
            "status": "pending",
            "requirement_digest": requirement_digest(intent, ep["id"], r["id"]),
            "endpoint_ref": endpoint_ref,
            "requirement_ref": requirement_ref,
            "policy_kind": r["policy"]["kind"],
            "intent_position": {
                "endpoint": intent["endpoints"].index(ep) + 1,
                "requirement": ep["requirements"].index(r) + 1,
            },
            "expires_in_seconds": 900,
            "fallback_command": "trustwright confirm " + request_id,
            "untrusted_text": {
                "source": "security-intent",
                "text": "[Review the exact requirement in the local intent file before approving.]",
            },
        }

    def finish_confirmation(self, request_id, approved, channel):
        return self.state.complete(request_id, self.read_intent(), approved, channel)

    def input_state(self, files, intent, ledger, engine):
        packs = {
            p.relative_to(PACK_DIR).as_posix(): read_regular(p).hex()
            for p in PACK_DIR.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
        }
        manifests = {p: v.hex() for p, v in files.items() if not p.endswith(".py")}
        return {
            "workspace_id": self.state.workspace_id,
            "code_digest": digest({p: v.hex() for p, v in files.items() if p.endswith(".py")}),
            "intent_digest": digest(intent),
            "confirmation_digest": digest(ledger["intent_confirmations"]),
            "check_configuration_digest": self.state.read().get(
                "active_bindings_digest", digest([])
            ),
            "packs_digest": digest(packs),
            "dependencies_digest": digest(manifests),
            "configuration_digest": digest(
                {
                    "version": __version__,
                    "excluded": sorted(EXCLUDED),
                    "engine": engine,
                    "caps": [500, 20_000_000, 1_000_000],
                    "discovery": "direct-fastapi-v1",
                }
            ),
            "engine": engine,
            "advisory": {"status": "not_queried", "checked_at": None},
            "scope": "Python source and supported dependency manifests only; deployment and runtime not assessed",
        }

    def make_finding(self, control, method, evidence, scope, intent_ref=None, limitations=()):
        f = dict(
            id="F-" + str(int(digest([control, method, evidence, intent_ref])[:20], 16)),
            control_id=control,
            intent_ref=intent_ref,
            scope=scope,
            result="unknown",
            method=method,
            evidence=[evidence],
            limitations=list(limitations),
        )
        a, b = validator.derive_display(f, {})
        f["display"] = {"outcome": a, "status": b}
        if control == "TOKEN-INTEGRITY":
            f["recipe_ref"] = {"pack_id": PACK_ID, "recipe_id": "verify-token"}
        return f

    def unknowns(self, intent):
        result = []
        for ep in intent["endpoints"]:
            for r in ep["requirements"]:
                if r["provenance"]["source"] != "confirmed" or r["policy"]["kind"] == "unknown":
                    result.append(
                        self.make_finding(
                            r["control_id"],
                            "intent_review",
                            {
                                "type": "intent_gap",
                                "validation": "unchecked",
                                "reason": "policy_unknown"
                                if r["policy"]["kind"] == "unknown"
                                else "policy_inferred_not_confirmed",
                            },
                            {"kind": "endpoint", "ref": ep["id"]},
                            {"endpoint_id": ep["id"], "requirement_id": r["id"]},
                            [
                                "Developer intent has not been established; no endpoint check conclusion applies."
                            ],
                        )
                    )
        return result

    def run_checks(self, bindings=None):
        started = time.monotonic()
        files = snapshot(self.root)
        intent = self.read_intent()
        ledger = self.state.read()["ledger"]
        effective = self.effective(intent, ledger)
        engine = engine_identity(self.engine, self.root)
        findings = []
        coverage = []
        detected = detect(files)
        discovered, parse_errors = routes(files)
        supplied = {}
        for binding in bindings or []:
            ep, r = self.resolve(intent, binding["endpoint_ref"], binding["requirement_ref"])
            key = (ep["id"], r["id"])
            if key in supplied:
                raise Refused("duplicate_structural_binding")
            supplied[key] = binding["dependency"]
        with self.state.transaction() as state:
            state["active_bindings_digest"] = digest(bindings or [])
        inputs = self.input_state(files, intent, ledger, engine)
        if parse_errors:
            coverage.append(
                {
                    "check_id": "route-discovery",
                    "status": "error",
                    "reason": "source_parse_error",
                    "matches": 0,
                }
            )
        applicable = PACK_ID in detected["applicable_packs"]
        for check in PACK["checks"]:
            tasks = []
            if check["kind"] == "static_rule":
                tasks = [(None, None, None)]
            else:
                for ep in effective["endpoints"]:
                    for r in ep["requirements"]:
                        if (
                            r["control_id"] != check["control_id"]
                            or r["provenance"]["source"] != "confirmed"
                            or r["policy"]["kind"] != "authenticated"
                        ):
                            continue
                        candidates = [
                            x
                            for x in discovered
                            if x["method"] == ep["method"] and x["path"] == ep["path"]
                        ]
                        if len(candidates) != 1:
                            coverage.append(
                                {
                                    "check_id": check["id"],
                                    "status": "not_run",
                                    "reason": "route_binding_ambiguous"
                                    if candidates
                                    else "route_not_resolved",
                                    "matches": 0,
                                }
                            )
                            continue
                        deps = {x["dependency"] for x in candidates if x["dependency"]}
                        if (ep["id"], r["id"]) in supplied:
                            deps = {supplied[(ep["id"], r["id"])]}
                        if len(deps) != 1:
                            coverage.append(
                                {
                                    "check_id": check["id"],
                                    "status": "not_run",
                                    "reason": "dependency_binding_unresolved",
                                    "matches": 0,
                                }
                            )
                            continue
                        tasks.append(
                            (
                                ep,
                                r,
                                dict(
                                    method=ep["method"].lower(),
                                    path=ep["path"],
                                    dependency=next(iter(deps)),
                                ),
                            )
                        )
            for ep, r, params in tasks:
                if time.monotonic() - started > 180:
                    raise Refused("assessment_time_budget_exceeded")
                if not applicable or engine["status"] != "available":
                    coverage.append(
                        {
                            "check_id": check["id"],
                            "status": "not_run",
                            "reason": "pack_not_applicable"
                            if not applicable
                            else "scanner_unavailable",
                            "matches": 0,
                        }
                    )
                    continue
                try:
                    targets = files
                    if ep is not None:
                        candidate = next(
                            x
                            for x in discovered
                            if x["method"] == ep["method"] and x["path"] == ep["path"]
                        )
                        targets = {candidate["file"]: files[candidate["file"]]}
                    hits = scan(
                        self.engine,
                        targets,
                        check,
                        params,
                        target=candidate if ep is not None else None,
                    )
                    if ep is not None:
                        hits = [
                            h
                            for h in hits
                            if candidate["line"] <= h["start_line"] <= candidate["end_line"]
                        ]
                except Refused as e:
                    coverage.append(
                        {
                            "check_id": check["id"],
                            "status": "error",
                            "reason": str(e),
                            "matches": 0,
                        }
                    )
                    continue
                coverage.append(
                    {
                        "check_id": check["id"],
                        "status": "completed",
                        "reason": "matches" if hits else "no_matches_not_a_pass",
                        "matches": len(hits),
                    }
                )
                if ep is None:
                    for hit in hits:
                        loc = {
                            **hit,
                            "content_sha256": hashlib.sha256(files[hit["path"]]).hexdigest(),
                        }
                        findings.append(
                            self.make_finding(
                                check["control_id"],
                                "static_rule",
                                dict(
                                    type="rule_match",
                                    validation="rule_matched",
                                    pack_id=PACK_ID,
                                    check_id=check["id"],
                                    location=loc,
                                ),
                                dict(kind="function", ref=hit["path"], locations=[loc]),
                                limitations=check["cannot_establish"],
                            )
                        )
                else:
                    evidence = dict(
                        type="structural_link",
                        validation="structurally_linked" if hits else "not_linked",
                        pack_id=PACK_ID,
                        check_id=check["id"],
                        params=params,
                        binding_source="agent_supplied"
                        if (ep["id"], r["id"]) in supplied
                        else "static_discovery",
                        authentication_semantics="unverified",
                    )
                    if hits:
                        evidence["location"] = hits[0]
                    findings.append(
                        self.make_finding(
                            check["control_id"],
                            "structural_check",
                            evidence,
                            dict(kind="endpoint", ref=ep["id"]),
                            dict(endpoint_id=ep["id"], requirement_id=r["id"]),
                            check["cannot_establish"]
                            + [
                                "Only a dependency reference is checked. Its authentication behavior is unverified; this is not evidence that the endpoint enforces authentication.",
                            ],
                        )
                    )
        findings += self.unknowns(effective)
        if validator.validate(bundle(effective, findings), ledger):
            raise Refused("generated_findings_invalid")
        # Abort on changing inputs. Scan findings only describe the immutable copied bytes.
        if (
            self.input_state(
                snapshot(self.root),
                self.read_intent(),
                self.state.read()["ledger"],
                engine,
            )
            != inputs
        ):
            raise Refused("assessment_inputs_changed")
        assessment = {
            "id": "assessment-" + digest([inputs, now()])[:20],
            "created_at": now(),
            "inputs": inputs,
            "findings": findings,
            "coverage": coverage,
        }
        with self.state.transaction() as d:
            d["assessments"] = (d["assessments"] + [assessment])[-10:]
        # Local mapping is intentionally not returned through MCP.
        out = self.intent_path.parent / "last-assessment.json"
        labels = list(files)
        for ep in intent["endpoints"]:
            labels.extend([ep["id"], ep["path"]])
            labels.extend(r["id"] for r in ep["requirements"])
        local = {**assessment, "reference_map": {self.ref(label): label for label in labels}}
        atomic_write(out, json.dumps(local, indent=2).encode())
        return {
            "assessment_id": assessment["id"],
            "findings_count": len(findings),
            "coverage": coverage,
            "local_artifact": ".trustwright/last-assessment.json",
            "report_tool": "get_report",
        }

    def get_recipe(self, pack_id=PACK_ID, recipe_id="verify-token"):
        if pack_id != PACK_ID:
            raise Refused("pack_not_found")
        recipe = next((r for r in PACK["recipes"] if r["id"] == recipe_id), None)
        if not recipe:
            raise Refused("recipe_not_found")
        return {
            "pack_id": pack_id,
            "recipe_id": recipe_id,
            "control_id": recipe["control_id"],
            "tested_versions": recipe["tested_versions"],
            "content": (PACK_DIR / recipe["file"]).read_text(),
            "limitations": [
                "Trusted bundled recipe; adapt and review locally. M1a does not execute or verify the implementation."
            ],
        }

    def public_finding(self, f):
        """Keep the typed conclusion, suppress all workspace-origin strings (not heuristic redaction)."""
        f = json.loads(json.dumps(f))  # break shared aliases before per-field redaction
        if f["method"] == "structural_check":
            outcome, status = validator.derive_display(f, {})
            f["display"] = {"outcome": outcome, "status": status}
            for evidence in f["evidence"]:
                if evidence["type"] == "structural_link":
                    evidence.setdefault("binding_source", "legacy_unspecified")
                    evidence["authentication_semantics"] = "unverified"
            limitation = "Dependency-reference evidence does not establish authentication behavior."
            if limitation not in f["limitations"]:
                f["limitations"].append(limitation)
        f["scope"]["ref"] = self.ref(f["scope"]["ref"])
        for loc in f["scope"].get("locations", []):
            loc["path"] = "source/" + self.ref(loc["path"]) + ".py"
        if f["intent_ref"]:
            f["intent_ref"] = {k: self.ref(v) for k, v in f["intent_ref"].items()}
        for e in f["evidence"]:
            if "location" in e:
                e["location"]["path"] = "source/" + self.ref(e["location"]["path"]) + ".py"
            if "params" in e:
                # Report projection retains evidence identity without emitting arbitrary route/dependency strings.
                e["params"]["path"] = "/" + self.ref(e["params"]["path"])
                e["params"]["dependency"] = "dependency_" + digest(e["params"]["dependency"])[:20]
        return {
            "finding": f,
            "untrusted_text": {
                "source": "workspace",
                "text": "[Source text withheld. Opaque references map to the local assessment artifact.]",
            },
        }

    def get_report(self):
        files = snapshot(self.root)
        intent = self.read_intent()
        d = self.state.read()
        engine = engine_identity(self.engine, self.root)
        inputs = self.input_state(files, intent, d["ledger"], engine)
        effective = self.effective(intent, d["ledger"])
        current = []
        historical = []
        for a in d["assessments"]:
            item = {
                "assessment_id": a["id"],
                "created_at": a["created_at"],
                "inputs": a["inputs"],
                "findings": [self.public_finding(f) for f in a["findings"]],
                "coverage": a["coverage"],
            }
            (current if a["inputs"] == inputs else historical).append(item)
        detected = detect(files)
        discovered, parse_errors = routes(files)
        declared = {(e["method"], e["path"]) for e in intent["endpoints"]}
        gaps = [
            {
                "reason": "endpoint_not_declared",
                "scope_ref": self.ref([r["method"], r["path"]]),
                "display": {"outcome": "unknown", "status": "intent_missing"},
            }
            for r in discovered
            if (r["method"], r["path"]) not in declared and ("ANY", r["path"]) not in declared
        ]
        gaps += [
            {
                "reason": "route_discovery_incomplete",
                "scope_ref": p,
                "display": {"outcome": "unknown", "status": "not_assessed"},
            }
            for p in sorted(set(parse_errors))
        ]
        report = {
            "schema_version": "0.4.2",
            "generated_at": now(),
            "assessment_inputs": inputs,
            "current": current[-1:],
            "historical": historical[-5:],
            "coverage_gaps": detected["uncovered_controls"],
            "discovery_gaps": gaps,
            "unknowns": [self.public_finding(f) for f in self.unknowns(effective)],
            "response_assumptions": [
                "No HTTP requests or tests are run in M1a; pack behavioral response assumptions have not been evaluated."
            ],
            "untrusted_text": {
                "source": "workspace",
                "text": "[Repository-authored prose, names, paths, and source lines are not included.]",
            },
            "limitations": LIMITATIONS,
        }
        if validate_report(report):
            raise Refused("report_contract_invalid")
        return report


def validate_report(report):
    errors = list(validator._schema("report").iter_errors(report))
    if errors:
        return ["report_schema_invalid"]
    if any(a["inputs"] != report["assessment_inputs"] for a in report["current"]):
        return ["current_inputs_mismatch"]
    if any(a["inputs"] == report["assessment_inputs"] for a in report["historical"]):
        return ["historical_inputs_match"]
    return []
