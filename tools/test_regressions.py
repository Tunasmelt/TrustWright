"""Every case must be REJECTED for its stated reason. Run: python tools/test_regressions.py

Two kinds of case:
  tamper  the ledger is left alone; content-bound digests must catch the edit.
  logic   the ledger is RESEALED over the mutated runs, simulating a server that
          genuinely observed that outcome. The validator's reasoning must catch it,
          because a digest check alone would hide whether the logic works.

Each case names a fragment its rejection must contain. A rejection for some other
reason is reported as WRONG-REASON and counts as a failure.
"""
import copy
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from digest import WorkspaceError, run_record_digest, tree_digest  # noqa: E402
from validate import load, load_examples, validate  # noqa: E402

BASE = load_examples()
CASES = []


def case(group, expect, reseal=False):
    def wrap(fn):
        CASES.append((group, fn, expect, reseal))
        return fn
    return wrap


def F(b, fid): return next(x for x in b["findings"] if x["id"] == fid)
def R(b, rid): return next(x for x in b["runs"] if x["run_id"] == rid)
def EP(b, eid): return next(x for x in b["intent"]["endpoints"] if x["id"] == eid)
def pack(b): return b["packs"][0][0]


def reseal_runs(b, l):
    """Re-sign every observed run as if the server had genuinely observed its current content."""
    runs = {r["run_id"]: r for r in b["runs"]}
    for o in l["observed_runs"]:
        if o["run_id"] in runs:
            o["record_digest"] = run_record_digest(runs[o["run_id"]])


# ------------------------------------------------------------------ v0.1 overclaims

@case("v0.1", "behavioral_test")
def static_rule_claims_pass(b, l): F(b, "F-001")["result"] = "satisfied"

@case("v0.1", "behavioral_test")
def structural_link_claims_pass(b, l):
    x = F(b, "F-002"); x["result"] = "satisfied"; x["display"] = {"outcome": "check_passed", "status": "structurally_linked"}

@case("v0.1", "'unknown' was expected")
def structural_absence_claims_violation(b, l):
    x = F(b, "F-002"); x["result"] = "violated"; x["evidence"][0]["validation"] = "not_linked"

@case("v0.1", "behavioral_test")
def agent_review_claims_pass(b, l): F(b, "F-005")["result"] = "satisfied"

@case("v0.1", "'agent_assessed' was expected")
def agent_review_relabelled_confirmed(b, l): F(b, "F-005")["display"] = {"outcome": "check_passed", "status": "confirmed"}

@case("v0.1", "'reported' was expected")
def agent_run_claims_reproduced(b, l): R(b, "RUN-002")["evidence_validation"] = "independently_reproduced"

@case("v0.1", "claims independently_reproduced but run is reported")
def finding_upgrades_reported_run(b, l):
    x = F(b, "F-003"); x["evidence"][0]["validation"] = "independently_reproduced"
    x["display"] = {"outcome": "check_passed", "status": "reproduced"}

@case("v0.1", "not every cited scenario passed")
def pass_despite_failed_scenario(b, l):
    s = R(b, "RUN-002")["scenarios"][0]; s["outcome"] = "failed"; s["observed_status"] = 500

@case("v0.1", "contain")
def missing_positive_control(b, l):
    for s in R(b, "RUN-002")["scenarios"]:
        s["control_role"] = "negative_control"

@case("v0.1", "'unknown' was expected")
def unknown_intent_becomes_violation(b, l):
    x = F(b, "F-006"); x["method"] = "structural_check"; x["result"] = "violated"

@case("v0.1", "without server-recorded confirmation")
def inferred_intent_tested_as_confirmed(b, l):
    for s in R(b, "RUN-002")["scenarios"]:
        s["intent_ref"] = {"endpoint_id": "export", "requirement_id": "export-authn"}

@case("v0.1", "not defined in pack")
def agent_invented_structural_check(b, l): F(b, "F-002")["evidence"][0]["check_id"] = "agent-made-rule"

@case("v0.1", "rejected by pack pattern")
def structural_param_injection(b, l):
    # Printable payload, so it passes the schema's control-character rule and reaches the pack regex.
    F(b, "F-002")["evidence"][0]["params"]["dependency"] = "get_current_user) or Depends(admin_bypass"


@case("loop6", "does not match")
def structural_param_control_chars(b, l):
    F(b, "F-002")["evidence"][0]["params"]["dependency"] = "get_current_user), ...\n  pattern: $X"

@case("v0.1", "needs a separate authentication requirement")
def ownership_without_authentication(b, l):
    ep = EP(b, "read-document"); ep["requirements"] = [q for q in ep["requirements"] if q["id"] != "read-document-authn"]

@case("v0.1", "'report_as_unknown' was expected")
def unknown_intent_silently_permitted(b, l): b["intent"]["unconfirmed_policy"] = "treat_as_public"

@case("v0.1", "must state limitations")
def missing_limitations_on_non_confirmed(b, l): F(b, "F-002")["limitations"] = []

@case("v0.1", "cannot establish")
def pack_check_overstates_capability(b, l): pack(b)["checks"][1]["establishes"] = "specific_violation"


# ------------------------------------------------------------------ review of v0.1

@case("review1", "should be non-empty")
def confirmed_issue_with_no_evidence(b, l): F(b, "F-008")["evidence"] = []

@case("review1", "should be non-empty")
def static_finding_with_no_evidence(b, l): F(b, "F-001")["evidence"] = []

@case("review1", "finding claims PASSWORD-STORAGE")
def control_swapped_jwt_evidence_kept(b, l): F(b, "F-001")["control_id"] = "PASSWORD-STORAGE"

@case("review1", "needs a specific_violation check")
def suspicious_pattern_promoted_to_confirmed(b, l):
    x = F(b, "F-001"); x["result"] = "violated"; x["display"] = {"outcome": "issue_found", "status": "confirmed"}

@case("review1", "template verifies AUTHN-ENDPOINT")
def authn_tests_prove_ownership(b, l):
    x = F(b, "F-004"); x["control_id"] = "AUTHZ-OWNERSHIP"
    x["intent_ref"] = {"endpoint_id": "read-document", "requirement_id": "read-document-owner"}

@case("review1", "cannot verify AUTHZ-OWNERSHIP", reseal=True)
def scenarios_retargeted_at_ownership(b, l):
    for s in R(b, "RUN-003")["scenarios"]:
        s["intent_ref"] = {"endpoint_id": "read-document", "requirement_id": "read-document-owner"}

@case("review1", "control_role")
def positive_negative_roles_swapped(b, l):
    for s in R(b, "RUN-002")["scenarios"]:
        s["control_role"] = {"positive_control": "negative_control", "negative_control": "positive_control"}[s["control_role"]]

@case("review1", "template version 99.0.0")
def template_version_99(b, l): R(b, "RUN-002")["test_artifact"]["template"]["template_version"] = "99.0.0"

@case("review1", "principal")
def principal_changed(b, l): R(b, "RUN-002")["scenarios"][3]["principal"] = "valid_user"

@case("review1", "must cite all scenarios")
def cherry_pick_only_passing_positive(b, l):
    s = R(b, "RUN-002")["scenarios"][3]; s["outcome"] = "failed"; s["observed_status"] = 200
    F(b, "F-003")["evidence"][0]["scenario_ids"] = ["valid-token"]

@case("review1", "passed, but observed 200")
def observed_200_expected_401_marked_passed(b, l): R(b, "RUN-002")["scenarios"][1]["observed_status"] = 200

@case("review1", "granted (2xx)")
def violated_while_all_cited_passed(b, l):
    x = F(b, "F-003"); x["result"] = "violated"; x["display"] = {"outcome": "issue_found", "status": "reported"}

@case("review1", "every consistency check")
def failed_consistency_check_with_pass(b, l): R(b, "RUN-002")["consistency_checks"][3]["passed"] = False

@case("review1", "every consistency check")
def consistency_check_omitted(b, l): R(b, "RUN-002")["consistency_checks"].pop()

@case("review1", "every positive control", reseal=True)
def violation_when_positive_control_fails(b, l):
    s = R(b, "RUN-001")["scenarios"][0]; s["outcome"] = "failed"; s["observed_status"] = 500

@case("review1", "errored or skipped", reseal=True)
def violation_resting_on_runner_error(b, l):
    for s in R(b, "RUN-001")["scenarios"][2:]:
        s["outcome"] = "error"; s["observed_status"] = None

@case("review1", "duplicate finding id")
def duplicate_finding_ids(b, l): b["findings"].append(copy.deepcopy(F(b, "F-001")))

@case("review1", "duplicate run id")
def duplicate_run_ids(b, l): b["runs"].append(copy.deepcopy(R(b, "RUN-002")))

@case("review1", "duplicate requirement id")
def duplicate_requirement_ids(b, l): EP(b, "health")["requirements"][0]["id"] = "read-document-authn"

@case("review1", "is not valid for AUTHN-ENDPOINT")
def authn_control_given_owner_policy(b, l): EP(b, "read-document")["requirements"][1]["control_id"] = "AUTHN-ENDPOINT"

@case("review1", "is not declared")
def policy_references_missing_resource(b, l): EP(b, "read-document")["requirements"][1]["policy"]["resource"] = "invoices"

@case("review1", "escapes the pack directory")
def pack_path_escapes_via_dotdot(b, l): pack(b)["recipes"][0]["file"] = "../../../../../../etc/hostname"

@case("review1", "is a required property")
def advisory_confirmed_without_version_or_id(b, l):
    e = F(b, "F-008")["evidence"][0]; del e["version"]; del e["advisory_id"]

@case("review1", "matched advisory on a trusted version source")
def advisory_confirmed_unchecked(b, l): F(b, "F-008")["evidence"][0]["validation"] = "unchecked"

@case("review1", "matched advisory on a trusted version source")
def advisory_confirmed_from_unpinned_manifest(b, l): F(b, "F-008")["evidence"][0]["version_source"] = "unpinned_manifest"

@case("review1", "is not a 'date-time'")
def invalid_date_time(b, l): R(b, "RUN-002")["created_at"] = "not-a-date"


# ------------------------------------------------------------------ trust boundary (v0.2)

@case("trust", "no record of it")
def run_self_promoted_to_reproduced(b, l):
    r = R(b, "RUN-002"); r["runner"]["kind"] = "controlled_runner"; r["runner"]["observed_by_server"] = True
    r["evidence_validation"] = "independently_reproduced"
    x = F(b, "F-003"); x["evidence"][0]["validation"] = "independently_reproduced"
    x["display"] = {"outcome": "check_passed", "status": "reproduced"}

@case("trust", "run record differs")
def observed_run_results_swapped(b, l): R(b, "RUN-003")["results_artifact"]["sha256"] = "0" * 64

@case("trust", "run record differs")
def observed_run_workspace_changed(b, l): R(b, "RUN-003")["workspace_snapshot"]["tree_digest"]["value"] = "f" * 64

@case("trust", "no record of it")
def ledger_entry_removed(b, l): l["observed_runs"] = [o for o in l["observed_runs"] if o["run_id"] != "RUN-003"]

@case("trust", "no confirmation matching")
def requirement_self_confirmed(b, l):
    req = EP(b, "export")["requirements"][0]; req["policy"] = {"kind": "public"}; req["provenance"]["source"] = "confirmed"

@case("trust", "no confirmation matching")
def policy_edited_after_confirmation(b, l): EP(b, "read-document")["requirements"][0]["policy"] = {"kind": "public"}

@case("trust", "not in the trust ledger")
def human_review_without_ledger_attestation(b, l): l["human_attestations"] = []

@case("trust", "not in the trust ledger")
def attestation_reused_for_other_finding(b, l): l["human_attestations"][0]["finding_id"] = "F-005"


# ------------------------------------------------------------------ review of v0.2

@case("review2", "run record differs")
def observed_results_rewritten_ledger_untouched(b, l):
    for s in R(b, "RUN-001")["scenarios"]:
        s["outcome"] = "passed"; s["observed_status"] = s["expect_status"]
    x = F(b, "F-007"); x["result"] = "satisfied"; x.pop("severity")
    x["display"] = {"outcome": "check_passed", "status": "reproduced"}

@case("review2", "differs from what harris attested")
def attested_conclusion_flipped(b, l):
    x = F(b, "F-009"); x["result"] = "violated"; x["display"] = {"outcome": "issue_found", "status": "human_reviewed"}

@case("review2", "differs from what harris attested")
def attested_limitations_removed(b, l): F(b, "F-009")["limitations"] = ["Reviewed"]

@case("review2", "differs from what harris attested")
def attested_snapshot_swapped(b, l): F(b, "F-009")["evidence"][0]["reviewed_tree_digest"] = "a" * 64

@case("review2", "no confirmation matching")
def confirmed_endpoint_moved(b, l): EP(b, "read-document")["path"] = "/admin/secrets"

@case("review2", "no confirmation matching")
def confirmed_endpoint_method_changed(b, l): EP(b, "read-document")["method"] = "DELETE"

@case("review2", "no confirmation matching")
def owner_field_redefined_after_confirmation(b, l): b["intent"]["resources"][0]["owner_field"] = "created_by"

@case("review2", "structural evidence targets")
def structural_path_unrelated(b, l): F(b, "F-002")["evidence"][0]["params"]["path"] = "/unrelated"

@case("review2", "structural evidence targets")
def structural_method_mismatch(b, l): F(b, "F-002")["evidence"][0]["params"]["method"] = "post"

@case("review2", "assertion mismatch, not a bypass", reseal=True)
def negative_403_counted_as_violation(b, l):
    for s in R(b, "RUN-001")["scenarios"][2:]:
        s["observed_status"] = 403

@case("review2", "granted (2xx)", reseal=True)
def negative_500_counted_as_violation(b, l):
    for s in R(b, "RUN-001")["scenarios"][2:]:
        s["observed_status"] = 500

@case("review2", "is not of type 'integer'", reseal=True)
def reproduced_pass_without_observations(b, l):
    for s in R(b, "RUN-003")["scenarios"]:
        s["observed_status"] = None


# ------------------------------------------------------------------ pass 4 (self-review of v0.3.1)

EVIL_PATH = '/documents/1"\nimport pathlib; pathlib.Path("/tmp/PWNED_REGRESSION").write_text("x")\nX = "'

@case("pass4", "does not match")
def intent_path_with_code_rejected(b, l): EP(b, "read-document")["path"] = EVIL_PATH

@case("pass4", "does not match")
def citation_absolute_path(b, l): F(b, "F-005")["evidence"][0]["location"]["path"] = "/etc/shadow"

@case("pass4", "does not match")
def citation_traversal_path(b, l): F(b, "F-005")["evidence"][0]["location"]["path"] = "../../../.ssh/id_rsa"

@case("pass4", "does not match")
def scope_location_traversal(b, l): F(b, "F-001")["scope"]["locations"][0]["path"] = "app/../../secrets.env"

@case("pass4", "does not match")
def citation_windows_drive_path(b, l): F(b, "F-005")["evidence"][0]["location"]["path"] = "C:/Users/x/.aws/credentials"

@case("pass4", "ends (line")
def inverted_line_range(b, l): F(b, "F-001")["scope"]["locations"][0].update(start_line=40, end_line=3)

def _add_endpoint(b, l, eid, method, path, confirm=True):
    from digest import requirement_digest
    ep = copy.deepcopy(EP(b, "health")); ep["id"] = eid; ep["method"], ep["path"] = method, path
    ep["requirements"][0]["id"] = eid + "-req"
    b["intent"]["endpoints"].append(ep)
    if confirm:
        l["intent_confirmations"].append({**l["intent_confirmations"][0], "endpoint_id": eid,
            "request_id": "confirm-" + requirement_digest(b["intent"], eid, eid + "-req")[:32],
            "requirement_id": eid + "-req", "requirement_digest": requirement_digest(b["intent"], eid, eid + "-req")})

@case("pass4", "overlaps endpoint")
def same_route_confirmed_public_and_authenticated(b, l): _add_endpoint(b, l, "doc-public", "GET", "/documents/{doc_id}")

@case("pass4", "overlaps endpoint")
def same_route_param_renamed_trailing_slash(b, l): _add_endpoint(b, l, "doc-alias", "GET", "/documents/{id}/")

@case("pass4", "overlaps endpoint")
def any_method_overlaps_specific_method(b, l): _add_endpoint(b, l, "doc-any", "ANY", "/documents/{doc_id}")

@case("pass4", "duplicate ledger confirmation")
def duplicate_ledger_confirmation(b, l): l["intent_confirmations"].append(copy.deepcopy(l["intent_confirmations"][1]))

@case("pass4", "does not resolve")
def attestation_with_dangling_requirement(b, l): F(b, "F-009")["intent_ref"]["requirement_id"] = "nope"

@case("pass4", "does not resolve")
def attestation_with_dangling_endpoint(b, l): F(b, "F-009")["intent_ref"]["endpoint_id"] = "nope"

@case("pass4", "file uses placeholders")
def template_placeholder_undeclared(b, l): del pack(b)["test_templates"][0]["placeholders"]["test_key"]


def template_injection_runs_nothing():
    """Replay the P4-01 exploit through the renderer (schema bypassed) and execute the result."""
    import subprocess, ast
    import demo_slice as d
    from render import render
    marker = Path("/tmp/PWNED_REGRESSION"); marker.unlink(missing_ok=True)
    tmpl = d.TEMPLATE
    src = render((d.PACK_DIR / tmpl["file"]).read_text(), tmpl["placeholders"],
                 {"app_module": "app", "app_object": "app", "concrete_path": EVIL_PATH, "test_key": "k",
                  "test_audience": "a", "method": "get", "expect_ok_status": 200})
    value = next(n.value.value for n in ast.parse(src).body
                 if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "PATH")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td); (root / "auth.py").write_text((d.PACK_DIR / "recipes/verify_token.py").read_text())
        (root / "app.py").write_text(d.APP); (root / "test_x.py").write_text(src)
        subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_x.py"], cwd=root,
                       env={**os.environ, **d.ENV, "PYTHONPATH": str(root)}, capture_output=True)
    ran = marker.exists(); marker.unlink(missing_ok=True)
    return [] if ran or value != EVIL_PATH else ["injected path stayed inert data and nothing executed"]


def template_injection_other_placeholders_refused():
    import demo_slice as d
    from render import render, RenderError
    tmpl, good = d.TEMPLATE, {"app_module": "app", "app_object": "app", "concrete_path": "/x", "test_key": "k",
                              "test_audience": "a", "method": "get", "expect_ok_status": 200}
    attacks = [("method", "get(PATH); __import__('os').system('id'); client.get"),
               ("app_module", "os; __import__('os').system('id') #"), ("app_object", "app as a; import os #"),
               ("expect_ok_status", "200 or __import__('os').system('id')"), ("expect_ok_status", True)]
    for name, bad in attacks:
        try:
            render((d.PACK_DIR / tmpl["file"]).read_text(), tmpl["placeholders"], {**good, name: bad})
            return []
        except RenderError:
            pass
    return [f"all {len(attacks)} placeholder injections refused"]


def location_check_without_schema():
    """Defense in depth: the validator's own location check, with the schema layer bypassed."""
    import validate as V
    b, l = copy.deepcopy(BASE)
    F(b, "F-005")["evidence"][0]["location"]["path"] = "../../../.ssh/id_rsa"
    return V.check_findings(b["findings"], V.Context(b, l))


def validator_never_crashes_fuzz():
    """Deterministic fuzz of the UNGUARDED validator: dangling refs, deletions, wrong types, duplicates."""
    import random, validate as V
    ids = ["F-001", "F-009", "RUN-001", "read-document", "read-document-owner", "export", "nope", ""]
    def walk(o, p=()):
        yield p
        if isinstance(o, dict):
            for k, v in o.items(): yield from walk(v, p + (k,))
        elif isinstance(o, list):
            for i, v in enumerate(o): yield from walk(v, p + (i,))
    rng, crashes = random.Random(4242), []
    for _ in range(400):
        b, l = copy.deepcopy(BASE)
        for _ in range(rng.randint(1, 3)):
            doc = rng.choice([b["intent"], l] + b["findings"] + b["runs"])
            path = rng.choice([p for p in walk(doc) if p]); parent = doc
            for k in path[:-1]: parent = parent[k]
            key, op = path[-1], rng.choice(["retarget", "retarget", "delete", "type"])
            if op == "retarget" and isinstance(parent[key], str): parent[key] = rng.choice(ids)
            elif op == "delete": parent.pop(key)
            elif op == "type": parent[key] = rng.choice([None, 0, "x", [], {}])
        try:
            V._validate(b, l)
        except Exception as e:  # noqa: BLE001
            crashes.append(type(e).__name__)
    return [] if crashes else ["400 mutated bundles, no crashes"]


def fail_closed_on_internal_error():
    import validate as V
    original = V.check_intent
    V.check_intent = lambda ctx: 1 / 0
    try:
        return V.validate(*copy.deepcopy(BASE))
    finally:
        V.check_intent = original


# ------------------------------------------------------------------ loop 5

ALIAS_BOMB = "a: &a [x,x,x,x,x,x,x,x,x,x]\n" + "".join(
    f"{chr(98+i)}: &{chr(98+i)} [" + ",".join([f"*{chr(97+i)}"] * 10) + "]\n" for i in range(7))


def yaml_alias_bomb_refused():
    import time, validate as V
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "security-intent.yaml"; p.write_text(ALIAS_BOMB)
        t0 = time.time()
        try:
            V.load(p)
            return []
        except V.LoadError as e:
            return [str(e)] if time.time() - t0 < 1 else []


def oversized_document_refused():
    import validate as V
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "findings.json"; p.write_text("[" + ",".join(["0"] * 600_000) + "]")
        try:
            V.load(p)
            return []
        except V.LoadError as e:
            return [str(e)]


def deeply_nested_json_refused():
    import validate as V
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "findings.json"; p.write_text("[" * 100_000 + "]" * 100_000)
        try:
            V.load(p)
            return []
        except V.LoadError as e:
            return [str(e)]


def test_subprocess_gets_no_server_secrets():
    """Genuine execution: project code tries to read a secret planted in the server's environment."""
    import demo_slice as d
    previous = os.environ.get("SERVER_SECRET_TOKEN")
    os.environ["SERVER_SECRET_TOKEN"] = "sk-live-should-never-reach-project-code"
    orig = d.build_workspace
    try:
        with tempfile.TemporaryDirectory(prefix="trustwright-leak-") as marker_dir:
            marker = Path(marker_dir) / "LEAK_REGRESSION"
            def leaky(root, variant):
                tf = orig(root, variant)
                (root / "app.py").write_text((root / "app.py").read_text() + "\nimport os, pathlib\npathlib.Path("
                    + repr(str(marker)) + ").write_text(os.environ.get('SERVER_SECRET_TOKEN', 'absent'))\n")
                return tf
            d.build_workspace = leaky
            d.execute("RUN-950", "fixed", server_observed=True)
            seen = marker.read_text() if marker.exists() else "not run"
    finally:
        d.build_workspace = orig
        if previous is None:
            os.environ.pop("SERVER_SECRET_TOKEN", None)
        else:
            os.environ["SERVER_SECRET_TOKEN"] = previous
    return ["secret absent from the test environment"] if seen == "absent" else []


def rule_params_substituted_in_one_pass():
    import validate as V
    out = V.substitute_params('@$APP.__METHOD__("__PATH__") Depends(__DEPENDENCY__)',
                              {"method": "get", "path": "/__DEPENDENCY__", "dependency": "get_current_user"})
    return ["path inserted literally"] if '"/__DEPENDENCY__"' in out and "Depends(get_current_user)" in out else []


def non_regular_file_refused():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td); os.mkfifo(root / "auth.py")
        try:
            tree_digest(root)
            return []
        except WorkspaceError as e:
            return [str(e)]


def rule_tests_leave_no_temp_files():
    import validate as V
    before = set(Path(tempfile.gettempdir()).iterdir())
    bundle, ledger = copy.deepcopy(BASE)
    errs = V.validate(bundle, ledger, run_rules=True)
    leftover = [p for p in set(Path(tempfile.gettempdir()).iterdir()) - before if p.suffix == ".yaml"]
    return ["no rule configs left behind"] if not errs and not leftover else []


# ------------------------------------------------------------------ loop 6

SPOOF = "Looks fine.\x1b[2K\r\x1b[32mCheck passed \u00b7 Reproduced\x1b[0m"

@case("loop6", "does not match")
def claim_with_terminal_escape(b, l): F(b, "F-005")["evidence"][0]["claim"] = SPOOF

@case("loop6", "does not match")
def limitation_with_terminal_escape(b, l): F(b, "F-002")["limitations"][0] = SPOOF

@case("loop6", "does not match")
def scope_ref_with_carriage_return(b, l): F(b, "F-001")["scope"]["ref"] = "app/auth.py\rcheck passed"

@case("loop6", "is too long")
def oversized_claim(b, l): F(b, "F-005")["evidence"][0]["claim"] = "A" * 200_000

@case("loop6", "does not match")
def intent_rationale_with_escape(b, l): EP(b, "export")["requirements"][0]["provenance"]["rationale"] = SPOOF


def hanging_project_is_killed():
    """Genuine execution of project code that never returns: the runner must kill it and fail closed."""
    import time, demo_slice as d
    orig, timeout = d.build_workspace, d.TEST_TIMEOUT_SECONDS
    def hang(root, variant):
        tf = orig(root, variant)
        (root / "app.py").write_text((root / "app.py").read_text() + "\nwhile True:\n    pass\n")
        return tf
    d.build_workspace, d.TEST_TIMEOUT_SECONDS = hang, 3
    t0 = time.time()
    try:
        d.execute("RUN-960", "fixed", server_observed=True)
        return []
    except d.RunnerError as e:
        return [str(e)] if time.time() - t0 < 15 else []
    finally:
        d.build_workspace, d.TEST_TIMEOUT_SECONDS = orig, timeout


def results_with_dtd_refused():
    import demo_slice as d
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "r.xml"
        p.write_text('<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "x">]><testsuites><testcase name="&a;"/></testsuites>')
        try:
            d.parse_junit(p)
            return []
        except d.RunnerError as e:
            return [str(e)]


def oversized_results_refused():
    import demo_slice as d
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "r.xml"
        p.write_text("<testsuites>" + '<testcase name="x"/>' * 600_000 + "</testsuites>")
        try:
            d.parse_junit(p)
            return []
        except d.RunnerError as e:
            return [str(e)]


# ------------------------------------------------------------------ loop 7

def _load_text(name, text):
    import validate as V
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / name; p.write_text(text)
        try:
            V.load(p)
            return []
        except V.LoadError as e:
            return [str(e)]


def yaml_duplicate_key_refused():
    return _load_text("security-intent.yaml", "policy: {kind: authenticated}\nnote: reviewed\npolicy: {kind: public}\n")


def json_duplicate_key_refused():
    return _load_text("findings.json", '{"result": "violated", "result": "satisfied"}')


def yaml_python_tag_refused():
    return _load_text("security-intent.yaml", "x: !!python/object/apply:os.system ['id']\n")


def _run_with_project_files(extra):
    import demo_slice as d
    orig = d.build_workspace
    def build(root, variant):
        tf = orig(root, variant); extra(root); return tf
    d.build_workspace = build
    try:
        return d.execute("RUN-970", "fixed", server_observed=True)[0]
    finally:
        d.build_workspace = orig


FAKE_LOGIN_CONFTEST = ("import pytest\nfrom app import app\nfrom auth import get_current_user\n"
                       "@pytest.fixture(autouse=True)\ndef _fake_login():\n"
                       "    app.dependency_overrides[get_current_user] = lambda: {'id': 'test-user'}\n"
                       "    yield\n    app.dependency_overrides.clear()\n")


def project_conftest_cannot_fake_login():
    """Genuine run: a common FastAPI conftest overriding auth must not reach the generated tests."""
    run = _run_with_project_files(lambda r: (r / "conftest.py").write_text(FAKE_LOGIN_CONFTEST))
    neg = [s for s in run["scenarios"] if s["control_role"] == "negative_control"]
    return ["generated tests isolated from project conftest"] if all(
        s["outcome"] == "passed" and s["observed_status"] == 401 for s in neg) else []


def project_addopts_cannot_deselect_tests():
    run = _run_with_project_files(lambda r: (r / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "-k valid_token"\n'))
    return ["all scenarios ran despite project addopts"] if all(
        s["outcome"] == "passed" for s in run["scenarios"]) else []


def third_party_pytest_plugins_disabled():
    import demo_slice as d
    env = d.test_environment(Path("/tmp"))
    return ["plugin autoload disabled"] if env.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") == "1" else []


def recorded_command_matches_executed():
    run = _run_with_project_files(lambda r: None)
    cmd = run["runner"]["command"]
    return ["recorded command is exact"] if cmd.startswith("pytest -q -p no:cacheprovider --noconftest -c ") else []


# ------------------------------------------------------------------ loop 8

def loader_error_contract():
    """Every malformed document raises LoadError, never another exception type."""
    import validate as V
    probes = [("security-intent.yaml", b"? {a: 1}\n: x\n"), ("security-intent.yaml", b"x: " + b"9" * 5000 + b"\n"),
              ("findings.json", b'[{"x": ' + b"9" * 5000 + b"}]"), ("security-intent.yaml", b"name: \xff\xfe x\n"),
              ("findings.json", b'[{"start_line": NaN}]'), ("findings.json", b'[{"end_line": Infinity}]'),
              ("security-intent.yaml", b"a: [unclosed\n"), ("findings.json", b"{not json")]
    with tempfile.TemporaryDirectory() as td:
        for name, data in probes:
            p = Path(td) / name; p.write_bytes(data)
            try:
                V.load(p)
                return []
            except V.LoadError:
                continue
            except Exception:  # noqa: BLE001
                return []
    return [f"all {len(probes)} malformed documents raised LoadError"]


def loader_byte_fuzz():
    """Corrupt the real example files byte by byte: load must succeed or raise LoadError, nothing else."""
    import random, validate as V
    root = Path(__file__).resolve().parent.parent
    sources = [root / "examples" / "security-intent.yaml", root / "examples" / "findings.json",
               root / "examples" / "trust-ledger.json", root / "packs" / "fastapi-pyjwt-pwdlib" / "pack.yaml"]
    rng = random.Random(8080)
    with tempfile.TemporaryDirectory() as td:
        for _ in range(500):
            src = rng.choice(sources); data = bytearray(src.read_bytes())
            for _ in range(rng.randint(1, 4)):
                i = rng.randrange(len(data))
                op = rng.choice(["flip", "insert", "delete"])
                if op == "flip": data[i] = rng.randrange(256)
                elif op == "insert": data.insert(i, rng.choice(b'{}[]:,&*!"\'\n\x00\xff-#?|>'))
                else: del data[i]
            p = Path(td) / src.name; p.write_bytes(bytes(data))
            try:
                V.load(p)
            except V.LoadError:
                pass
            except Exception:  # noqa: BLE001
                return []
    return ["500 corrupted documents: every outcome was a document or LoadError"]


# ------------------------------------------------------------------ loop 9

def lone_surrogate_refused_at_load():
    raw = (Path(__file__).resolve().parent.parent / "examples" / "findings.json").read_text()
    return _load_text("findings.json", raw.replace('"Cited line', '"\\ud800Cited line', 1))


def lone_surrogate_refused_in_validate():
    """Documents handed over as objects (not via load) are gated too."""
    import validate as V
    b, l = copy.deepcopy(BASE)
    F(b, "F-005")["evidence"][0]["claim"] = "\ud800 smuggled"
    return V.validate(b, l)


def generated_test_imports_nothing_from_the_project_namespace():
    """The rendered test may import only the standard library, the test client, and the app under test.
    (Hardening for P9-02: a fixture must not share its import namespace with the code under test.)"""
    import ast, demo_slice as d
    from render import render
    src = render((d.PACK_DIR / d.TEMPLATE["file"]).read_text(), d.TEMPLATE["placeholders"],
                 {"app_module": "app", "app_object": "app", "concrete_path": "/x", "test_key": "k",
                  "test_audience": "a", "method": "get", "expect_ok_status": 200})
    allowed = {"base64", "hashlib", "hmac", "json", "time", "fastapi.testclient", "app"}
    imported = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    extra = imported - allowed
    return [f"imports limited to {sorted(imported)}"] if not extra else []


# ------------------------------------------------------------------ workspace digest

def symlink_retarget_changes_digest():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td); (root / "a.py").write_text("safe"); (root / "b.py").write_text("evil")
        os.symlink("a.py", root / "auth.py"); d1 = tree_digest(root)[0]
        (root / "auth.py").unlink(); os.symlink("b.py", root / "auth.py")
        return ["digest changed"] if tree_digest(root)[0] != d1 else []


def workspace_symlink_escape_refused():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td); os.symlink("/etc/hostname", root / "auth.py")
        try:
            tree_digest(root)
            return []
        except WorkspaceError as e:
            return [str(e)]


def pack_file_symlink_escape():
    bundle, ledger = copy.deepcopy(BASE)
    with tempfile.TemporaryDirectory() as td:
        clone = Path(td) / "pack"
        os.system(f"cp -r '{bundle['packs'][0][1]}' '{clone}'")
        (clone / "recipes" / "verify_token.py").unlink()
        os.symlink("/etc/hostname", clone / "recipes" / "verify_token.py")
        bundle["packs"] = [(load(clone / "pack.yaml"), clone)]
        return validate(bundle, ledger)


def _symlink_case(build):
    def run():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); build(root)
            try:
                tree_digest(root)
                return []
            except WorkspaceError as e:
                return [str(e)]
    return run


def _results(root):
    (root / ".trustwright" / "results").mkdir(parents=True)
    (root / ".trustwright" / "results" / "auth_impl.py").write_text("require_auth = True")


def legitimate_symlinks_still_digest():
    """Control: the symlink policy must not simply refuse every link."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "real.py").write_text("x"); os.symlink("real.py", root / "auth.py")
        (root / "src" / "__pycache__").mkdir(parents=True); (root / "src" / "m.py").write_text("x")
        os.symlink("src", root / "lib")
        try:
            tree_digest(root)
            return True
        except WorkspaceError:
            return False


def redirect_to_public_login_not_a_violation():
    """Genuine, server-observed run of a CORRECTLY protected endpoint that redirects
    unauthenticated users to a public /login page. Claiming a violation must fail."""
    import demo_slice
    run, entry = demo_slice.execute("RUN-901", "redirect", server_observed=True)
    negatives = [s["observed_status"] for s in run["scenarios"] if s["control_role"] == "negative_control"]
    if any(st == 200 for st in negatives):
        return []  # the template followed the redirect and recorded the login page: the original bug
    bundle, ledger = copy.deepcopy(BASE)
    bundle["runs"].append(run); ledger["observed_runs"].append(entry)
    claim = copy.deepcopy(F(bundle, "F-007")); claim["id"] = "F-901"; claim["evidence"][0]["run_id"] = "RUN-901"
    bundle["findings"].append(claim)
    return validate(bundle, ledger)


# ------------------------------------------------------------------ scanner harness

def _fake_engine(tmpdir: Path, exit_code: int, mode: str) -> str:
    script = tmpdir / f"fake-{mode}"
    manifest = BASE[0]["packs"][0][1] / "pack.yaml"
    script.write_text(f"""#!{sys.executable}
import json, sys, yaml
args = sys.argv[1:]
rule = yaml.safe_load(open(args[args.index("--config") + 1]))["rules"][0]["id"]
target = args[-1]
check = next(c for c in yaml.safe_load(open({str(manifest)!r}))["checks"] if c["rule_id"] == rule)
lines = check["samples"]["expected_lines"] if target.endswith(check["samples"]["should_match"]) else []
if {mode!r} == "off_by_one":
    lines = [n + 1 for n in lines]
out = {{"results": [{{"check_id": "tmp." + rule, "start": {{"line": n}}}} for n in lines], "errors": []}}
if {mode!r} == "no_errors_key":
    del out["errors"]
if {mode!r} == "engine_errors":
    out["errors"] = [{{"message": "parse failure"}}]
print(json.dumps(out))
sys.exit({exit_code})
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def harness(exit_code, mode):
    bundle, ledger = copy.deepcopy(BASE)
    with tempfile.TemporaryDirectory() as td:
        return validate(bundle, ledger, run_rules=True, engine=_fake_engine(Path(td), exit_code, mode))


EXTRA = [
    ("digest", "symlink_retarget_changes_digest", symlink_retarget_changes_digest, "digest changed"),
    ("digest", "workspace_symlink_escape_refused", workspace_symlink_escape_refused, "points outside the workspace"),
    ("review1", "pack_file_symlink_escape", pack_file_symlink_escape, "escapes the pack directory"),
    ("review3", "redirect_to_public_login_not_a_violation", redirect_to_public_login_not_a_violation, "redirected (3xx)"),
    ("review3", "symlink_to_excluded_results_file", _symlink_case(lambda r: (_results(r),
        os.symlink(".trustwright/results/auth_impl.py", r / "auth.py"))), "targets excluded content"),
    ("review3", "symlink_to_git_internals", _symlink_case(lambda r: ((r / ".git").mkdir(),
        (r / ".git" / "a.py").write_text("x"), os.symlink(".git/a.py", r / "auth.py"))), "targets excluded content"),
    ("review3", "dir_symlink_to_ancestor_of_excluded", _symlink_case(lambda r: (_results(r),
        os.symlink(".trustwright", r / "cfg"))), "contains excluded content"),
    ("review3", "symlink_chain_into_excluded", _symlink_case(lambda r: (_results(r),
        os.symlink(".trustwright/results/auth_impl.py", r / "hop.py"), os.symlink("hop.py", r / "auth.py"))),
        "targets excluded content"),
    ("review3", "dir_symlink_to_workspace_root", _symlink_case(lambda r: os.symlink(".", r / "loop")),
        "contains excluded content"),
    ("review3", "symlink_cycle", _symlink_case(lambda r: (os.symlink("b", r / "a"), os.symlink("a", r / "b"))),
        "loops"),
    ("pass4", "template_injection_runs_nothing", template_injection_runs_nothing, "stayed inert"),
    ("pass4", "template_injection_other_placeholders_refused", template_injection_other_placeholders_refused, "injections refused"),
    ("pass4", "location_check_without_schema", location_check_without_schema, "outside the workspace"),
    ("pass4", "validator_never_crashes_fuzz", validator_never_crashes_fuzz, "no crashes"),
    ("pass4", "fail_closed_on_internal_error", fail_closed_on_internal_error, "failing closed"),
    ("loop5", "yaml_alias_bomb_refused", yaml_alias_bomb_refused, "anchors are not allowed"),
    ("loop5", "oversized_document_refused", oversized_document_refused, "the limit is"),
    ("loop5", "deeply_nested_json_refused", deeply_nested_json_refused, "nested too deeply"),
    ("loop5", "test_subprocess_gets_no_server_secrets", test_subprocess_gets_no_server_secrets, "secret absent"),
    ("loop5", "rule_params_substituted_in_one_pass", rule_params_substituted_in_one_pass, "inserted literally"),
    ("loop5", "non_regular_file_refused", non_regular_file_refused, "not a regular file"),
    ("loop5", "rule_tests_leave_no_temp_files", rule_tests_leave_no_temp_files, "no rule configs left"),
    ("loop6", "hanging_project_is_killed", hanging_project_is_killed, "were killed"),
    ("loop6", "results_with_dtd_refused", results_with_dtd_refused, "declares a DTD"),
    ("loop6", "oversized_results_refused", oversized_results_refused, "the limit is"),
    ("loop7", "yaml_duplicate_key_refused", yaml_duplicate_key_refused, "duplicate key 'policy'"),
    ("loop7", "json_duplicate_key_refused", json_duplicate_key_refused, "duplicate key 'result'"),
    ("loop7", "yaml_python_tag_refused", yaml_python_tag_refused, "could not determine a constructor"),
    ("loop7", "project_conftest_cannot_fake_login", project_conftest_cannot_fake_login, "isolated from project conftest"),
    ("loop7", "project_addopts_cannot_deselect_tests", project_addopts_cannot_deselect_tests, "all scenarios ran"),
    ("loop7", "third_party_pytest_plugins_disabled", third_party_pytest_plugins_disabled, "autoload disabled"),
    ("loop7", "recorded_command_matches_executed", recorded_command_matches_executed, "recorded command is exact"),
    ("loop8", "loader_error_contract", loader_error_contract, "raised LoadError"),
    ("loop8", "loader_byte_fuzz", loader_byte_fuzz, "document or LoadError"),
    ("loop9", "lone_surrogate_refused_at_load", lone_surrogate_refused_at_load, "not valid Unicode"),
    ("loop9", "lone_surrogate_refused_in_validate", lone_surrogate_refused_in_validate, "not valid Unicode"),
    ("loop9", "generated_test_imports_nothing_from_the_project_namespace", generated_test_imports_nothing_from_the_project_namespace, "imports limited to"),
    ("harness", "failure_exit_with_perfect_json", lambda: harness(2, "perfect"), "engine exited 2"),
    ("harness", "success_exit_wrong_lines", lambda: harness(0, "off_by_one"), "matched lines"),
    ("harness", "success_exit_missing_errors_list", lambda: harness(0, "no_errors_key"), "missing results/errors"),
    ("harness", "success_exit_engine_reported_errors", lambda: harness(0, "engine_errors"), "engine reported errors"),
]


if __name__ == "__main__":
    b, l = copy.deepcopy(BASE)
    if validate(b, l):
        print("Baseline examples invalid:", *validate(b, l), sep="\n  "); sys.exit(2)
    if harness(0, "perfect"):
        print("Harness control failed: a well-behaved fake engine was rejected"); sys.exit(2)
    b, l = copy.deepcopy(BASE); reseal_runs(b, l)
    if validate(b, l):
        print("Reseal control failed: resealing unmodified runs broke validation"); sys.exit(2)
    if not legitimate_symlinks_still_digest():
        print("Symlink control failed: legitimate in-workspace links were refused"); sys.exit(2)

    results = []
    for group, fn, expect, reseal in CASES:
        b, l = copy.deepcopy(BASE)
        fn(b, l)
        if reseal:
            reseal_runs(b, l)
        results.append((group + ("*" if reseal else ""), fn.__name__, expect, validate(b, l)))
    for group, name, fn, expect in EXTRA:
        results.append((group, name, expect, fn()))

    bad = 0
    for group, name, expect, errs in results:
        right = any(expect in e for e in errs)
        status = "REJECTED" if right else ("WRONG-REASON" if errs else "MISSED")
        bad += not right
        shown = next((e for e in errs if expect in e), errs[0] if errs else "")
        print(f"{status:<12} [{group:<8}] {name:<44} {shown[:78]}")
    tally = {}
    for group, _, expect, errs in results:
        g = group.rstrip("*"); tally.setdefault(g, [0, 0])
        tally[g][0] += any(expect in e for e in errs); tally[g][1] += 1
    print("\n" + "  ".join(f"{g}: {r}/{t}" for g, (r, t) in tally.items()))
    print(f"{len(results) - bad}/{len(results)} rejected for the stated reason "
          "(* = logic test on a resealed ledger; controls: baseline, harness, reseal, symlinks)")
    sys.exit(1 if bad else 0)
