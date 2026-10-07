"""Measure route discovery against an acceptance fixture through the public draft_intent path.

Usage: python acceptance/tools/measure_discovery.py acceptance/<fixture> [--json]
Copies the fixture to a temporary directory, runs TrustWright's draft_intent there (project code is parsed,
never executed), and compares the drafted (method, path) pairs with the fixture's expected-inventory.csv.
Exit code 0 when every expected mounted pair is drafted and nothing extra is invented; 1 otherwise.
"""
import csv
import json
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

from trustwright.service import Service

fixture = Path(sys.argv[1]).resolve()
rows = list(csv.DictReader(open(fixture / "expected-inventory.csv", newline="")))
expected = {(r["method"], r["path"]) for r in rows if r.get("mounted_when", "always") != "never"}
never = {(r["method"], r["path"]) for r in rows if r.get("mounted_when") == "never"}
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp) / "project"
    shutil.copytree(fixture, root, ignore=shutil.ignore_patterns("expected-inventory.csv", "*.md", "SHA256SUMS"))
    service = Service(root, Path(tmp) / "state", None)
    try:
        result = service.draft_intent()
        intent = yaml.safe_load((root / ".trustwright/security-intent.yaml").read_text())
        drafted = {(e["method"], e["path"]) for e in intent["endpoints"]}
        errors = result.get("discovery_errors", [])
        refusal = None
    except Exception as e:  # a refusal is a measurement outcome, not a crash of this tool
        drafted, errors, refusal = set(), [], f"{type(e).__name__}: {e}"
out = {
    "fixture": fixture.name,
    "python": sys.version.split()[0],
    "expected_mounted": len(expected),
    "correct": len(drafted & expected),
    "missing": sorted(expected - drafted),
    "invented": sorted(drafted - expected - never),
    "reported_unmounted_as_mounted": sorted(drafted & never),
    "discovery_errors": errors,
    "refusal": refusal,
}
if "--json" in sys.argv:
    print(json.dumps(out, indent=1))
else:
    print(f"{out['fixture']} (python {out['python']}): {out['correct']}/{out['expected_mounted']} correct, "
          f"{len(out['missing'])} missing, {len(out['invented'])} invented, "
          f"{len(out['reported_unmounted_as_mounted'])} unmounted reported, "
          f"{len(errors)} discovery errors" + (f", refused: {refusal}" if refusal else ""))
ok = not out["missing"] and not out["invented"] and not out["reported_unmounted_as_mounted"]
sys.exit(0 if ok else 1)
