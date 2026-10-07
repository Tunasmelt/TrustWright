"""Verify FINDINGS.md against the regression suite.

Every backticked name in a "Regression tests" column must be a real test in
tools/test_regressions.py, and it must currently be rejected for its stated reason.
Every Fixed finding must cite at least one such test (or explicitly cite a
non-test guard), and every suite test must be cited somewhere (two-way traceability). Run: python tools/check_register.py
"""
import copy
import re
import sys
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_regressions as suite  # noqa: E402
from validate import validate  # noqa: E402

REGISTER = Path(__file__).resolve().parent.parent / "FINDINGS.md"
NON_TEST_GUARDS = ("Release procedure", "Covered by", "Whole suite", "n/a", "To be added")


def register_rows():
    """Yield (finding_id, status, [test names]) from every table with a Regression tests column."""
    header = None
    for line in REGISTER.read_text().splitlines():
        if not line.startswith("|"):
            header = None
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if set(line) <= set("|-: "):
            continue
        if "Regression tests" not in header:
            continue
        row = dict(zip(header, cells))
        yield row["ID"], row.get("Status", ""), row["Regression tests"]


def suite_results():
    results = {}
    for group, fn, expect, reseal in suite.CASES:
        b, l = copy.deepcopy(suite.BASE)
        fn(b, l)
        if reseal:
            suite.reseal_runs(b, l)
        results[fn.__name__] = any(expect in e for e in validate(b, l))
    for group, name, fn, expect in suite.EXTRA:
        results[name] = any(expect in e for e in fn())
    # M1a assertions run through pytest, including a real stdio client and terminal CLI.
    with tempfile.TemporaryDirectory() as scratch:
        xml = Path(scratch) / "m1a.xml"
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "tests", "--junitxml", str(xml)],
            cwd=REGISTER.parent, capture_output=True, text=True, timeout=300, check=False,
        )
        if not xml.exists():
            raise RuntimeError("M1a test runner failed to produce its result artifact")
        cases = list(ET.parse(xml).getroot().iter("testcase"))
        for case in cases:
            results[case.attrib["name"]] = not any(case.find(tag) is not None for tag in ("failure", "error", "skipped"))
        if completed.returncode and all(results.values()):
            raise RuntimeError("M1a test runner exited unsuccessfully")
    return results


if __name__ == "__main__":
    results = suite_results()
    problems, cited = [], set()
    for fid, status, cell in register_rows():
        names = re.findall(r"`([a-z0-9_]+)`", cell)
        if status == "Fixed" and not names and not any(g in cell for g in NON_TEST_GUARDS):
            problems.append(f"{fid}: Fixed but cites no regression test or guard")
        for n in names:
            cited.add(n)
            if n not in results:
                problems.append(f"{fid}: cites `{n}`, which is not a test in the suite")
            elif not results[n]:
                problems.append(f"{fid}: `{n}` is not currently rejected for its stated reason")
    for n in sorted(set(results) - cited):
        problems.append(f"suite test `{n}` is not cited in the register (untraceable)")
    for p in problems:
        print("FAIL", p)
    print(f"{len(cited)}/{len(results)} suite tests cited in the register; "
          f"all exist, all pass, none untraceable: {not problems}")
    sys.exit(1 if problems else 0)
