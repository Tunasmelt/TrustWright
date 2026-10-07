"""Run each required gate and bind successful outcomes to the exact tested inputs."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from release_support import source_digest

ROOT = Path(__file__).resolve().parent.parent
if __name__ == "__main__":
    output = ROOT / "release-validation"
    output.mkdir(exist_ok=True)
    commands = [
        (
            "lint",
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                "trustwright",
                "tests",
                "setup.py",
                "tools/install_opengrep.py",
                "tools/clean_room.py",
                "tools/release_support.py",
                "tools/release.py",
                "tools/package_release.py",
            ],
        ),
        ("demo", [sys.executable, "tools/demo_slice.py"]),
        ("contracts", [sys.executable, "tools/validate.py", "--run-rules"]),
        ("regressions", [sys.executable, "tools/test_regressions.py"]),
        ("register", [sys.executable, "tools/check_register.py"]),
        ("build", [sys.executable, "-m", "build"]),
        ("clean-room", [sys.executable, "tools/clean_room.py"]),
    ]
    results = []
    initial = source_digest(ROOT)
    for name, command in commands:
        print("Running " + name, flush=True)
        if source_digest(ROOT) != initial:
            raise SystemExit("release_source_binding: source changed during gates")
        if name == "build":
            for p in (ROOT / "dist").glob("trustwright_mcp-*"):
                p.unlink()
        started = time.monotonic()
        with (output / (name + ".log")).open("w") as log:
            result = subprocess.run(
                command,
                cwd=ROOT,
                env=os.environ.copy(),
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
        row = {
            "gate": name,
            "exit_code": result.returncode,
            "seconds": round(time.monotonic() - started, 2),
            "source_digest": initial,
        }
        if name in ("build", "clean-room"):
            wheels = list((ROOT / "dist").glob("*.whl"))
            if len(wheels) == 1:
                row["wheel_digest"] = hashlib.sha256(wheels[0].read_bytes()).hexdigest()
        results.append(row)
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(name + ": " + str(result.returncode), flush=True)
        if result.returncode:
            raise SystemExit(result.returncode)
        if source_digest(ROOT) != initial:
            raise SystemExit("release_source_binding: source changed during gate")
