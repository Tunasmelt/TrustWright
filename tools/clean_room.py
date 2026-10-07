"""Fifth release gate: build/install a wheel in a fresh environment and exercise MCP.

Also checks that packaged assets exist without the source tree on sys.path.
Dependencies may be downloaded during this release-only command.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
if __name__ == "__main__":
    wheels = sorted((ROOT / "dist").glob("trustwright_mcp-*.whl"))
    if not wheels:
        raise SystemExit("Run python -m build first")
    with tempfile.TemporaryDirectory(prefix="trustwright-clean-") as scratch:
        scratch = Path(scratch)
        subprocess.run([sys.executable, "-m", "venv", str(scratch / "venv")], check=True)
        python = scratch / "venv/bin/python"
        subprocess.run(
            [str(python), "-m", "pip", "install", str(wheels[-1]) + "[test]", "--quiet"], check=True
        )
        shutil.copytree(
            ROOT / "tests", scratch / "tests", ignore=shutil.ignore_patterns("__pycache__")
        )
        shutil.copytree(
            ROOT / "tools", scratch / "tools", ignore=shutil.ignore_patterns("__pycache__")
        )
        env = {**os.environ, "PYTHONPATH": ""}
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                'from trustwright.contracts import ASSETS; from trustwright.service import Service; assert "site-packages" in str(ASSETS); assert (ASSETS / "schemas/report.schema.json").is_file(); print("Installed wheel assets verified")',
            ],
            cwd=scratch,
            env=env,
            check=True,
        )
        subprocess.run(
            [str(python), "-I", "-m", "pytest", "-q", "tests"], cwd=scratch, env=env, check=True
        )
