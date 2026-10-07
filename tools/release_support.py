"""Content binding for local release gates; not an attestation against a malicious OS user."""

import hashlib
import json
from pathlib import Path

EXPECTED = {"lint", "demo", "contracts", "regressions", "register", "build", "clean-room"}


def source_digest(root):
    root = Path(root)
    paths = []
    for name in ("trustwright", "schemas", "catalogue", "packs", "tests", "tools", ".github", "acceptance"):
        paths.extend(
            p
            for p in (root / name).rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
        )
    paths.extend(
        root / n
        for n in (
            "pyproject.toml",
            "setup.py",
            "MANIFEST.in",
            "FINDINGS.md",
            "requirements-dev.lock",
            "LICENSE",
            "examples/findings.json",
            "examples/security-intent.yaml",
        )
        if (root / n).exists()
    )
    entries = []
    for p in sorted(paths):
        if p.is_symlink():
            raise ValueError("release_source_binding: symlink in tested inputs")
        entries.append([p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()])
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()


def check_release(root, results):
    root = Path(root)
    current = source_digest(root)
    if (
        not isinstance(results, list)
        or len(results) != len(EXPECTED)
        or {r.get("gate") for r in results} != EXPECTED
        or any(r.get("exit_code") != 0 for r in results)
    ):
        raise ValueError("release_gates_missing_or_failed")
    if any(r.get("source_digest") != current for r in results):
        raise ValueError("release_source_binding: source changed or gate binding missing")
    wheels = list((root / "dist").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("release_wheel_binding: exactly one wheel required")
    wheel_hash = hashlib.sha256(wheels[0].read_bytes()).hexdigest()
    for name in ("build", "clean-room"):
        row = next(r for r in results if r["gate"] == name)
        if row.get("wheel_digest") != wheel_hash:
            raise ValueError("release_wheel_binding: wheel changed or not tested")
