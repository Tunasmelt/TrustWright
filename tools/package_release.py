"""Package only source, distributables and passing release evidence; never local environments."""

import hashlib
import json
from pathlib import Path
import zipfile
import tomllib
from release_support import check_release

ROOT = Path(__file__).resolve().parent.parent
if __name__ == "__main__":
    results = json.loads((ROOT / "release-validation/results.json").read_text())
    try:
        check_release(ROOT, results)
    except ValueError as error:
        raise SystemExit(str(error)) from None
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    excluded = {
        ".venv",
        ".git",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        ".trustwright",
    }
    allowed_dirs = {
        "trustwright",
        "acceptance",
        "catalogue",
        "examples",
        "handoff",
        "packs",
        "schemas",
        "tests",
        "tools",
        ".github",
        "release-validation",
        "dist",
    }
    allowed_files = {
        "README.md",
        "RELEASE.md",
        "REVIEW-LOOPS.md",
        "FINDINGS.md",
        "CHANGELOG.md",
        "LICENSE",
        "pyproject.toml",
        "setup.py",
        "MANIFEST.in",
        "requirements-dev.lock",
        ".gitignore",
    }
    paths = []
    for p in sorted(ROOT.rglob("*")):
        rel = p.relative_to(ROOT)
        if rel.parts[0] not in allowed_dirs and rel.as_posix() not in allowed_files:
            continue
        if any(
            part.startswith(".env") or part in {".aws", ".ssh", ".gnupg"} for part in rel.parts
        ) or p.suffix.lower() in {".key", ".pem", ".p12", ".pfx"}:
            continue
        if any(
            part in excluded or part.endswith(".egg-info") or part.startswith(".venv")
            for part in rel.parts
        ):
            continue
        if p.is_symlink():
            raise SystemExit("Release file is a symlink: " + str(rel))
        if not p.is_file() or p.suffix == ".pyc" or p.name == "SHA256SUMS":
            continue
        if rel.parts[0] == "dist" and p.suffix != ".whl":
            continue
        paths.append(p)
    checksums = "".join(
        hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.relative_to(ROOT).as_posix() + "\n"
        for p in paths
    )
    (ROOT / "SHA256SUMS").write_text(checksums)
    target = ROOT.parent / f"trustwright-m1a-v{version}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for p in paths + [ROOT / "SHA256SUMS"]:
            archive.write(p, Path("trustwright-m1a") / p.relative_to(ROOT))
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None:
            raise SystemExit("Archive integrity check failed")
    print(target)
    print("Files:", len(paths) + 1, "Bytes:", target.stat().st_size)
    print("SHA-256:", hashlib.sha256(target.read_bytes()).hexdigest())
