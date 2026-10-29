"""Static discovery only: never import the project, consult its interpreter, or run hooks."""

import ast
import os
import platform
import re
import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from .contracts import CONTROLS, PACK, PACK_ID, digest
from .safety import MAX_FILES, MAX_TREE, Refused, read_regular

EXCLUDED = {
    ".git",
    ".trustwright",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".aws",
    ".ssh",
    ".gnupg",
}
MANIFESTS = {
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "pyproject.toml",
}


def snapshot(root):
    files = {}
    total = 0
    entries = 0

    def traversal_error(_):
        raise Refused("workspace_traversal_failed")

    for directory, dirs, names in os.walk(root, followlinks=False, onerror=traversal_error):
        entries += len(dirs) + len(names)
        if entries > 10000:
            raise Refused("workspace_entry_limit")
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED)
        for d in dirs:
            if (Path(directory) / d).is_symlink():
                raise Refused("symlink_refused")
        for name in sorted(names):
            if name.startswith(".env") or name.endswith((".pem", ".key", ".p12", ".pfx")):
                continue
            p = Path(directory) / name
            if p.suffix != ".py" and name not in MANIFESTS:
                continue
            data = read_regular(p)
            total += len(data)
            if total > MAX_TREE or len(files) >= MAX_FILES:
                raise Refused("project_snapshot_limit")
            files[p.relative_to(root).as_posix()] = data
    return files


def dependencies(files):
    records = []

    def add(name, version, source, file, resolved):
        name = name.lower().replace("_", "-")
        if name not in {"fastapi", "pyjwt", "pwdlib"}:
            return
        if resolved:
            try:
                version = str(Version(version))
                if not re.fullmatch(
                    r"[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?",
                    version,
                ):
                    version = None
                    resolved = False
            except InvalidVersion:
                version = None
                resolved = False
        else:
            # Ranges are unresolved; do not echo arbitrary local version labels.
            version = None
        records.append(
            dict(
                name=name,
                version=version,
                source=source,
                resolved=resolved,
                evidence_id="file-" + digest(file)[:16],
            )
        )

    for file, raw in files.items():
        name = Path(file).name
        try:
            if name in ("uv.lock", "poetry.lock"):
                for p in tomllib.loads(raw.decode()).get("package", []):
                    add(p["name"], p.get("version"), "lockfile", file, True)
            elif name == "Pipfile.lock":
                import json

                d = json.loads(raw)
                for group in ("default", "develop"):
                    for n, v in d.get(group, {}).items():
                        value = v.get("version", "")
                        add(
                            n,
                            value.removeprefix("=="),
                            "lockfile",
                            file,
                            value.startswith("=="),
                        )
            elif name in ("requirements.txt", "pyproject.toml"):
                lines = (
                    raw.decode().splitlines()
                    if name == "requirements.txt"
                    else tomllib.loads(raw.decode()).get("project", {}).get("dependencies", [])
                )
                for line in lines:
                    try:
                        r = Requirement(line.split(" #")[0])
                    except InvalidRequirement:
                        continue
                    spec = str(r.specifier)
                    pinned = bool(re.fullmatch(r"==[^*,]+", spec))
                    add(r.name, spec[2:] if pinned else spec, "manifest", file, pinned)
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise Refused("dependency_document_malformed") from None
    present = {r["name"] for r in records}
    text = b"\n".join(raw for p, raw in files.items() if p.endswith(".py")).decode(
        "utf8", errors="replace"
    )
    for module, name in [
        ("fastapi", "fastapi"),
        ("jwt", "pyjwt"),
        ("pwdlib", "pwdlib"),
    ]:
        if name not in present and re.search(r"(?:from|import)\s+" + module + r"\b", text):
            add(name, None, "import_marker", "source", False)
    return records


def detect(files):
    deps = dependencies(files)
    by = {}
    for name in ("fastapi", "pyjwt", "pwdlib"):
        opts = [d for d in deps if d["name"] == name]
        if opts:
            locks = [d for d in opts if d["source"] == "lockfile"]
            chosen = locks or opts
            versions = {d["version"] for d in chosen}
            by[name] = {**chosen[0], "conflicting": len(versions) > 1}
    supported = bool(by.get("fastapi"))
    for name, d in by.items():
        ranges = {c["package"]: c["supported_versions"] for c in PACK["components"]}
        if d["conflicting"]:
            supported = False
        if (
            d["resolved"]
            and name in ranges
            and Version(d["version"]) not in SpecifierSet(ranges[name])
        ):
            supported = False
    covered = {check["control_id"] for check in PACK["checks"]} if supported else set()
    return {
        "dependencies": list(by.values()),
        "applicable_packs": [PACK_ID] if supported else [],
        "uncovered_controls": [c["id"] for c in CONTROLS if c["id"] not in covered],
        "limitations": [
            "Versions describe files, not an observed runtime environment.",
            "Only Python/FastAPI route discovery is implemented.",
            "No dependency advisories are queried in M1a.",
        ],
    }


def routes(files):
    """Return (routes, errors); each error names its file reference and one distinct reason."""
    result = []
    errors = []
    for file, raw in files.items():
        if not file.endswith(".py"):
            continue
        ref = "file-" + digest(file)[:16]

        def gap(reason):
            errors.append({"scope_ref": ref, "reason": reason})

        try:
            tree = ast.parse(raw)
        except (SyntaxError, UnicodeError, ValueError, RecursionError):
            # Parseability depends on the interpreter (e.g. PEP 758 needs 3.14), so the version is part of the reason.
            errors.append(
                {"scope_ref": ref, "reason": "source_parse_error", "python_version": platform.python_version()}
            )
            continue
        constructors = set()
        for item in tree.body:
            if isinstance(item, ast.ImportFrom) and item.module == "fastapi":
                constructors.update(a.asname or a.name for a in item.names if a.name == "FastAPI")
            elif isinstance(item, ast.Import):
                constructors.update(
                    (a.asname or a.name) + ".FastAPI" for a in item.names if a.name == "fastapi"
                )
        assignments = {}
        for item in tree.body:
            if isinstance(item, (ast.Assign, ast.AnnAssign)):
                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        assignments.setdefault(target.id, []).append(item.value)
        apps = {
            name
            for name, values in assignments.items()
            if len(values) == 1
            and isinstance(values[0], ast.Call)
            and ast.unparse(values[0].func) in constructors
        }
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            deps = []
            for part in ast.walk(node.args):
                if (
                    isinstance(part, ast.Call)
                    and isinstance(part.func, ast.Name)
                    and part.func.id == "Depends"
                    and part.args
                ):
                    value = ast.unparse(part.args[0])
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", value):
                        deps.append(value)
            argument_deps = list(deps)
            for dec in node.decorator_list:
                deps = list(argument_deps)
                if (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr in {"api_route", "route", "websocket", "websocket_route"}
                ):
                    gap("unsupported_route_form")
                if (
                    not isinstance(dec, ast.Call)
                    or not isinstance(dec.func, ast.Attribute)
                    or dec.func.attr
                    not in {"get", "post", "put", "patch", "delete", "head", "options"}
                ):
                    continue
                if not isinstance(dec.func.value, ast.Name) or dec.func.value.id not in apps:
                    gap("unsupported_route_form")
                    continue
                if not dec.args:
                    gap("unsupported_route_form")
                    continue
                if not isinstance(dec.args[0], ast.Constant) or not isinstance(dec.args[0].value, str):
                    gap("unresolved_dynamic_route")
                    continue
                path = dec.args[0].value
                if not re.fullmatch(r"/[A-Za-z0-9_{}/.\-]*", path):
                    gap("unsupported_route_form")
                    continue
                for kw in dec.keywords:
                    if kw.arg == "dependencies":
                        for part in ast.walk(kw.value):
                            if (
                                isinstance(part, ast.Call)
                                and isinstance(part.func, ast.Name)
                                and part.func.id == "Depends"
                                and part.args
                            ):
                                value = ast.unparse(part.args[0])
                                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", value):
                                    deps.append(value)
                result.append(
                    dict(
                        method=dec.func.attr.upper(),
                        path=path,
                        file=file,
                        line=min(d.lineno for d in node.decorator_list),
                        receiver=dec.func.value.id,
                        end_line=node.lineno,
                        dependency=deps[0] if len(set(deps)) == 1 else None,
                    )
                )
    if len(result) > 100:
        raise Refused("route_limit")
    return result, errors
