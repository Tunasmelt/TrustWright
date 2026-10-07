"""Canonical digests shared by the server, the validator, and the demo runner.

Principle (v0.3): a trust-ledger entry authenticates *content*, never a pointer.
Each digest below covers everything a conclusion depends on, so editing any of
it invalidates the ledger entry.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path

TREE_ALGORITHM = "sha256-sorted-entries-v2"
EXCLUDED_DIRS = {".git", "__pycache__"}
EXCLUDED_PREFIXES = (".trustwright/results/",)


class WorkspaceError(Exception):
    """The workspace cannot be digested safely (for example, a symlink escapes it)."""


def _is_excluded(rel: str) -> bool:
    """True if a workspace-relative path lies in, or is, content the digest skips."""
    parts = rel.split("/")
    return (any(part in EXCLUDED_DIRS for part in parts) or rel.endswith(".pyc")
            or any((rel + "/").startswith(prefix) for prefix in EXCLUDED_PREFIXES))


def _contains_excluded(rel: str) -> bool:
    """True if a directory at rel is an ancestor of an excluded prefix (or is the root itself)."""
    return rel in ("", ".") or any(prefix.startswith(rel + "/") for prefix in EXCLUDED_PREFIXES)


def _resolve_link(p: Path) -> Path:
    """Detect kernel symlink loops even when non-strict resolve tolerates them."""
    try:
        os.stat(p)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise RuntimeError("symlink loop") from None
        if e.errno not in (errno.ENOENT, errno.ENOTDIR):
            raise
    return p.resolve(strict=False)


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def tree_digest(root: Path) -> tuple[str, int]:
    """sha256-sorted-entries-v2.

    One entry per path, sorted:
      file     'f\\0<rel>\\0<sha256 of content>\\n'
      symlink  'l\\0<rel>\\0<link target as written>\\n'
    Symlinks are recorded, not followed, so retargeting one changes the digest.
    A symlink is refused (WorkspaceError) unless its fully resolved target is inside
    the workspace AND hashed: targets in excluded areas (.git, __pycache__,
    .trustwright/results/, *.pyc) and directories containing an excluded area are
    refused, because their content would not be covered. Chains are resolved fully.
    """
    root = Path(root).resolve()
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        names = filenames + [d for d in dirnames if (base / d).is_symlink()]
        for name in names:
            p = base / name
            rel = p.relative_to(root).as_posix()
            if any(rel.startswith(x) for x in EXCLUDED_PREFIXES) or rel.endswith(".pyc"):
                continue
            if p.is_symlink():
                try:
                    target = _resolve_link(p)
                    target_rel = target.relative_to(root).as_posix()
                except (ValueError, RuntimeError, OSError):
                    raise WorkspaceError(f"symlink {rel!r} points outside the workspace or loops") from None
                if _is_excluded(target_rel):
                    raise WorkspaceError(f"symlink {rel!r} targets excluded content {target_rel!r}; it would not be hashed")
                if target.is_dir() and _contains_excluded(target_rel):
                    raise WorkspaceError(f"symlink {rel!r} targets directory {target_rel or '.'!r}, which contains excluded content")
                entries.append(f"l\0{rel}\0{os.readlink(p)}\n")
            elif p.is_file():
                entries.append(f"f\0{rel}\0{sha256_file(p)}\n")
            elif not p.is_dir():
                raise WorkspaceError(f"{rel!r} is not a regular file, directory, or symlink (FIFO, socket, or device)")
    # Walking skips symlinked directories' contents (followlinks=False) but records the link itself.
    entries.sort()
    return sha256_bytes("".join(entries).encode()), len(entries)


def run_record_digest(run: dict) -> str:
    """Covers the entire run document: scenarios, outcomes, observed statuses, intent
    references, template identity, consistency checks, snapshot, and artifact hashes."""
    return sha256_bytes(canonical(run))


def requirement_digest(intent: dict, endpoint_id: str, requirement_id: str) -> str:
    """Covers the endpoint's identity (method, path), the requirement, and any resource
    or role definition the policy depends on. Moving or redefining any of them voids it."""
    ep = next((e for e in intent["endpoints"] if e["id"] == endpoint_id), None)
    req = next((r for r in ep["requirements"] if r["id"] == requirement_id), None) if ep else None
    if req is None:
        raise LookupError(f"requirement {endpoint_id}/{requirement_id} does not exist in the intent")
    policy = req["policy"]
    subject = {"endpoint": {"id": ep["id"], "method": ep["method"], "path": ep["path"]},
               "requirement": {"id": req["id"], "control_id": req["control_id"], "policy": policy}}
    if policy["kind"] == "owner_of":
        subject["resource"] = next((r for r in intent.get("resources", []) if r["id"] == policy["resource"]), None)
    if policy["kind"] == "role":
        subject["principal"] = next((p for p in intent["principals"] if p["id"] == policy["role"]), None)
    return sha256_bytes(canonical(subject))


def attestation_subject_digest(finding: dict, intent: dict) -> str:
    """What a human reviewer attested to: the conclusion, its scope, its limitations,
    the requirement it answers, and the code snapshot that was reviewed."""
    attest = [e for e in finding["evidence"] if e["type"] == "human_attestation"]
    subject = {
        "finding_id": finding["id"], "control_id": finding["control_id"],
        "intent_ref": finding["intent_ref"], "scope": finding["scope"],
        "result": finding["result"], "severity": finding.get("severity"),
        "limitations": finding["limitations"],
        "reviewed_tree_digest": [e.get("reviewed_tree_digest") for e in attest],
    }
    if finding["intent_ref"]:
        subject["requirement_digest"] = requirement_digest(
            intent, finding["intent_ref"]["endpoint_id"], finding["intent_ref"]["requirement_id"])
    return sha256_bytes(canonical(subject))
