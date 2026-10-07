"""Run only bundled rule definitions against a bounded copy of source files."""

import json
import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import yaml

from .contracts import PACK_DIR, load, validator
from .safety import MAX_OUTPUT, Refused

ENGINE_VERSION = "1.30.0"


def bounded_process(argv, cwd, timeout=60, cap=MAX_OUTPUT):
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(cwd),
        "LANG": "C.UTF-8",
        "OPENGREP_SEND_METRICS": "off",
        "SEMGREP_SEND_METRICS": "off",
        "NO_COLOR": "1",
    }
    with subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as p:
        chunks = {p.stdout: bytearray(), p.stderr: bytearray()}
        size = 0
        try:
            with selectors.DefaultSelector() as sel:
                for stream in chunks:
                    sel.register(stream, selectors.EVENT_READ)
                end = time.monotonic() + timeout
                while sel.get_map():
                    if time.monotonic() > end:
                        raise Refused("scanner_timeout")
                    for key, _ in sel.select(min(0.1, max(0, end - time.monotonic()))):
                        data = os.read(key.fileobj.fileno(), 8192)
                        if not data:
                            sel.unregister(key.fileobj)
                            continue
                        size += len(data)
                        if size > cap:
                            raise Refused("scanner_output_limit")
                        chunks[key.fileobj].extend(data)
                code = p.wait(timeout=max(0.1, end - time.monotonic()))
            if code != 0:
                raise Refused("scanner_nonzero_exit")
            return bytes(chunks[p.stdout])
        except subprocess.TimeoutExpired:
            raise Refused("scanner_timeout") from None
        finally:
            # Kill descendants even if the direct process exits before its children.
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()


def engine_identity(engine, workspace):
    if not engine:
        return {
            "name": "opengrep",
            "version": None,
            "digest": None,
            "status": "unavailable",
        }
    p = Path(engine).resolve()
    if p == workspace or workspace in p.parents:
        raise Refused("scanner_must_be_outside_workspace")
    import hashlib

    try:
        with p.open("rb") as f:
            h = hashlib.file_digest(f, "sha256").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            output = (
                bounded_process([str(p), "--version"], Path(tmp), timeout=15, cap=4096)
                .decode()
                .strip()
            )
        if output != ENGINE_VERSION:
            raise Refused("scanner_version_mismatch")
    except OSError:
        raise Refused("scanner_unavailable") from None
    return {"name": "opengrep", "version": output, "digest": h, "status": "available"}


def scan(engine, files, check, params=None, *, target=None):
    params = params or {}
    declared = {p["name"]: p["pattern"] for p in check.get("params", [])}
    if set(params) != set(declared) or any(
        not re.fullmatch(declared[k], v) for k, v in params.items()
    ):
        raise Refused("structural_parameters_invalid")
    rules = load(PACK_DIR / check["rule_file"])
    rules["rules"] = [r for r in rules["rules"] if r["id"] == check["rule_id"]]
    text = validator.substitute_params(yaml.safe_dump(rules, sort_keys=False), params)
    with tempfile.TemporaryDirectory(prefix="trustwright-scan-") as tmp:
        root = Path(tmp)
        source = root / "source"
        source.mkdir()
        # Opaque paths prevent filenames and project scanner config becoming arguments/config.
        mapping = {}
        for i, (file, data) in enumerate(sorted(files.items())):
            if not file.endswith(".py"):
                continue
            name = f"file_{i}.py"
            (source / name).write_bytes(data)
            mapping[name] = file
        config = root / "rule.yaml"
        config.write_text(text)
        if not mapping:
            return []
        raw = bounded_process(
            [
                str(engine),
                "scan",
                "--config",
                str(config),
                "--json",
                "-q",
                "--no-git-ignore",
                "--disable-nosem",
                "--disable-version-check",
                "--jobs",
                "1",
                "--timeout",
                "10",
                str(source),
            ],
            root,
        )
        try:
            data = json.loads(raw)
            if (
                not isinstance(data, dict)
                or not isinstance(data.get("results"), list)
                or not isinstance(data.get("errors"), list)
            ):
                raise ValueError
            if data["errors"]:
                raise Refused("scanner_reported_errors")
            scanned = data.get("paths", {}).get("scanned")
            expected = {str((source / name).resolve()) for name in mapping}
            if (
                not isinstance(scanned, list)
                or any(not isinstance(p, str) for p in scanned)
                or {str(Path(p).resolve()) for p in scanned} != expected
                or data.get("skipped_rules")
            ):
                raise Refused("scanner_incomplete_coverage")
            if len(data["results"]) > 200:
                raise Refused("scanner_match_limit")
            matches = []
            for hit in data["results"]:
                if str(hit["check_id"]).split(".")[-1] != check["rule_id"]:
                    raise ValueError
                path = Path(hit["path"])
                if path.resolve().parent != source:
                    raise ValueError
                file = mapping[path.name]
                line = hit["start"]["line"]
                if type(line) is not int or not 1 <= line <= len(files[file].splitlines()):
                    raise ValueError
                if target is not None:
                    receiver = hit["extra"]["metavars"]["$APP"]["abstract_content"]
                    if (
                        file != target["file"]
                        or not target["line"] <= line <= target["end_line"]
                        or receiver != target["receiver"]
                    ):
                        continue
                matches.append({"path": file, "start_line": line})
            return matches
        except Refused:
            raise
        except (ValueError, TypeError, KeyError):
            raise Refused("scanner_malformed_output") from None
