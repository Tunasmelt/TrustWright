"""Bounded input and file access. Never format caught exceptions or scanner output."""

import json
import math
import os
import stat
from pathlib import Path

MAX_FRAME = 65_536
MAX_FILE = 1_000_000
MAX_TREE = 20_000_000
MAX_FILES = 500
MAX_OUTPUT = 1_000_000


class Refused(ValueError):
    pass


def strict_json(raw):
    if len(raw) > MAX_FRAME:
        raise Refused("message_too_large: maximum 65536 bytes")

    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise Refused("malformed_json: duplicate key")
            d[k] = v
        return d

    def constant(_):
        raise Refused("malformed_json: non-finite number")

    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        obj = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)

        def walk(v, depth=0):
            if depth > 32:
                raise Refused("malformed_json: maximum nesting exceeded")
            if isinstance(v, float) and not math.isfinite(v):
                raise Refused("malformed_json: non-finite number")
            if isinstance(v, str):
                if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
                    raise Refused("malformed_json: invalid Unicode")
            elif isinstance(v, dict):
                for k, x in v.items():
                    walk(k, depth + 1)
                    walk(x, depth + 1)
            elif isinstance(v, list):
                for x in v:
                    walk(x, depth + 1)

        walk(obj)
        return obj
    except (ValueError, UnicodeError, RecursionError) as e:
        if isinstance(e, Refused):
            raise
        raise Refused("malformed_json: invalid bounded JSON") from None


def read_regular(path, cap=MAX_FILE):
    """Refuse links in every component; open final entry without following links."""
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise Refused("symlink_refused: use ordinary files")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise Refused("special_file_refused")
            data = f.read(cap + 1)
        if len(data) > cap:
            raise Refused("file_too_large")
        return data
    except OSError:
        raise Refused("file_unavailable") from None


def atomic_write(path, data):
    import tempfile

    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise Refused("symlink_refused")
    fd, tmp = tempfile.mkstemp(prefix=".trustwright-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
