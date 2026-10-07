"""Per-workspace, external, transactional state. Same-user shell access is not isolated."""

import contextlib
import fcntl
import json
import os
import time
import uuid
from datetime import UTC
from pathlib import Path

from .contracts import digest, empty_ledger, requirement_digest
from .safety import Refused, atomic_write, read_regular


def now():
    from datetime import datetime

    return datetime.now(UTC).isoformat()


class State:
    def __init__(self, root, base=None):
        self.workspace_id = digest({"canonical_root": str(root)})
        base = Path(
            base or os.environ.get("TRUSTWRIGHT_STATE_DIR", Path.home() / ".local/share/trustwright")
        ).absolute()
        for p in (base, *base.parents):
            if p.is_symlink():
                raise Refused("state_symlink_refused")
        base = base.resolve()
        if base == root or root in base.parents:
            raise Refused("state_must_be_outside_workspace")
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory = base / self.workspace_id
        if self.directory.is_symlink():
            raise Refused("state_symlink_refused")
        self.directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.file = self.directory / "state.json"

    @contextlib.contextmanager
    def transaction(self):
        fd = os.open(self.directory / "state.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if self.file.exists():
                try:
                    data = json.loads(read_regular(self.file, 8_000_000))
                except (ValueError, TypeError):
                    raise Refused("state_invalid") from None
            else:
                data = {"ledger": empty_ledger(), "pending": {}, "assessments": []}
            yield data
            encoded = json.dumps(data, ensure_ascii=True).encode()
            if len(encoded) > 8_000_000:
                raise Refused("state_size_limit")
            atomic_write(self.file, encoded)

    def read(self):
        with self.transaction() as data:
            return data

    def request(self, intent, ep, req):
        request_id = "confirm-" + uuid.uuid4().hex
        with self.transaction() as d:
            d["pending"] = {k: v for k, v in d["pending"].items() if v["expires"] > time.time()}
            if len(d["pending"]) >= 100:
                raise Refused("pending_request_limit")
            d["pending"][request_id] = {
                "endpoint_id": ep,
                "requirement_id": req,
                "requirement_digest": requirement_digest(intent, ep, req),
                "intent_digest": digest(intent),
                "expires": time.time() + 900,
                "status": "pending",
            }
        return request_id

    def pending(self, request_id, intent):
        with self.transaction() as d:
            return self.check_pending(d, request_id, intent).copy()

    def check_pending(self, d, request_id, intent):
        p = d["pending"].get(request_id)
        if not p:
            raise Refused("unknown_confirmation_request")
        if p["status"] != "pending":
            raise Refused("confirmation_already_consumed")
        if p["expires"] <= time.time():
            raise Refused("confirmation_expired")
        if p["intent_digest"] != digest(intent):
            raise Refused("confirmation_intent_changed")
        return p

    def complete(self, request_id, intent, approved, channel):
        with self.transaction() as d:
            p = self.check_pending(d, request_id, intent)
            p["status"] = "approved" if approved else "declined"
            if approved:
                entry = {k: p[k] for k in ("endpoint_id", "requirement_id", "requirement_digest")}
                entry.update(
                    request_id=request_id,
                    confirmed_by="developer",
                    confirmed_at=now(),
                    channel=channel,
                )
                d["ledger"]["intent_confirmations"] = [
                    c
                    for c in d["ledger"]["intent_confirmations"]
                    if (c["endpoint_id"], c["requirement_id"])
                    != (p["endpoint_id"], p["requirement_id"])
                ] + [entry]
        return {"request_id": request_id, "status": p["status"]}
