"""Reuse the baseline's hardened loader and semantic validator."""

import sys
from pathlib import Path

ASSETS = Path(__file__).parent / "_assets"
if not ASSETS.exists():
    ASSETS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ASSETS / "tools"))
import validate as validator  # noqa: E402
from digest import canonical as canonical_json  # noqa: E402
from digest import sha256_bytes  # noqa: E402
from digest import requirement_digest as requirement_digest  # noqa: E402

load = validator.load
PACK_ID = "fastapi-pyjwt-pwdlib"
PACK_DIR = ASSETS / "packs" / PACK_ID
PACK = load(PACK_DIR / "pack.yaml")
CONTROLS = load(ASSETS / "catalogue/controls.yaml")["controls"]


def digest(value):
    return sha256_bytes(canonical_json(value))


def empty_ledger():
    return dict(
        schema_version="0.4",
        observed_runs=[],
        intent_confirmations=[],
        human_attestations=[],
    )


def bundle(intent, findings=()):
    return dict(
        intent=intent,
        findings=list(findings),
        runs=[],
        controls=CONTROLS,
        packs=[(PACK, PACK_DIR)],
    )
