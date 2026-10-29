import hashlib
from pathlib import Path

import pytest

ACCEPTANCE = Path(__file__).resolve().parent.parent / "acceptance"
FIXTURES = ("fastapi-template", "router-patterns")


@pytest.mark.skipif(not ACCEPTANCE.is_dir(), reason="acceptance fixtures are not shipped in the wheel")
def test_acceptance_fixture_bytes_match_checksums():
    # A checkout must reproduce the pinned bytes; line-ending normalization silently changed one (TW-03).
    mismatched = []
    for fixture in FIXTURES:
        root = ACCEPTANCE / fixture
        entries = [line.split(maxsplit=1) for line in (root / "SHA256SUMS").read_text().splitlines() if line.strip()]
        assert entries, fixture
        mismatched += [
            f"{fixture}/{name}" for digest, name in entries
            if hashlib.sha256((root / name.lstrip("*")).read_bytes()).hexdigest() != digest
        ]
    assert mismatched == []
