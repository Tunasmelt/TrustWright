import os
import shutil
from pathlib import Path

import pytest

from trustwright.service import Service

FIXTURE = Path(__file__).parent / "fixtures/fastapi"


@pytest.fixture
def service(tmp_path):
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root)
    return Service(
        root,
        tmp_path / "state",
        os.environ.get("TRUSTWRIGHT_OPENGREP") or shutil.which("opengrep"),
    )


def choose_fixture_intent(service):
    import yaml

    intent = yaml.safe_load(service.intent_path.read_text())
    for endpoint in intent["endpoints"]:
        if endpoint["path"] == "/documents/{doc_id}":
            endpoint["requirements"][0]["policy"] = {"kind": "authenticated"}
    service.intent_path.write_text(yaml.safe_dump(intent))
    return service.validate_intent()
