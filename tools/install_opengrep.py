"""Install the Linux x86-64 release used by CI after checking the pinned SHA-256.

Other platforms: install Opengrep 1.30.0 from its release and pass --opengrep.
The scanner is an external LGPL component, never bundled in trustwright wheels.
"""

import hashlib
import os
import platform
import sys
import urllib.request
from pathlib import Path

URL = "https://github.com/opengrep/opengrep/releases/download/v1.30.0/opengrep_manylinux_x86"
SHA256 = "35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c"
if __name__ == "__main__":
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise SystemExit(
            "This helper supports Linux x86-64 only; install the matching 1.30.0 release manually."
        )
    target = (
        Path(sys.argv[1]).absolute() if len(sys.argv) > 1 else Path.home() / ".local/bin/opengrep"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    import tempfile

    fd, name = tempfile.mkstemp(dir=target.parent, prefix=".opengrep-")
    try:
        h = hashlib.sha256()
        size = 0
        with (
            os.fdopen(fd, "wb") as f,
            urllib.request.urlopen(URL, timeout=60) as response,
        ):
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 500_000_000:
                    raise SystemExit("Download exceeded size cap")
                h.update(chunk)
                f.write(chunk)
        if h.hexdigest() != SHA256:
            raise SystemExit("Checksum mismatch; refusing installation")
        os.chmod(name, 0o755)
        os.replace(name, target)
        print("Installed checksum-verified Opengrep 1.30.0 at", target)
    finally:
        if os.path.exists(name):
            os.unlink(name)
