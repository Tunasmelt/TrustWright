"""Include the unchanged contract tooling and declarative assets in built wheels."""

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class Build(build_py):
    def run(self):
        super().run()
        dest = Path(self.build_lib) / "trustwright" / "_assets"
        for folder in ("schemas", "catalogue", "packs"):
            shutil.copytree(folder, dest / folder, dirs_exist_ok=True)
        (dest / "tools").mkdir(parents=True, exist_ok=True)
        for name in ("validate.py", "digest.py", "render.py"):
            shutil.copyfile(Path("tools") / name, dest / "tools" / name)


setup(cmdclass={"build_py": Build})
