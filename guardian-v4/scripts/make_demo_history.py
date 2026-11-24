"""Python generator for fixtures/attack-demo git history with 2 commits."""
import os
import shutil
import stat
import subprocess
from pathlib import Path

target = Path(__file__).resolve().parent.parent / "fixtures" / "attack-demo"


def remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)


if target.exists():
    shutil.rmtree(target, onerror=remove_readonly)
target.mkdir(parents=True, exist_ok=True)


def git(*args):
    subprocess.run(["git", *args], cwd=str(target), check=True, capture_output=True)


git("init", "-b", "main")
git("config", "user.name", "Guardian Demo")
git("config", "user.email", "demo@guardian.local")

# Commit 1
pkg1 = """{
  "name": "attack-demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "3.10.1"
  }
}"""
lock1 = """{
  "name": "attack-demo",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "attack-demo",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "3.10.1"
      }
    },
    "node_modules/lodash": {
      "version": "3.10.1",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-3.10.1.tgz",
      "integrity": "sha512-sha512-originalhash123=="
    }
  }
}"""
(target / "package.json").write_text(pkg1, encoding="utf-8")
(target / "package-lock.json").write_text(lock1, encoding="utf-8")
git("add", "package.json", "package-lock.json")
git("commit", "-m", "Initial clean release")

# Commit 2
pkg2 = """{
  "name": "attack-demo",
  "version": "1.1.0",
  "dependencies": {
    "lodash": "4.17.15",
    "recat": "1.0.0"
  }
}"""
lock2 = """{
  "name": "attack-demo",
  "version": "1.1.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "attack-demo",
      "version": "1.1.0",
      "dependencies": {
        "lodash": "4.17.15",
        "recat": "1.0.0"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
      "integrity": "sha512-sha512-TAMPERED_MODIFIED_HASH_999=="
    },
    "node_modules/recat": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/recat/-/recat-1.0.0.tgz",
      "integrity": "sha512-PLANTED_TYPOSQUAT_HASH==",
      "hasInstallScript": true
    }
  }
}"""
(target / "package.json").write_text(pkg2, encoding="utf-8")
(target / "package-lock.json").write_text(lock2, encoding="utf-8")
git("add", "package.json", "package-lock.json")
git("commit", "-m", "Add recats and bump lodash")
print("attack-demo initialized with 2 commits successfully!")
