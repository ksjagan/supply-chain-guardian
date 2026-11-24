"""Settings and paths in one place. Simple constants, no magic."""
import json
import os
import time
from pathlib import Path

PKG = Path(__file__).resolve().parent          # guardian-v4/guardian
ROOT = PKG.parent                              # guardian-v4
OUT_DIR = ROOT / "out"
CACHE_DIR = PKG / "cache"
DATA_DIR = PKG / "data"
FIXTURES = ROOT / "fixtures"
OFFLINE_DIR = FIXTURES / "osv_offline"

# Limits (section 6 / 4 of the spec)
MAX_MANIFESTS = 50
MAX_COMPONENTS = 5000
CLONE_TIMEOUT_S = 60
CLONE_MAX_MB = 300
AGENT_TIMEOUT_S = 120
TOTAL_TIMEOUT_S = 600
MAX_REPAIRS = 2

# Token budgets per agent and per run
BUDGETS = {"reader": 12000, "analyst": 8000, "skeptic": 6000, "remediator": 6000}
RUN_TOKEN_BUDGET = 40000

# Approximate USD per million tokens (input, output). Estimates only.
PRICES = {"haiku": (0.10, 0.50), "sonnet": (2.0, 10.0)}


def load_env():
    """Read guardian-v4/.env (if present) into os.environ. Never overrides real env."""
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"'))


load_env()


def model_cheap():
    return os.environ.get("GUARDIAN_MODEL_CHEAP", "claude-haiku-5-5")


def model_big():
    return os.environ.get("GUARDIAN_MODEL_BIG", "claude-sonnet-5-5")


def new_run_id():
    return time.strftime("run-%Y%m%d-%H%M%S")


def run_dir(run_id):
    return OUT_DIR / run_id


def read_json(path, default=None):
    p = Path(path)
    if not p.exists():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


def write_json(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")


def load_run(rd):
    """The run settings written when the scan started."""
    return read_json(Path(rd) / "run.json", {})
