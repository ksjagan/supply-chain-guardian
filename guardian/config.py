"""
Configuration: env-vars, model names, timeouts, limits.
All tunable knobs in one place – easy for a beginner to find.
"""
import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT_DIR  = Path(__file__).resolve().parent.parent   # project root
DATA_DIR  = ROOT_DIR / "guardian" / "data"
CACHE_DIR = ROOT_DIR / "cache"
OUT_DIR   = ROOT_DIR / "out"
FIXTURES_DIR = ROOT_DIR / "fixtures"

# ── Auto-load .env if present ──────────────────────────────────────────────────
def _load_env_file():
    env_path = ROOT_DIR / ".env"
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k and not os.environ.get(k):
                            os.environ[k] = v
        except Exception:
            pass

_load_env_file()

# ── LLM Models & API Keys ─────────────────────────────────────────────────────
# Supports Anthropic, Gemini, or OpenAI – whichever API key you provide!
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
GEMINI_API_KEY    = os.environ.get("GEMINI_API_KEY", "")
OPENAI_API_KEY    = os.environ.get("OPENAI_API_KEY", "")

# Preferred models
MODEL_ANTHROPIC = os.environ.get("GUARDIAN_MODEL_ANTHROPIC", "claude-3-5-haiku-20241022")
MODEL_GEMINI    = os.environ.get("GUARDIAN_MODEL_GEMINI",    "gemini-2.5-flash")
MODEL_OPENAI    = os.environ.get("GUARDIAN_MODEL_OPENAI",    "gpt-4o-mini")

# Active provider detection
def get_active_provider() -> tuple[str, str, str]:
    """Returns (provider, api_key, model_name)."""
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini", os.environ["GEMINI_API_KEY"], MODEL_GEMINI
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", os.environ["ANTHROPIC_API_KEY"], MODEL_ANTHROPIC
    if os.environ.get("OPENAI_API_KEY"):
        return "openai", os.environ["OPENAI_API_KEY"], MODEL_OPENAI
    return "none", "", ""

# ── Clone / repo limits ───────────────────────────────────────────────────────
CLONE_TIMEOUT_S   = 60      # seconds before git clone is killed
CLONE_MAX_MB      = 300     # refuse repos larger than this after clone
MAX_MANIFEST_FILES = 50     # stop reading manifests after this many
MAX_COMPONENTS     = 5000   # hard cap on total components

# ── API concurrency ───────────────────────────────────────────────────────────
OSV_CHUNK_SIZE    = 500     # components per OSV /querybatch call
OSV_PARALLEL_MAX  = 10      # parallel detail fetches
AGENT_TIMEOUT_S   = 120     # max seconds any single agent may run
GLOBAL_TIMEOUT_S  = 600     # 10-minute global cap

# ── LLM budget (tokens, illustrative) ────────────────────────────────────────
BUDGET_READER_TOKENS    = 12_000
BUDGET_ANALYST_TOKENS   =  8_000
BUDGET_SKEPTIC_TOKENS   =  6_000
BUDGET_REMEDIATOR_TOKENS=  6_000
BUDGET_GLOBAL_TOKENS    = 40_000
LLM_MAX_REPAIRS         = 2
READER_MAX_ITEMS        = 15

# OSV / KEV endpoints
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL       = "https://api.osv.dev/v1/vulns/{id}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# Canary package (planted fixture for self-test)
CANARY_PACKAGE = "canary-old-cve"
CANARY_VERSION = "0.0.1"
