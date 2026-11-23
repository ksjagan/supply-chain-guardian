"""
Configuration: env-vars, model names, timeouts, limits.
All tunable knobs in one place – easy for a beginner to find.
"""
import os
from pathlib import Path

# ── LLM Models ───────────────────────────────────────────────────────────────
# Set these in your .env file or shell before running.
MODEL_CHEAP = os.environ.get("GUARDIAN_MODEL_CHEAP", "claude-haiku-4-5")
MODEL_BIG   = os.environ.get("GUARDIAN_MODEL_BIG",   "claude-sonnet-4-5")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

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

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT_DIR  = Path(__file__).resolve().parent.parent   # project root
DATA_DIR  = ROOT_DIR / "guardian" / "data"
CACHE_DIR = ROOT_DIR / "cache"
OUT_DIR   = ROOT_DIR / "out"
FIXTURES_DIR = ROOT_DIR / "fixtures"

# OSV / KEV endpoints
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL       = "https://api.osv.dev/v1/vulns/{id}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# Canary package (planted fixture for self-test)
CANARY_PACKAGE = "canary-old-cve"
CANARY_VERSION = "0.0.1"
