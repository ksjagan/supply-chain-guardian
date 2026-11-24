"""The ONLY file that talks to an LLM. Temperature 0, schema-locked JSON, one retry showing
the error, cache by hash, token/cost tracking and budgets. No tools, no network for the model."""
import hashlib
import json
import os
import threading
import time
from pathlib import Path

from guardian import config
from guardian.llm import schemas

_LOCK = threading.Lock()
BACKEND = None          # tests set this to a function(model, system, user) -> reply text


def set_backend(fn):
    global BACKEND
    BACKEND = fn


def ai_available():
    return BACKEND is not None or bool(os.environ.get("ANTHROPIC_API_KEY"))


def _price(model):
    key = "haiku" if "haiku" in model else "sonnet"
    return config.PRICES[key]


def _cache_file():
    return config.CACHE_DIR / "llm_cache.json"


def _real_call(model, system, user):
    """One Anthropic call. Returns (text, tokens_in, tokens_out)."""
    import anthropic
    client = anthropic.Anthropic()
    kwargs = dict(model=model, max_tokens=2000, system=system,
                  messages=[{"role": "user", "content": user}])
    try:
        r = client.messages.create(temperature=0, **kwargs)
    except anthropic.BadRequestError as e:
        if "temperature" not in str(e).lower():
            raise
        r = client.messages.create(**kwargs)      # some models fix their own temperature
    text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
    return text, r.usage.input_tokens, r.usage.output_tokens


def _approx_tokens(s):
    return max(1, len(s) // 4)


def _usage_rows(rd):
    p = Path(rd) / "llm_usage.jsonl"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _log(rd, row):
    with _LOCK:
        with open(Path(rd) / "llm_usage.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")


def over_budget(rd, agent):
    rows = _usage_rows(rd)
    used_agent = sum(r["tokens_in"] + r["tokens_out"] for r in rows if r["agent"] == agent)
    used_all = sum(r["tokens_in"] + r["tokens_out"] for r in rows)
    return used_agent >= config.BUDGETS.get(agent, 6000) or used_all >= config.RUN_TOKEN_BUDGET


def call_json(rd, agent, model, system, payload, schema):
    """Returns (parsed_or_None, info). info has 'error' text when the result is unusable."""
    user = json.dumps(payload, sort_keys=True)
    if not ai_available():
        return None, {"error": "AI layer off: no API key"}
    if over_budget(rd, agent):
        return None, {"error": f"{agent} token budget used up"}
    key = hashlib.sha256((model + system + user).encode()).hexdigest()
    with _LOCK:
        cache = config.read_json(_cache_file(), {})
    if key in cache:
        _log(rd, {"agent": agent, "model": model, "tokens_in": 0, "tokens_out": 0, "cost": 0.0,
                  "cache_hit": True, "retries": 0, "ts": time.time()})
        return cache[key], {"error": ""}
    retries, prompt, last_err = 0, user, ""
    for attempt in range(2):
        try:
            text, tin, tout = (BACKEND(model, system, prompt), None, None) if BACKEND \
                else _real_call(model, system, prompt)
        except Exception as e:
            return None, {"error": f"LLM call failed: {type(e).__name__}: {str(e)[:120]}"}
        if tin is None:
            tin, tout = _approx_tokens(system + prompt), _approx_tokens(text)
        pin, pout = _price(model)
        _log(rd, {"agent": agent, "model": model, "tokens_in": tin, "tokens_out": tout,
                  "cost": round((tin * pin + tout * pout) / 1e6, 6), "cache_hit": False,
                  "retries": retries, "ts": time.time()})
        try:
            parsed = schemas.extract_json(text)
            last_err = schemas.validate(parsed, schema) or ""
        except ValueError as e:
            parsed, last_err = None, f"reply was not valid JSON ({e})"
        if not last_err:
            with _LOCK:
                cache = config.read_json(_cache_file(), {})
                cache[key] = parsed
                config.write_json(_cache_file(), cache)
            return parsed, {"error": ""}
        retries += 1
        prompt = user + "\n\nYour previous reply was rejected: " + last_err + \
            ". Reply again with valid JSON only."
    return None, {"error": "schema check failed twice: " + last_err}
