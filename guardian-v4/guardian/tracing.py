"""Observability: @traced writes one span per agent to trace.jsonl and a live timeline."""
import functools
import json
import threading
import time
from pathlib import Path

from guardian import config
from langgraph.errors import GraphBubbleUp

_LOCK = threading.Lock()
LLM_AGENTS = {"reader", "analyst", "skeptic", "remediator"}


def rd_of(state):
    return Path(state["ledger_path"]).parent


def _append(path, rec):
    with _LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def breaker_event(rd, what, detail=""):
    """Record a circuit-breaker event (shown on the Run health page)."""
    _append(Path(rd) / "trace.jsonl", {"agent": "breaker", "event": what, "detail": detail,
                                       "start": time.time(), "status": "breaker"})


def _usage(rd):
    p = Path(rd) / "llm_usage.jsonl"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _set_status(rd, agent, state, **kw):
    with _LOCK:
        p = Path(rd) / "run_status.json"
        cur = config.read_json(p, {"agents": {}, "order": []})
        if agent not in cur["agents"]:
            cur["order"].append(agent)
        cur["agents"].setdefault(agent, {}).update({"state": state, **kw})
        config.write_json(p, cur)


def elapsed_total(rd):
    run = config.load_run(rd)
    return time.time() - run.get("created_ts", time.time())


def traced(agent):
    """Wrap a graph node: time it, count tokens, catch errors so the run degrades, not dies."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(state):
            rd = rd_of(state)
            if agent in LLM_AGENTS and elapsed_total(rd) > config.TOTAL_TIMEOUT_S:
                breaker_event(rd, "total_timeout", f"{agent} skipped: 10 minute run budget used")
                return {"errors": [f"{agent}: skipped, total time budget used"]}
            start = time.time()
            before = len(_usage(rd))
            _set_status(rd, agent, "running", start=start)
            status, err, out = "ok", None, {}
            try:
                out = fn(state) or {}
            except GraphBubbleUp:       # a human-approval pause is not an error: pass it up
                _append(Path(rd) / "trace.jsonl", {
                    "agent": agent, "start": start, "end": time.time(), "duration": 0,
                    "status": "waiting", "tokens": 0, "cost": 0, "cache_hits": 0, "llm_calls": 0,
                    "retries": 0, "error": None})
                _set_status(rd, agent, "waiting for human approval")
                raise
            except Exception as e:  # degrade, never crash the whole run
                status, err = "error", f"{type(e).__name__}: {e}"
                out = {"errors": [f"{agent}: {err}"]}
            end = time.time()
            if end - start > config.AGENT_TIMEOUT_S:
                breaker_event(rd, "agent_timeout", f"{agent} took {end - start:.0f}s (limit 120s)")
            use = _usage(rd)[before:]
            span = {"agent": agent, "start": start, "end": end, "duration": round(end - start, 3),
                    "status": status, "tokens": sum(u["tokens_in"] + u["tokens_out"] for u in use),
                    "cost": round(sum(u["cost"] for u in use), 6),
                    "cache_hits": sum(1 for u in use if u["cache_hit"]),
                    "llm_calls": len(use), "retries": sum(u.get("retries", 0) for u in use),
                    "error": err}
            _append(Path(rd) / "trace.jsonl", span)
            _set_status(rd, agent, status, duration=span["duration"], tokens=span["tokens"])
            return out
        return wrapper
    return deco


def read_trace(rd):
    p = Path(rd) / "trace.jsonl"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def summarize(rd):
    """Per-agent totals versus budget (run_summary.json)."""
    agents = {}
    for s in read_trace(rd):
        if s["agent"] == "breaker":
            continue
        a = agents.setdefault(s["agent"], {"seconds": 0, "tokens": 0, "cost": 0.0, "calls": 0,
                                           "cache_hits": 0})
        a["seconds"] = round(a["seconds"] + s["duration"], 3)
        a["tokens"] += s["tokens"]
        a["cost"] = round(a["cost"] + s["cost"], 6)
        a["calls"] += s["llm_calls"]
        a["cache_hits"] += s["cache_hits"]
    for name, a in agents.items():
        a["budget"] = config.BUDGETS.get(name)
    tot_calls = sum(a["calls"] for a in agents.values())
    return {"agents": agents,
            "total_tokens": sum(a["tokens"] for a in agents.values()),
            "token_budget": config.RUN_TOKEN_BUDGET,
            "total_cost_usd": round(sum(a["cost"] for a in agents.values()), 6),
            "cache_hit_rate": round(sum(a["cache_hits"] for a in agents.values()) / tot_calls, 3)
            if tot_calls else None,
            "breaker_events": [s for s in read_trace(rd) if s["agent"] == "breaker"]}
