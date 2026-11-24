"""The LangGraph Orchestrator for Guardian.
Sequences deterministic eyes, quarantined Reader, LLM judges, code Verifier, and hands."""
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from guardian import config
from guardian.llm import client
from guardian.nodes import (
    after_scout,
    hunt_canary_node,
    hunt_changes_node,
    hunt_files_node,
    hunt_join_node,
    hunt_kev_node,
    hunt_osv_node,
    hunt_static_node,
    mapper_node,
    scout_node,
)
from guardian.nodes_llm import (
    analyst_node,
    human_approval_node,
    reader_node,
    remediator_node,
    reporter_node,
    rules_node,
    skeptic_node,
    validator_node,
    verifier_analyst_node,
)
from guardian.state import State
from guardian.tracing import rd_of
from guardian.validator import approval_for
from guardian.ledger import Ledger


def route_after_scout(state):
    return after_scout(state)


def route_after_rules(state):
    rd = rd_of(state)
    run = config.load_run(rd)
    if not run.get("ai", True) or not client.ai_available():
        return "remediator"
    return "analyst"


def route_after_verifier(state):
    if state.get("pending") and state.get("repairs", 0) < config.MAX_REPAIRS:
        return "analyst"
    rd = rd_of(state)
    run = config.load_run(rd)
    if not run.get("ai", True) or not client.ai_available():
        return "remediator"
    findings = config.read_json(rd / "findings.json", [])
    has_high = any(f.get("risk") in ("high", "critical") for f in findings)
    return "skeptic" if has_high else "remediator"


def route_after_remediator(state):
    rd = rd_of(state)
    run = config.load_run(rd)
    return "human_approval" if run.get("remediate") else "reporter"


def route_after_approval(state):
    rd = rd_of(state)
    led = Ledger(rd / "ledger.json")
    findings = config.read_json(rd / "findings.json", [])
    vulns = [f for f in findings if f.get("type") == "vulnerability"]
    if vulns and approval_for(led, vulns[0]["id"]):
        return "validator"
    return "reporter"


def build_graph():
    builder = StateGraph(State)

    # 1. Deterministic EYES
    builder.add_node("scout", scout_node)
    builder.add_node("mapper", mapper_node)
    builder.add_node("hunt_osv", hunt_osv_node)
    builder.add_node("hunt_kev", hunt_kev_node)
    builder.add_node("hunt_static", hunt_static_node)
    builder.add_node("hunt_files", hunt_files_node)
    builder.add_node("hunt_canary", hunt_canary_node)
    builder.add_node("hunt_changes", hunt_changes_node)
    builder.add_node("hunt_join", hunt_join_node)

    # 2. Quarantined READER + deterministic RULES
    builder.add_node("reader", reader_node)
    builder.add_node("rules", rules_node)

    # 3. JUDGES: Analyst, Verifier, Skeptic
    builder.add_node("analyst", analyst_node)
    builder.add_node("verifier_analyst", verifier_analyst_node)
    builder.add_node("skeptic", skeptic_node)

    # 4. HANDS: Remediator, Approval, Validator, Reporter
    builder.add_node("remediator", remediator_node)
    builder.add_node("human_approval", human_approval_node)
    builder.add_node("validator", validator_node)
    builder.add_node("reporter", reporter_node)

    # Wiring edges
    builder.add_edge(START, "scout")
    builder.add_conditional_edges("scout", route_after_scout, {"mapper": "mapper", "reporter": "reporter"})

    # Parallel fan-out
    for h in ("hunt_osv", "hunt_kev", "hunt_static", "hunt_files", "hunt_canary", "hunt_changes"):
        builder.add_edge("mapper", h)
        builder.add_edge(h, "hunt_join")

    builder.add_edge("hunt_join", "reader")
    builder.add_edge("reader", "rules")

    builder.add_conditional_edges("rules", route_after_rules, {"analyst": "analyst", "remediator": "remediator"})
    builder.add_edge("analyst", "verifier_analyst")
    builder.add_conditional_edges("verifier_analyst", route_after_verifier,
                                  {"analyst": "analyst", "skeptic": "skeptic", "remediator": "remediator"})
    builder.add_edge("skeptic", "remediator")

    builder.add_conditional_edges("remediator", route_after_remediator,
                                  {"human_approval": "human_approval", "reporter": "reporter"})
    builder.add_conditional_edges("human_approval", route_after_approval,
                                  {"validator": "validator", "reporter": "reporter"})
    builder.add_edge("validator", "reporter")
    builder.add_edge("reporter", END)

    return builder


def run_pipeline(run_id, resume=False):
    """Run or resume the Guardian pipeline for a given run directory."""
    rd = config.run_dir(run_id)
    builder = build_graph()
    db_path = rd / "checkpoint.sqlite"
    with SqliteSaver.from_conn_string(str(db_path)) as checkpointer:
        graph = builder.compile(checkpointer=checkpointer)
        config_thread = {"configurable": {"thread_id": run_id}}
        if resume:
            return graph.invoke(None, config_thread)
        state_init = {
            "run_id": run_id,
            "ledger_path": str(rd / "ledger.json"),
            "status": "running",
            "budgets": config.BUDGETS,
            "errors": [],
            "repairs": 0,
        }
        return graph.invoke(state_init, config_thread)
