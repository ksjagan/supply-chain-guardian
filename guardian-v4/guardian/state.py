"""The small shared graph state: only ids, paths, status, budgets and errors (spec section 5).
Everything bigger lives in files inside out/<run-id>/ so the checkpoint stays tiny."""
import operator
from typing import Annotated, TypedDict


class State(TypedDict, total=False):
    run_id: str
    ledger_path: str
    status: str                                  # running / COMPLETE / INCOMPLETE / UNTRUSTED
    budgets: dict
    errors: Annotated[list, operator.add]        # parallel nodes can all add errors
    repairs: int
    pending: list
    fix_errors: dict
