"""The Evidence Ledger. Only plain code writes here. LLM output is never evidence."""
import json
from pathlib import Path


class Ledger:
    def __init__(self, path):
        self.path = Path(path)
        self.items = []
        if self.path.exists():
            self.items = json.loads(self.path.read_text(encoding="utf-8"))

    def add(self, kind, source, data):
        """Add one fact. Returns its ID like E-001. Call save() when done."""
        eid = "E-%03d" % (len(self.items) + 1)
        self.items.append({"id": eid, "kind": kind, "source": source, "data": data})
        return eid

    def get(self, eid):
        for it in self.items:
            if it["id"] == eid:
                return it
        return None

    def exists(self, eid):
        return self.get(eid) is not None

    def by_kind(self, *kinds):
        return [it for it in self.items if it["kind"] in kinds]

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.items, indent=2), encoding="utf-8")


def open_ledger(path):
    return Ledger(path)
