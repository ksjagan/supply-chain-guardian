"""GitHub workflow checks by plain line scanning (no YAML library, nothing is run)."""
import re

from guardian.security.sanitize import redact

USES = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^\s'\"#]+)")
RUN = re.compile(r"^(\s*)(-\s+)?run:\s*(.*)$")
SHA = re.compile(r"^[0-9a-f]{40}$")
EXPR = re.compile(r"\$\{\{\s*github\.(event\.|head_ref)")


def scan(text):
    issues, runs, actions = [], [], []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line, n = lines[i], i + 1
        code = line.split("#", 1)[0]
        m = USES.match(code)
        if m:
            ref = m.group(1)
            if not ref.startswith(("./", "docker://")):
                actions.append(ref)
                if "@" not in ref or not SHA.match(ref.split("@", 1)[1]):
                    issues.append({"rule": "workflow_unpinned_action", "line": n, "text": ref[:120]})
        if re.search(r"\bpull_request_target\b", code):
            issues.append({"rule": "workflow_pull_request_target", "line": n,
                           "text": "uses pull_request_target"})
        if re.search(r"permissions:\s*write-all", code):
            issues.append({"rule": "workflow_write_all", "line": n, "text": "permissions: write-all"})
        r = RUN.match(code)
        if r:
            indent = len(r.group(1)) + (len(r.group(2)) if r.group(2) else 0)
            first = r.group(3).strip()
            body = []
            if first in ("|", ">", "|-", ">-", "|+", ">+"):
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or
                                          len(lines[j]) - len(lines[j].lstrip()) > indent):
                    body.append(lines[j].strip())
                    j += 1
                i = j - 1
            else:
                body = [first]
            block = "\n".join(body)
            runs.append({"line": n, "text": redact(block)[:400]})
            if EXPR.search(block):
                issues.append({"rule": "workflow_expression_injection", "line": n,
                               "text": redact(block)[:200]})
        i += 1
    return {"issues": issues, "run_lines": runs, "actions": actions}
