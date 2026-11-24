"""Dockerfile checks. Plain text parsing only; the file is never built or run."""
import re

from guardian.security.sanitize import redact

SECRET_KEY = re.compile(r"(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)")
CURL_SH = re.compile(r"(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh)\b")
ADD_HTTP = re.compile(r"(?i)^ADD\s+(--\S+\s+)*https?://")


def _logical_lines(text):
    """Join lines that end with a backslash. Yields (start_line_number, text)."""
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if line.lstrip().startswith("#") and not buf:
            continue
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        if buf.strip():
            yield start, buf.strip()
        buf = ""
    if buf.strip():
        yield start, buf.strip()


def _image_problem(ref):
    if "@sha256:" in ref or ref == "scratch" or "$" in ref:
        return None
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last:
        return "docker_untagged_image"
    return "docker_latest_tag" if last.endswith(":latest") else None


def scan(text):
    issues, runs, images = [], [], []
    user, last_from, stages = None, 1, set()
    for n, line in _logical_lines(text):
        parts = line.split(None, 1)
        instr, rest = parts[0].upper(), (parts[1] if len(parts) > 1 else "")
        if instr == "FROM":
            toks = [t for t in rest.split() if not t.startswith("--")]
            ref = toks[0] if toks else ""
            last_from = n
            images.append(ref)
            if ref not in stages and _image_problem(ref):
                issues.append({"rule": _image_problem(ref), "line": n, "text": "FROM " + ref[:120]})
            if len(toks) >= 3 and toks[1].upper() == "AS":
                stages.add(toks[2])
        elif instr == "USER":
            user = rest.split(":")[0].strip()
        elif instr == "RUN":
            runs.append({"line": n, "text": redact(rest)[:400]})
            if CURL_SH.search(rest):
                issues.append({"rule": "docker_curl_pipe_sh", "line": n, "text": redact(rest)[:200]})
        elif instr == "ADD" and ADD_HTTP.match(line):
            issues.append({"rule": "docker_add_remote_url", "line": n, "text": redact(line)[:200]})
        elif instr in ("ENV", "ARG"):
            for key, val in _pairs(rest):
                if SECRET_KEY.search(key) and val and not val.startswith("$"):
                    issues.append({"rule": "docker_secret_in_env", "line": n,
                                   "text": f"{instr} {key[:60]}=[REDACTED]"})
    if images and (user is None or user in ("root", "0")):
        issues.append({"rule": "docker_no_user", "line": last_from, "text": "no non-root USER set"})
    return {"issues": issues, "run_lines": runs, "base_images": images, "user": user or ""}


def _pairs(rest):
    """ENV A=1 B=2  /  ENV A 1  /  ARG A=1  /  ARG A  -> (key, value) pairs."""
    if "=" in rest:
        return [tuple(p.split("=", 1)) for p in rest.split() if "=" in p]
    toks = rest.split(None, 1)
    return [(toks[0], toks[1].strip() if len(toks) > 1 else "")] if toks else []
