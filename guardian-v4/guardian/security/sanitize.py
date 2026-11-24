"""Guardrails 7 and 8: name whitelist, secret redaction, and what an LLM may see."""
import re

# npm names are lowercase; scoped names use @ and /. Max 214 chars.
NAME_RE = re.compile(r"^@?[a-z0-9][a-z0-9._~-]*(/[a-z0-9][a-z0-9._~-]*)?$")
VER_RE = re.compile(r"^[0-9][0-9A-Za-z.+-]{0,63}$")

SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)(\s*[=:]\s*)\S+"),
]

# Only these evidence fields are ever shown to an LLM (no raw untrusted text).
VIEW_KEYS = {"name", "version", "cves", "vuln_id", "severity", "cvss_est", "fixed", "epss",
             "cve", "result", "similar_to", "distance", "change_type", "old", "new", "rule",
             "file", "line", "ok", "path", "install_script", "dev", "direct", "score",
             "new_vulns", "major_jump", "source", "decision"}
NAME_KEYS = {"name", "similar_to"}


def safe_name(name):
    return isinstance(name, str) and len(name) <= 214 and bool(NAME_RE.match(name))


def safe_version(v):
    return isinstance(v, str) and bool(VER_RE.match(v))


def redact(text):
    """Replace anything that looks like a secret with [REDACTED]."""
    text = str(text)
    for pat in SECRET_PATTERNS[:-1]:
        text = pat.sub("[REDACTED]", text)
    return SECRET_PATTERNS[-1].sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", text)


def clean_untrusted(text, limit=4096):
    """Strip control characters, redact secrets, cut to 4 KB. Used before the Reader."""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", str(text))
    return redact(text)[:limit]


def _val(key, value):
    if isinstance(value, bool) or isinstance(value, (int, float)) or value is None:
        return value
    if isinstance(value, list):
        return [_val(key, v) for v in value[:20]]
    if isinstance(value, dict):
        return {k: _val(k, v) for k, v in value.items() if k in VIEW_KEYS}
    s = str(value)
    if key in NAME_KEYS:
        return s if safe_name(s) else "[invalid-name]"
    return s[:80] if re.match(r"^[\w@./:+ ~^<>=*#>-]{0,80}$", s) else "[omitted]"


def llm_view(evidence):
    """The safe, narrow view of one evidence item that an LLM may read."""
    data = {k: _val(k, v) for k, v in evidence["data"].items() if k in VIEW_KEYS}
    return {"id": evidence["id"], "kind": evidence["kind"], "data": data}
