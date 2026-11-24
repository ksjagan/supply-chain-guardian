"""Small shared helpers: severity levels and version comparison."""
import re

SEV = ["low", "medium", "high", "critical"]
LABEL_TO_SEV = {"critical": "critical", "high": "high", "moderate": "medium",
                "medium": "medium", "low": "low"}
# OSV gives a label (not a CVSS number). We map the label to a representative score.
LABEL_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0}
ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "ok": "🟢"}


def sev_index(s):
    return SEV.index(s) if s in SEV else 0


def sev_shift(s, n):
    """Move a severity up (+n) or down (-n), staying inside low..critical."""
    return SEV[max(0, min(3, sev_index(s) + n))]


def parse_ver(v):
    """'4.17.21' -> (4, 17, 21). Pre-release tags are ignored (simple on purpose)."""
    core = re.split(r"[-+]", str(v), maxsplit=1)[0]
    nums = [int(x) for x in re.findall(r"\d+", core)][:3]
    return tuple(nums) + (0,) * (3 - len(nums))


def cmp_ver(a, b):
    pa, pb = parse_ver(a), parse_ver(b)
    return (pa > pb) - (pa < pb)


def major(v):
    return parse_ver(v)[0]


def label(name, version):
    return f"{name}@{version}"
