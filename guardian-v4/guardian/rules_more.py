"""rules_more.py: package, Dockerfile and workflow findings."""
from guardian.models import sev_shift
from guardian.rules import BUMP_FLAGS, ids

FILE_RISK = {"docker_curl_pipe_sh": "high", "docker_secret_in_env": "high",
             "docker_latest_tag": "medium", "docker_untagged_image": "medium",
             "docker_add_remote_url": "medium", "docker_no_user": "low",
             "workflow_unpinned_action": "medium", "workflow_pull_request_target": "high",
             "workflow_write_all": "high", "workflow_expression_injection": "high"}


def package_findings(b):
    for cid, kinds in sorted(b.idx.items()):
        rf = b.reader_flags(cid)
        inst, typo = kinds.get("install_script", []), kinds.get("typosquat", [])
        anchor = ids(inst) + ids(typo) + b.base_ev(cid) + b.diff_ev.get(cid, [])
        if typo:
            t = typo[0]["data"]
            b.add("typosquat", f"{cid} looks like '{t['similar_to']}' (typosquat)",
                  "critical" if inst else "high", anchor, b.path(cid), cid, b.cflags(cid),
                  ["typosquat AND install script -> critical"] if inst
                  else ["name close to a popular package -> high"],
                  f"edit distance {t['distance']} from {t['similar_to']}")
        if inst:
            name = inst[0]["data"]["name"]
            new = name in b.new_pkgs or not b.ch.get("items")
            risk, notes = ("high", ["install script on a new/unknown package -> high"]) if new \
                else ("low", ["install script on a package that already existed -> low"])
            if new and any(rf.get(k) for k in BUMP_FLAGS):
                risk = sev_shift(risk, 1)
                notes.append("Reader (AI) flagged risky install text -> one level up")
            ft = "new_install_script" if name in b.new_pkgs else "install_script"
            b.add(ft, f"{cid} runs an install script", risk, anchor, b.path(cid), cid,
                  b.cflags(cid, introduced=ft == "new_install_script"), notes)
        for u in kinds.get("unusual_source", []):
            b.add("unusual_source", f"{cid} comes from an unusual source", "medium",
                  [u["id"]] + b.base_ev(cid), b.path(cid), cid, b.cflags(cid),
                  ["not from the npm registry, or no integrity hash"], u["data"]["source"])
        if any((b.flags.get(it["id"]) or {}).get("mentions_instructions_to_ai")
               for k in ("install_script", "typosquat", "unusual_source", "vuln")
               for it in kinds.get(k, [])) or kinds.get("injection_text"):
            b.add("prompt_injection_attempt", f"{cid}: text tries to instruct an AI", "high",
                  anchor, b.path(cid), cid, b.cflags(cid),
                  ["Reader reported instructions to an AI inside untrusted text"])


def file_findings(b):
    for it in b.led.by_kind("dockerfile_issue", "workflow_issue"):
        d = it["data"]
        b.add(it["kind"], f"{d['rule']} in {d['file']}:{d['line']}", FILE_RISK[d["rule"]],
              [it["id"]], [d["file"]], "", {"direct": False, "dev": False, "reach": "unknown"},
              [f"rule {d['rule']} -> {FILE_RISK[d['rule']]}"], d["text"])
