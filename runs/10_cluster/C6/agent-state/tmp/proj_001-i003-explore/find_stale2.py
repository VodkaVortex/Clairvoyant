#!/usr/bin/env python3
import os, re, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s01"
CALLS = [
    r"skb_cow_head\s*\(", r"(?<![\w_])skb_cow\s*\(", r"skb_unclone\s*\(", r"pskb_expand_head\s*\(",
    r"(?<![\w_])skb_linearize\s*\(", r"__skb_linearize\s*\(", r"__pskb_pull_tail\s*\(",
    r"(?<![\w_])pskb_may_pull\s*\(", r"(?<![\w_])pskb_pull\s*\(",
]

CALL_RE = re.compile("|".join(CALLS))

def function_spans(lines):
    spans = []
    i, n = 0, len(lines)
    header_re = re.compile(r"^[A-Za-z_][\w\s\*,\(\)\[\]]*\(.*$")
    while i < n:
        line = lines[i]
        if header_re.match(line) and not line.startswith(("if","for","while","switch","return")):
            depth = 0
            started = False
            j = i
            end = None
            while j < n and j < i + 3000:
                for ch in lines[j]:
                    if ch == '{':
                        depth += 1; started = True
                    elif ch == '}':
                        depth -= 1
                        if started and depth == 0:
                            end = j
                            break
                if end is not None:
                    break
                j += 1
            if end is not None:
                spans.append((i, end))
                i = end + 1
                continue
        i += 1
    return spans

results = []
for dirpath, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in (".git",)]
    for f in files:
        if not f.endswith(".c"):
            continue
        p = os.path.join(dirpath, f)
        rel = os.path.relpath(p, ROOT)
        if not (rel.startswith("net/") or rel.startswith("drivers/")):
            continue
        try:
            lines = open(p, errors="ignore").read().split("\n")
        except Exception:
            continue
        for (fs, fe) in function_spans(lines):
            body = lines[fs:fe+1]
            call_idxs = [k for k, l in enumerate(body) if CALL_RE.search(l)]
            if not call_idxs:
                continue
            # capture pointer vars before first call: `type *var = <expr involving skb-ish name>`;
            cap_re = re.compile(r"^\s*(?:const\s+)?(?:struct\s+)?(?:unsigned\s+)?\w+\s*\*\s*(\w+)\s*=\s*([^;]+);")
            captures = []
            for k, l in enumerate(body):
                m = cap_re.match(l)
                if m:
                    var, rhs = m.group(1), m.group(2)
                    if var == "skb":
                        continue
                    if re.search(r"(hdr|head|data|skb|pkt)", rhs, re.I):
                        captures.append((k, var, l.strip()))
            for cl in call_idxs:
                for (ck, var, capline) in captures:
                    if ck >= cl:
                        continue
                    # uses after the call line
                    use_lines = []
                    reassigned = None
                    for k in range(cl, len(body)):
                        l = body[k]
                        if re.search(r"\b%s\s*=" % re.escape(var), l) and not re.search(r"==", l):
                            # re-assignment (refetch) — mark and stop counting further stale uses
                            reassigned = k
                            break
                        for m in re.finditer(r"\b%s\b" % re.escape(var), l):
                            use_lines.append(k)
                            break
                    # only stale uses strictly between call and reassignment (or end)
                    stale = [u for u in use_lines if reassigned is None or u < reassigned]
                    if stale:
                        results.append({
                            "file": rel, "func": body[0].strip()[:80],
                            "call_line": fs+1+cl, "call": [x.strip() for x in [body[cl]]][0].strip()[:90],
                            "capture_line": fs+1+ck, "var": var, "capture": capline[:90],
                            "first_stale_use": fs+1+stale[0], "stale_uses": len(stale),
                            "refetch_line": (fs+1+reassigned) if reassigned is not None else None,
                        })
# dedupe
seen = set(); out = []
for r in results:
    k = (r["file"], r["call_line"], r["var"])
    if k in seen: continue
    seen.add(k); out.append(r)
json.dump(out, open(sys.argv[1], "w"), indent=1)
print(f"total: {len(out)}")
