#!/usr/bin/env python3
import os, re, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s01"
CALLS = [r"skb_cow_head\s*\(", r"(?<![\w_])skb_cow\s*\(", r"skb_unclone\s*\(", r"skb_share_check\s*\(", r"pskb_expand_head\s*\(", r"skb_linearize\s*\(", r"__skb_linearize\s*\(", r"__pskb_pull_tail\s*\(", r"(?<![\w_])pskb_may_pull\s*\("]

HDR_ACCESSORS = re.compile(
    r"(ip_hdr|ipv6_hdr|tcp_hdr|udp_hdr|icmp_hdr|icmp6_hdr|skb_network_header|skb_mac_header|skb_transport_header|skb_inner_network_header|eth_hdr|ip_eth_hdr)\s*\(\s*(\w+)\s*\)")

CAPTURE_TYPES = [
    r"struct\s+(\w+)\s*\*", r"const\s+struct\s+(\w+)\s*\*", r"unsigned\s+char\s*\*", r"u?int?8_t\s*\*", r"__be16\s*\*", r"char\s*\*", r"void\s*\*", r"(\w+)\s*\*"
]
CAP_RE = re.compile(r"^\s*(?:const\s+)?(?:struct\s+)?(\w+)?\s*\*?\s*(\w+)\s*=\s*(.+);")

def func_spans(lines):
    # crude: find lines starting at col 0 with '(' and match braces
    spans = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if re.match(r"^[A-Za-z_].*\(.*\)?\s*$", line) and "=" not in line.split("(")[0] and not line.lstrip().startswith(("if","for","while","switch","return","}")):
            # candidate function start
            depth = 0
            started = False
            j = i
            while j < n and j < i + 2000:
                for ch in lines[j]:
                    if ch == '{':
                        depth += 1; started = True
                    elif ch == '}':
                        depth -= 1
                        if started and depth == 0:
                            spans.append((i, j))
                            break
                if spans and spans[-1] == (i, j):
                    break
                j += 1
            if spans and spans[-1][0] == i:
                i = spans[-1][1] + 1
                continue
        i += 1
    return spans

results = []
for dirpath, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in (".git",)]
    for f in files:
        if not f.endswith((".c", ".h")):
            continue
        p = os.path.join(dirpath, f)
        rel = os.path.relpath(p, ROOT)
        if not (rel.startswith("net/") or rel.startswith("drivers/")):
            continue
        try:
            text = open(p, errors="ignore").read()
        except Exception:
            continue
        lines = text.split("\n")
        has_call = False
        for c in CALLS:
            if re.search(c, text):
                has_call = True
                break
        if not has_call:
            continue
        for (fs, fe) in func_spans(lines):
            body = lines[fs:fe+1]
            bodytext = "\n".join(body)
            call_lines = []
            for c in CALLS:
                for m in re.finditer(c, bodytext):
                    ln = bodytext[:m.start()].count("\n")
                    call_lines.append(ln)
            if not call_lines:
                continue
            # find captures of pointers derived from skb data
            captures = []  # (offset, varname)
            for m in CAP_RE.finditer(bodytext):
                var = m.group(2)
                rhs = m.group(3).strip()
                if var in ("skb",) : continue
                # pointer derived from skb data?
                if re.search(r"(skb|pkt|_skb|head)\b", rhs) and re.search(r"(->data|_hdr\(|header|data|head)", rhs) and "*" in m.group(0):
                    captures.append((bodytext[:m.start()].count("\n"), var, m.group(0).strip()))
            for cl in sorted(set(call_lines)):
                for (capln, var, captext) in captures:
                    if capln >= cl:  # capture must be before call
                        continue
                    # find uses after call
                    uses = []
                    for m in re.finditer(r"\b%s\b" % re.escape(var), bodytext[sum(len(l)+1 for l in body[:cl]):]):
                        off = sum(len(l)+1 for l in body[:cl]) + m.start()
                        ln = bodytext[:off].count("\n")
                        # skip the capture itself and simple re-assignment var = ...
                        line_str = body[ln] if ln < len(body) else ""
                        if re.match(r"\s*(const\s+)?(struct\s+)?\w+\s*\*?\s*%s\s*=" % re.escape(var), line_str):
                            continue
                        uses.append(ln)
                    if uses:
                        results.append({
                            "file": rel, "func_start": fs+1, "call_line": fs+1+cl,
                            "capture_line": fs+1+capln, "var": var, "capture": captext,
                            "first_use_after": fs+1+uses[0], "use_count": len(uses)
                        })
seen = set()
out = []
for r in results:
    k = (r["file"], r["call_line"], r["var"])
    if k in seen: continue
    seen.add(k)
    out.append(r)
out.sort(key=lambda r: (r["file"], r["call_line"]))
json.dump(out, open(sys.argv[1] if len(sys.argv)>1 else "/tmp/out.json","w"), indent=1)
print(f"total candidate chains: {len(out)}")
