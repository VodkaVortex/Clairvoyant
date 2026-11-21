import os, re, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s01"
SKIP_DIRS = {".git"}
RELOC = re.compile(r"\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|skb_unclone|skb_share_check)\s*\(")

# 1) index functions containing a relocating call; map function name -> (file, defline)
func_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_ \t\*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

def functions(path):
    """yield (name, start_line, end_line) using brace matching"""
    try:
        with open(path, errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = func_re.match(line)
        if m and not line.lstrip().startswith(("#", "//", "*", "/*")) and "=" not in line.split("(")[0]:
            name = m.group(1)
            # find opening brace within a few lines
            j = i
            depth = 0
            started = False
            while j < n and j < i + 12:
                for ch in lines[j]:
                    if ch == "{":
                        started = True
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                if started and depth <= 0:
                    yield name, i + 1, j + 1
                    i = j
                    break
                j += 1
        i += 1

callees = {}  # func name -> list of (file, defline, endline)
files = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in filenames:
        if fn.endswith((".c", ".h")):
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, ROOT)
            if rel.startswith("tools/") or "/Documentation/" in rel:
                continue
            files.append(p)

filefuncs = {}
for p in files:
    fl = []
    for name, s, e in functions(p):
        fl.append((name, s, e))
    filefuncs[p] = fl
    with open(p, errors="ignore") as f:
        text = f.read()
    lines = text.split("\n")
    for name, s, e in fl:
        body = "\n".join(lines[s-1:e])
        if RELOC.search(body):
            callees.setdefault(name, []).append((os.path.relpath(p, ROOT), s, e))

print("relocating-callee function names:", len(callees))
with open(os.path.join(os.environ["TMPDIR"], "i022", "callees.json"), "w") as f:
    json.dump({k: v for k, v in sorted(callees.items())}, f, indent=0)
