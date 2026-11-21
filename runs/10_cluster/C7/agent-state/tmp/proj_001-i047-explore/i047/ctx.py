#!/usr/bin/env python3
"""Classify each plain lock site's enclosing function by likely context:
  - irq handler (matched against handler set)
  - process (non-irq) if the function is a file_operation/ioctl/open/proc/workqueue
    helper NOT in handler set and NOT reachable from irq (we approximate: any
    function not the irq handler itself; then manual review).
Print a compact shortlist of strong candidates: handler takes lock plainly AND
some non-handler function also takes it plainly."""
import re, os
from collections import defaultdict
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s04"
T = os.environ.get("TMPDIR", "/tmp") + "/i047"

# Build map of file -> {funcname: [start_line, end_line]}
def parse_funcs(path):
    try:
        with open(os.path.join(ROOT, path), errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return {}
    funcs = {}
    funcpat = re.compile(r"^[A-Za-z_][\w\s\*]*?\b(\w+)\s*\(")
    i = 0
    n = len(lines)
    while i < n:
        l = lines[i]
        m = funcpat.match(l)
        if m and not l.strip().startswith("#"):
            name = m.group(1)
            if name in ("if","for","while","switch","return","sizeof","else","do","case","defined","spin_lock","spin_unlock"):
                i += 1; continue
            # find opening brace on this or following lines, until ';'
            j = i
            found = False
            while j < n and j <= i + 15:
                if ";" in lines[j] and "{" not in lines[j]:
                    break
                if "{" in lines[j]:
                    depth = 0
                    k = j
                    started = False
                    # find first '{'
                    col = lines[j].index("{")
                    depth = 1
                    k = j
                    while k < n:
                        startcol = col if k == j else 0
                        for ch in lines[k][startcol:]:
                            if ch == "{": depth += 1
                            elif ch == "}": depth -= 1
                        if depth == 0:
                            funcs[name] = (i+1, k+1)
                            i = k
                            found = True
                            break
                        k += 1
                    break
                j += 1
        i += 1
    return funcs

# gather candidate files
entries = []
with open(T + "/cross.tsv") as f:
    cur = None
    for line in f:
        if not line.startswith(" "):
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 5:
                cur = {"path": parts[0], "lock": parts[1], "hp": parts[2], "op": parts[3], "os": parts[4], "others": [], "handlers": []}
                entries.append(cur)
        elif cur is not None:
            if line.startswith("  HANDLER"):
                cur["handlers"].append(line.strip())
            elif line.startswith("  OTHER"):
                m = re.match(r"\s+OTHER (\d+): (.*)", line)
                if m:
                    cur["others"].append((int(m.group(1)), m.group(2)))

# handler names per file
handlers_by_file = defaultdict(set)
with open(T + "/handlers.txt") as f:
    for line in f:
        p = line.rstrip("\n").split("\t")
        if len(p) == 4:
            handlers_by_file[p[0]].add(p[2])

# Also treat functions that the irq handler calls (same file, 1 level) as irq-context.
# We do a simple transitive closure over same-file static calls.
def build_callgraph(path, funcs):
    try:
        with open(os.path.join(ROOT, path), errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return {}
    calls = defaultdict(set)
    for name, (s, e) in funcs.items():
        for i in range(s-1, e):
            for m in re.finditer(r"\b(\w+)\s*\(", lines[i]):
                callee = m.group(1)
                if callee in funcs and callee != name:
                    calls[name].add(callee)
    return calls

out = []
for e in entries:
    path = e["path"]
    funcs = parse_funcs(path)
    if not funcs:
        continue
    handlers = handlers_by_file.get(path, set())
    # only keep handlers that exist in this file's funcs (definitions)
    hdefs = [h for h in handlers if h in funcs]
    if not hdefs:
        continue
    calls = build_callgraph(path, funcs)
    # transitive closure of functions reachable from handlers
    irq_funcs = set()
    stack = list(hdefs)
    while stack:
        fn = stack.pop()
        if fn in irq_funcs:
            continue
        irq_funcs.add(fn)
        for c in calls.get(fn, ()):
            if c not in irq_funcs:
                stack.append(c)
    # classify OTHER plain sites
    other_ctx = []
    for (ln, content) in e["others"]:
        fn = None
        for name, (s, en) in funcs.items():
            if s <= ln <= en:
                fn = name
                break
        if fn is None:
            continue
        ctx = "irq-reachable" if fn in irq_funcs else "non-irq"
        other_ctx.append((ln, fn, ctx, content))
    non_irq = [o for o in other_ctx if o[2] == "non-irq"]
    if non_irq:
        out.append((path, e["lock"], e["hp"], e["op"], non_irq))

out.sort(key=lambda x: -len(x[4]))
with open(T + "/shortlist.txt", "w") as f:
    for path, lock, hp, op, non_irq in out:
        f.write(f"== {path} lock={lock} {hp} {op}\n")
        for (ln, fn, ctx, content) in non_irq:
            f.write(f"   {ln} {fn}(): {content}\n")
        f.write("\n")
print("shortlisted files:", len(out))
print(open(T + "/shortlist.txt").read()[:5000])
