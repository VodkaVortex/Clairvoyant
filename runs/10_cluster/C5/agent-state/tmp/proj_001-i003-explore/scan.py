#!/usr/bin/env python3
"""Scan s01 for double-fetch candidates: functions with >1 user-fetch calls
where the same user pointer is fetched more than once."""
import os, re, subprocess, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C5/public/snapshots/s01"
# Only attack-surface dirs (exclude tools, samples, Documentation, selftests)
SCAN_DIRS = ["kernel", "fs", "net", "ipc", "security", "mm", "block", "io_uring",
             "drivers", "virt", "lib", "crypto", "init", "usr"]
# skip tools & samples entirely

FETCH_RE = re.compile(r'\b(get_user|__get_user|copy_from_user|__copy_from_user|'
                      r'strncpy_from_user|strnlen_user|peek_user|__peek_user|'
                      r'copy_struct_from_user|load_user)\s*\(')
GUP_RE = re.compile(r'\b(get_user_pages|pin_user_pages|get_user_pages_fast|pin_user_pages_fast|get_user_pages_unlocked|get_user_pages_remote)\b')
ARG_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*(?:->[\w.]+)*(?:\[[^\]]*\])?)\s*[,\)]')

def files():
    for d in SCAN_DIRS:
        top = os.path.join(ROOT, d)
        for dirpath, dirnames, filenames in os.walk(top):
            # skip test dirs
            dirnames[:] = [x for x in dirnames if x not in ("selftests", "testing", "test_drivers", "kunit")]
            for f in filenames:
                if f.endswith(".c"):
                    yield os.path.join(dirpath, f)

def line_of(text, pos):
    return text.count("\n", 0, pos) + 1

results = []
nfiles = 0
for path in files():
    rel = os.path.relpath(path, ROOT)
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    nfiles += 1
    # split into functions at top-level braces: approximate by scanning
    # find function starts: line beginning non-space word( at col 0
    fstarts = [m for m in re.finditer(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\([^;{}]*\)\s*\n?\{', text, re.M)]
    for i, m in enumerate(fstarts):
        start = m.start()
        # find matching close brace
        depth = 0
        j = text.find("{", m.start())
        k = j
        while k < len(text):
            c = text[k]
            if c == "{": depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0: break
            k += 1
        body = text[start:k+1]
        name = re.match(r'.*?([A-Za-z_][A-Za-z0-9_]*)\s*\(', m.group(0))
        fname = name.group(1) if name else "?"
        # collect fetch calls
        calls = []
        for fm in FETCH_RE.finditer(body):
            # capture args up to 200 chars
            p = fm.end()
            args = body[p:p+200]
            # balance parens
            depth2 = 1; idx = 0
            while idx < len(args) and depth2 > 0:
                if args[idx] == "(": depth2 += 1
                elif args[idx] == ")": depth2 -= 1
                idx += 1
            argstr = args[:idx-1] if depth2 == 0 else args[:idx]
            # last arg is the user pointer (get_user(x, ptr)) or first (copy_from_user)
            mm = ARG_RE.findall(argstr)
            if fm.group(1).endswith("get_user"):
                ptr = mm[-1] if mm else None
            else:
                ptr = mm[0] if mm else None
            calls.append((line_of(body, fm.start()) + line_of(text, start) - 1, fm.group(1), ptr, argstr[:120]))
        if not calls:
            continue
        # dedupe: same pointer token fetched by user-fetch >= 2 times
        from collections import defaultdict
        byptr = defaultdict(list)
        for (ln, fn, ptr, argstr) in calls:
            if ptr:
                byptr[ptr].append((ln, fn, argstr))
        dup = {p: v for p, v in byptr.items() if len(v) >= 2 and len(p) >= 2 and p not in ("sizeof",)}
        if dup and len(dup) >= 1:
            # heuristic score: prefer pointer-ish tokens (optval, arg, uarg, ubuf, ...)
            score = 0
            for p, v in dup.items():
                score += len(v) * 2
                if re.search(r'optval|uarg|argp|ubuf|user|from|ptr|hdr|head|desc|ctl|buf|base|data|it', p, re.I):
                    score += 3
            results.append({
                "file": rel, "func": fname,
                "func_start": line_of(text, start), "func_end": line_of(text, k),
                "dups": [{"ptr": p, "fetches": v} for p, v in dup.items()],
                "score": score,
            })

results.sort(key=lambda r: -r["score"])
out = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C5/agent-state/tmp/proj_001-i003-explore/doublefetch_scan.json"
json.dump({"nfiles": nfiles, "ncandidates": len(results), "results": results}, open(out, "w"), indent=1)
print(f"files scanned: {nfiles}; candidate functions: {len(results)}")
for r in results[:45]:
    ptrs = ", ".join(f"{d['ptr']}x{len(d['fetches'])}" for d in r["dups"])
    print(f"{r['score']:>4} {r['file']}:{r['func_start']} {r['func']}() [{ptrs}]")
