#!/usr/bin/env python3
"""Second-pass scanner: find same user location fetched twice.

Pattern A: get_user(X, &u->f) ... later get_user(Y, &u->f) for the same field f
           of the same user pointer u.
Pattern B: copy_from_user(localA, u, n) then later get_user(X, &u->f) or another
           copy_from_user from the same base u (with offset) - the classic
           header-then-field double fetch.
Outputs candidates with exact line numbers.
"""
import os, re, sys, json

ROOT = sys.argv[1]
SKIP = {"Documentation", "tools", "samples", "usr", "rust", "scripts", ".git"}

GU = re.compile(r'\b(?:get_user|__get_user|unsafe_get_user)\s*\(\s*([^,]+),\s*([^)]+)\)')
CFU = re.compile(r'\b(?:copy_from_user|__copy_from_user)\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)')
GET_M = re.compile(r'^([A-Za-z_][\w]*(?:\s*->\s*[A-Za-z_][\w]*)*)$')

def files(root):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP]
        for f in fn:
            if f.endswith(".c"):
                yield os.path.join(dp, f)

def line_of(src, idx):
    return src.count("\n", 0, idx) + 1

out = []
for path in files(ROOT):
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    if "get_user" not in src:
        continue
    # Pattern A: same user operand in >=2 get_user calls in the same file.
    # Group by enclosing function via simple brace tracking.
    # find all get_user sites
    sites = []
    for m in GU.finditer(src):
        val, uptr = m.group(1).strip(), m.group(2).strip()
        uptr = uptr.rstrip(")")
        sites.append((m.start(), val, uptr))
    if len(sites) < 2:
        continue
    # map to functions
    funcs = []
    fm = re.finditer(r'^([A-Za-z_][\w]*)\([^;]*?\)\s*\n\{', src, re.M | re.S)
    for f in fm:
        # body end
        start = f.end() - 1
        depth = 0; i = start
        while i < len(src):
            if src[i] == "{": depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0: break
            i += 1
        funcs.append((f.start(), i, f.group(1)))
    for (fs, fe, fname) in funcs:
        fsites = [s for s in sites if fs <= s[0] <= fe]
        # group by user operand
        from collections import defaultdict
        byuptr = defaultdict(list)
        for pos, val, uptr in fsites:
            byuptr[uptr].append((pos, val))
        for uptr, occ in byuptr.items():
            if len(occ) >= 2:
                # same user location fetched >= 2 times; check distinct dest or same field
                # extract field from uptr like &u->f or &u[i]
                mm = re.search(r'->\s*([A-Za-z_]\w*)\s*$', uptr)
                field = mm.group(1) if mm else uptr
                # dedup: only report if the SAME field (identical uptr string)
                lines = [line_of(src, p) for p, _ in occ]
                vals = [v for _, v in occ]
                out.append({
                    "file": os.path.relpath(path, ROOT),
                    "func": fname,
                    "user_operand": uptr,
                    "field": field,
                    "lines": lines,
                    "dests": vals,
                    "pattern": "A:get_user_same_operand",
                })
    # Pattern B: copy_from_user(klocal, u, n) followed by get_user(&u->f)
    cfu_sites = []
    for m in CFU.finditer(src):
        cfu_sites.append((m.start(), m.group(2).strip(), m.group(3).strip()))
    for (fs, fe, fname) in funcs:
        fcfu = [(p, dst, n) for (p, dst, n) in cfu_sites if fs <= p <= fe]
        fgu = [(p, val, up) for (p, val, up) in sites if fs <= p <= fe]
        for (cp, dst, n) in fcfu:
            base = re.sub(r'\s*\+\s*\S+$', '', dst)  # strip "+ off"
            for (gp, val, up) in fgu:
                if gp > cp:
                    upm = re.search(r'&?\s*([A-Za-z_]\w*)', up)
                    upbase = upm.group(1) if upm else up
                    if base == upbase:
                        out.append({
                            "file": os.path.relpath(path, ROOT),
                            "func": fname,
                            "cfu_line": line_of(src, cp),
                            "cfu_src": dst,
                            "cfu_len": n,
                            "gu_line": line_of(src, gp),
                            "gu_operand": up,
                            "pattern": "B:cfu_then_get_user_same_base",
                        })
json.dump(out, open(sys.argv[2], "w"), indent=1)
print("pattern hits:", len(out))
