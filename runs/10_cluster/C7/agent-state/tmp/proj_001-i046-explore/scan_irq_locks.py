#!/usr/bin/env python3
"""Find hardirq handler bodies containing plain spin_lock and cross-index
with plain spin_lock sites in the same file (potential non-irq holders)."""
import os, re, sys, json, subprocess

ROOT = "."
results = []

# 1) collect request_irq / devm_request_irq registrations: file, handler name
irq_re = re.compile(r'(?:devm_)?request(?:_threaded)?_irq\s*\(')
handler_re = re.compile(r'(?:devm_)?request(?:_threaded)?_irq\s*\(\s*([^,]+)\s*,\s*(?:IRQF_\w+\s*\|\s*)*([A-Za-z_][A-Za-z0-9_]*)\s*,')

def find_files():
    out = subprocess.check_output(["grep", "-rl", "--include=*.c",
        "-e", "request_irq(", "-e", "request_threaded_irq(", "-e", "devm_request_irq(", "-e", "devm_request_threaded_irq(", "."]).decode().split()
    return out

files = find_files()
handler_sites = {}  # handler -> list of (file, line)
for f in files:
    try:
        lines = open(f, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        continue
    for i, l in enumerate(lines, 1):
        if "request_irq" in l or "request_threaded_irq" in l:
            # try to find handler arg (2nd or 3rd arg)
            m = re.search(r'(?:devm_)?request(?:_threaded)?_irq\s*\(([^;]{0,300})', l + " " + (lines[i] if i < len(lines) else ""))
            if m:
                args = m.group(1)
                parts = args.split(",")
                if len(parts) >= 2:
                    h = parts[1].strip()
                    h = re.sub(r'[^A-Za-z0-9_]', '', h)
                    if h and h not in ("NULL",):
                        handler_sites.setdefault(h, []).append((f, i))

# 2) for each handler defined as static function in some file, extract body, check spin_lock(
def_sig_re = re.compile(r'^static\s+(?:irqreturn_t\s+)?\w[\w\s\*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')

plain_lock_re = re.compile(r'\bspin_lock\s*\(\s*&?')
plain_unlock_re = re.compile(r'\bspin_unlock\s*\(\s*&?')

report = []
for h, sites in handler_sites.items():
    # find definition
    deffile = None
    for (f, ln) in sites:
        # search definition in same file
        try:
            src = open(f, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        m = re.search(r'^[A-Za-z_][\w\s\*]*?\b' + re.escape(h) + r'\s*\(', src, re.M)
        if m:
            deffile = f
            break
    if not deffile:
        continue
    src = open(deffile, encoding="utf-8", errors="replace").read()
    lines = src.splitlines()
    # find def line index
    defidx = None
    sig = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?(?:irqreturn_t\s+)?[A-Za-z_][\w\s\*]*?\b' + re.escape(h) + r'\s*\(')
    for i, l in enumerate(lines):
        if sig.match(l):
            defidx = i
            break
    if defidx is None:
        continue
    # extract body by brace matching
    depth = 0; started = False; body = []
    j = defidx
    while j < len(lines) and j < defidx + 400:
        l = lines[j]
        body.append((j+1, l))
        depth += l.count("{") - l.count("}")
        if "{" in l:
            started = True
        if started and depth <= 0:
            break
        j += 1
    # find spin_lock( calls in handler body (plain)
    plain_in_handler = []
    for (ln, l) in body:
        if plain_lock_re.search(l):
            # skip if it's actually spin_lock_irq etc handled by regex \b
            if re.search(r'\bspin_lock(?:_irqsave|_irq|_bh)\b', l):
                continue
            # extract lock expression
            lm = re.search(r'spin_lock\s*\(\s*([^;]+?)\s*\)', l)
            lockexpr = lm.group(1) if lm else l.strip()
            plain_in_handler.append((ln, lockexpr))
    if not plain_in_handler:
        continue
    # cross-index: plain spin_lock of same lock expr elsewhere in file
    for (hln, lockexpr) in plain_in_handler:
        core = lockexpr
        # match by containing key token e.g. priv->lock, np->lock
        m = re.search(r'([A-Za-z_][\w]*(?:->\w+)+|&?\w+)->?$', lockexpr) or re.search(r'(\w+(?:->\w+)+)', lockexpr)
        key = None
        mm = re.search(r'([A-Za-z_]\w*(?:->[A-Za-z_]\w*)+)', lockexpr)
        if mm:
            key = mm.group(1)
        else:
            mm = re.search(r'&\s*([A-Za-z_]\w*)', lockexpr)
            if mm:
                key = mm.group(1)
        if not key:
            continue
        others = []
        for i, l in enumerate(lines, 1):
            if re.search(r'\bspin_lock\s*\(', l) and key in l:
                if re.search(r'\bspin_lock(?:_irqsave|_irq|_bh)\b', l):
                    continue
                others.append(i)
        report.append({
            "handler": h, "file": deffile,
            "handler_lock_line": hln, "lock": lockexpr, "key": key,
            "register_sites": [f"{f}:{ln}" for (f, ln) in sites],
            "plain_sites_same_file": others,
        })

json.dump(report, open(os.environ.get("OUT", os.path.join(os.environ["TMPDIR"], "hardirq_report.json")), "w"), indent=1)
print(f"handlers={len(handler_sites)} candidate_pairs={len(report)}")
