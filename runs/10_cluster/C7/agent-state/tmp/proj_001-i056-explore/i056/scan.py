import os, re, sys, json
from collections import defaultdict

ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12'
out = os.path.join(os.environ['TMPDIR'], 'i056')
os.makedirs(out, exist_ok=True)

irq_call = re.compile(r'\b(request_irq|devm_request_irq|request_threaded_irq)\s*\(')
func_def = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
lock_re = re.compile(r'\b(spin_lock|spin_lock_irq|spin_lock_irqsave|spin_lock_bh|spin_trylock|spin_trylock_irq|spin_trylock_bh|spin_lock_nested|spin_lock_irqsave_nested|spin_unlock|spin_unlock_irq|spin_unlock_irqrestore|spin_unlock_bh|spin_trylock_irqsave)\s*\(\s*(?:&\s*)?([^,\s\)]+)')
irqsave_re = re.compile(r'\b(spin_lock_irqsave|spin_lock_irqsave_nested|spin_trylock_irqsave|spin_unlock_irqrestore)\b')
plain_lock_re = re.compile(r'\b(spin_lock|spin_trylock|spin_unlock)\s*\(\s*&?\s*([^,\s\)]+)')

handler_sites = []   # (file, line, handler_name, api)
lock_sites = []      # (file, line, func, lockexpr, kind)
func_of_line = {}    # file -> sorted list of (line, funcname)

files = []
for dirpath, dirs, fns in os.walk(ROOT):
    if '/.git' in dirpath: continue
    for fn in fns:
        if fn.endswith(('.c', '.h')):
            files.append(os.path.join(dirpath, fn))

for f in files:
    rel = os.path.relpath(f, ROOT)
    try:
        with open(f, 'r', errors='replace') as fh:
            lines = fh.readlines()
    except Exception:
        continue
    # function boundary tracking: crude — a line that starts at col 0 with '{' after a func-sig line
    cur = None
    funcstarts = []  # (startline, endline, name)
    sig = None
    for i, ln in enumerate(lines, 1):
        m = func_def.match(ln)
        if m and not ln.lstrip().startswith(('#', '}', 'return', 'else', '.', '->')) and ln.rstrip().endswith(('{', ')')) is False:
            pass
        # detect function start: line at col0 ends with '{'
        if ln.startswith(('{', '}', ')')) or (ln[0] not in ' \t#/*' and not ln.startswith('static inline __attribute')):
            pass
        if not ln.startswith((' ', '\t', '#', '/', '*', '\n')) and (ln.rstrip().endswith('{') or ln.rstrip().endswith(')')) and not re.match(r'^(return|if|for|while|switch|do|else|}\s*while|EXPORT|MODULE|asm|__|union|struct|enum)\b', ln):
            # candidate function signature start
            # find name
            stripped = ln.rstrip()
            if stripped.endswith('{'):
                # match name before '(' on this line
                nm = re.search(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', stripped)
                if nm:
                    cur = (nm.group(1), i)
        if not ln.startswith((' ', '\t', '#', '/', '*')) and ln.rstrip() == '}':
            if cur:
                funcstarts.append((cur[1], i, cur[0]))
                cur = None
    func_of_line[rel] = funcstarts
    # note: signatures spanning multiple lines -> cur stays None; acceptable heuristic
    import bisect
    starts = [s[0] for s in funcstarts]

    def funcof(line):
        idx = bisect.bisect_right(starts, line) - 1
        if idx >= 0 and line <= funcstarts[idx][1]:
            return funcstarts[idx][2]
        return None

    for i, ln in enumerate(lines, 1):
        m = irq_call.search(ln)
        if m:
            # try to find handler name in same or next 6 lines
            text = ''.join(lines[i-1:i+6])
            hm = re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\s*,', text)
            handler_sites.append((rel, i, m.group(1), text[:400]))
        for lm in lock_re.finditer(ln):
            kind = lm.group(1)
            expr = lm.group(2)
            lock_sites.append((rel, i, funcof(i), expr, kind))

with open(os.path.join(out, 'handlers.txt'), 'w') as fh:
    for (rel, i, api, text) in handler_sites:
        fh.write(f"{rel}:{i}:{api}\n")

with open(os.path.join(out, 'locks.txt'), 'w') as fh:
    for (rel, i, fn, expr, kind) in lock_sites:
        fh.write(f"{rel}:{i}:{fn}:{kind}:{expr}\n")

print("handlers", len(handler_sites), "locks", len(lock_sites))
