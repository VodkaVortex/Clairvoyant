import os, re, sys, json
from collections import defaultdict

ROOTS = ["drivers/net", "drivers/staging", "net"]

# collect .c files grouped by driver dir (top-level driver identity)
def driver_key(path):
    # e.g. drivers/net/wireless/ath/ath6kl/main.c -> ath/ath6kl
    parts = path.split(os.sep)
    if parts[0] == "drivers":
        return os.sep.join(parts[1:4])  # net/wireless/ath etc -> take 3 levels
    return os.sep.join(parts[:2])

files = {}
for root in ROOTS:
    for dirpath, dirnames, filenames in os.walk(root):
        if "/tools/" in dirpath or "/scripts/" in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(".c") or fn.endswith(".h"):
                p = os.path.join(dirpath, fn)
                files.setdefault(driver_key(p), []).append(p)

funcdef_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?\**([A-Za-z_][A-Za-z0-9_]*)\s*\(', re.M)

def extract(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            src = f.read()
    except Exception:
        return {}, [], []
    # strip comments and strings (rough)
    src2 = re.sub(r'/\*.*?\*/', ' ', src, flags=re.S)
    src2 = re.sub(r'//[^\n]*', ' ', src2)
    lines = src2.split('\n')
    # find function definitions: line starting at col 0 with non-keyword, ending with '{' on same/next lines
    funcs = {}  # name -> (start_line, body)
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_ \t\*]*?)\s*\**([A-Za-z_][A-Za-z0-9_]*)\s*\(', line)
        if m and not line.lstrip().startswith(('#', '}', 'else', 'return', 'if', 'for', 'while', 'switch', 'case', 'do')):
            ret = m.group(1).strip()
            name = m.group(2)
            if name in ('if','for','while','switch','sizeof','return') or ret.endswith('=') :
                i += 1; continue
            # find opening brace within next ~5 lines, at end of a line
            j = i
            depth = 0
            started = False
            sig = ''
            while j < n and j < i + 6:
                sig += lines[j] + '\n'
                if '{' in lines[j]:
                    started = True
                    break
                if ';' in lines[j]:
                    break
                j += 1
            if not started:
                i += 1; continue
            # capture body
            k = j
            body_lines = []
            while k < n:
                body_lines.append(lines[k])
                if lines[k].startswith('}'):
                    break
                k += 1
            body = '\n'.join(body_lines)
            # exclude macros / structs: body must contain ';'
            if ';' in body and depth == 0:
                funcs[name] = (i+1, body)
            i = k + 1
        else:
            i += 1
    return funcs, lines, src2

# Build global per-driver graph
graph = defaultdict(lambda: defaultdict(set))  # driver -> caller -> callees
func_sites = defaultdict(lambda: defaultdict(dict))  # driver -> func -> (file, line)
all_func_files = defaultdict(lambda: defaultdict(list))

call_re = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')

for dkey, paths in files.items():
    for p in paths:
        funcs, lines, src2 = extract(p)
        for name, (ln, body) in funcs.items():
            func_sites[dkey][name][p] = ln
            callees = set()
            for m in call_re.finditer(body):
                cn = m.group(1)
                if cn != name:
                    callees.add(cn)
            graph[dkey][name] |= callees

# find ndo_start_xmit handler names
xmit_handlers = []
assign_re = re.compile(r'\.ndo_start_xmit\s*=\s*([A-Za-z_][A-Za-z0-9_]*)')
for dkey, paths in files.items():
    for p in paths:
        if not p.endswith('.c'): continue
        try:
            src = open(p, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        for m in assign_re.finditer(src):
            xmit_handlers.append((dkey, m.group(1), p))

# work handlers: INIT_WORK(&.., func), INIT_DELAYED_WORK, schedule_work
work_re = re.compile(r'(?:INIT_WORK|INIT_DELAYED_WORK|INIT_WORK_ONSTACK|INIT_DEFERRABLE_WORK|queue_work(?:_system|_unbound|_on|_key)?)\s*\([^;]*?,\s*(?:&?([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)\s*\))')
# simpler: find , func) or , func,
work2_re = re.compile(r'(?:INIT_WORK|INIT_DELAYED_WORK|INIT_WORK_ONSTACK|INIT_DEFERRABLE_WORK)\s*\([^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')
work_handlers = []
for dkey, paths in files.items():
    for p in paths:
        if not p.endswith('.c'): continue
        try:
            src = open(p, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        for m in work2_re.finditer(src):
            work_handlers.append((dkey, m.group(1), p))

# timer handlers for completeness of softirq side? branch1 is xmit; skip.

def reachable(dkey, start, maxdepth=12):
    seen = {start}
    frontier = [start]
    for _ in range(maxdepth):
        newf = []
        for f in frontier:
            for c in graph[dkey].get(f, ()):
                if c not in seen:
                    seen.add(c)
                    newf.append(c)
        frontier = newf
        if not frontier:
            break
    return seen

# for each xmit handler, compute reachable set per driver; find plain spin_lock inside reachable funcs
plain_lock_re = re.compile(r'[^_a-zA-Z0-9]spin_lock\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_>.\-]*)')

results = []
for dkey, h, p in xmit_handlers:
    if h not in graph[dkey]:
        continue
    r = reachable(dkey, h)
    locks = {}
    for f in r:
        for fp, ln in func_sites[dkey].get(f, {}).items():
            try:
                src = open(fp, encoding='utf-8', errors='replace').read().split('\n')
            except Exception:
                continue
            # find plain spin_lock in function body: search file for func signature then scan until closing
            pass
    results.append((dkey, h, p, r))

# Now, for each driver: find work handlers, compute reachable, intersect with xmit reachable set
out = []
for dkey, h, p, r in results:
    for dkey2, w, wp in work_handlers:
        if dkey2 != dkey or w not in graph[dkey]:
            continue
        rw = reachable(dkey, w)
        inter = (r & rw) - {h, w}
        inter = {f for f in inter if f in func_sites[dkey]}
        if inter:
            out.append({"driver": dkey, "xmit": h, "xmit_file": p, "work": w, "work_file": wp, "shared": sorted(inter)})

print(json.dumps(out, indent=1))
