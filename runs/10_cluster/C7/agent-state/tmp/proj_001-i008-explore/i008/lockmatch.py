import os, re, sys, json
from collections import defaultdict

ROOTS = ["drivers/net", "drivers/staging", "net"]

def driver_key(path):
    parts = path.split(os.sep)
    if parts[0] == "drivers":
        return os.sep.join(parts[1:4])
    return os.sep.join(parts[:2])

files = defaultdict(list)
for root in ROOTS:
    for dirpath, dirnames, filenames in os.walk(root):
        if "/tools/" in dirpath or "/scripts/" in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(".c") or fn.endswith(".h"):
                p = os.path.join(dirpath, fn)
                files[driver_key(p)].append(p)

call_re = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
plain_lock_re = re.compile(r'(?<![\w.])spin_lock\s*\(\s*([^;()]{1,80}?)\s*\)')
any_lock_re = re.compile(r'(?<![\w.])spin_lock(?:_bh|_irqsave|_irqsave_nested|_irq|_nested)?\s*\(\s*([^;()]{1,80}?)\s*\)')

def extract(path):
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return {}
    src2 = re.sub(r'/\*.*?\*/', ' ', src, flags=re.S)
    src2 = re.sub(r'//[^\n]*', ' ', src2)
    lines = src2.split('\n')
    funcs = {}
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_ \t\*]*?)\s*\**([A-Za-z_][A-Za-z0-9_]*)\s*\(', line)
        if m and not line.lstrip().startswith(('#','}','else','return','if','for','while','switch','case','do')):
            name = m.group(2)
            if name in ('if','for','while','switch','sizeof','return'):
                i += 1; continue
            j = i; started = False
            while j < n and j < i + 6:
                if '{' in lines[j]: started = True; break
                if ';' in lines[j]: break
                j += 1
            if not started: i += 1; continue
            k = j; body = []
            while k < n:
                body.append(lines[k])
                if lines[k].startswith('}'): break
                k += 1
            b = '\n'.join(body)
            if ';' in b:
                funcs[name] = (i+1, b, path)  # body line numbers i+1..k+1
            i = k + 1
        else:
            i += 1
    return funcs

graph = defaultdict(lambda: defaultdict(set))
func_info = defaultdict(dict)  # driver -> name -> list of (file, startline, body)
for dkey, paths in files.items():
    for p in paths:
        for name, (ln, body, fp) in extract(p).items():
            func_info[dkey].setdefault(name, []).append((fp, ln, body))
            callees = set(m.group(1) for m in call_re.finditer(body)) - {name}
            graph[dkey][name] |= callees

def norm(t):
    t = t.strip()
    t = re.sub(r'\s+', '', t)
    if t.startswith('&'): t = t[1:]
    # normalize container var names: keep last field expr e.g. priv->tx_dev.tx_dev_lock -> tx_dev.tx_dev_lock? 
    # keep as-is but also produce field-only variant
    return t

def field_of(t):
    # take the last identifier chain after -> or .
    m = re.findall(r'(?:->|\.)([A-Za-z_][A-Za-z0-9_.]*)$', t)
    return m[0] if m else t

# entries
xmit_entries = []   # (driver, name, file)
assign_re = re.compile(r'\.(?:ndo_start_xmit|tx)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)')
napi_re = re.compile(r'netif_napi_add(?:_rx|_tx|_weight)?\s*\([^;]*?,\s*(?:&)?([A-Za-z_][A-Za-z0-9_]*)\s*,')
work2_re = re.compile(r'(?:INIT_WORK|INIT_DELAYED_WORK|INIT_WORK_ONSTACK|INIT_DEFERRABLE_WORK)\s*\([^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')
for dkey, paths in files.items():
    for p in paths:
        if not p.endswith('.c'): continue
        try: src = open(p, encoding='utf-8', errors='replace').read()
        except Exception: continue
        for m in assign_re.finditer(src):
            xmit_entries.append((dkey, m.group(1), p))
        for m in napi_re.finditer(src):
            xmit_entries.append((dkey, m.group(1), p))
        for m in work2_re.finditer(src):
            pass  # collected separately

work_entries = []
for dkey, paths in files.items():
    for p in paths:
        if not p.endswith('.c'): continue
        try: src = open(p, encoding='utf-8', errors='replace').read()
        except Exception: continue
        for m in work2_re.finditer(src):
            work_entries.append((dkey, m.group(1), p))

# per function: plain locks and any locks with sites
def locks_in(dkey, fname):
    plain, anyl = {}, {}
    for (fp, ln, body) in func_info[dkey].get(fname, []):
        for m in plain_lock_re.finditer(body):
            t = norm(m.group(1))
            plain.setdefault(t, []).append((fp, ln))
        for m in any_lock_re.finditer(body):
            t = norm(m.group(1))
            anyl.setdefault(t, []).append((fp, ln))
    return plain, anyl

def reachable_with_path(dkey, start, maxdepth=14):
    # BFS with parent for path reconstruction
    parent = {start: None}
    q = [start]
    for _ in range(maxdepth):
        nq = []
        for f in q:
            for c in graph[dkey].get(f, ()):
                if c not in parent:
                    parent[c] = f
                    nq.append(c)
        q = nq
        if not q: break
    return parent

def path_to(parent, node):
    p = []
    while node is not None:
        p.append(node)
        node = parent[node]
    return list(reversed(p))

hits = []
for dkey, xname, xfile in xmit_entries:
    if xname not in graph[dkey]: continue
    px = reachable_with_path(dkey, xname)
    # collect lock acquisitions on xmit side
    xlocks = defaultdict(list)  # field -> sites(func, file, line)
    for f in px:
        if f not in func_info[dkey]: continue
        _, anyl = locks_in(dkey, f)
        for t, sites in anyl.items():
            for (fp, ln) in sites:
                xlocks[field_of(t)].append((f, fp, ln, t))
    if not xlocks: continue
    for dkey2, wname, wfile in work_entries:
        if dkey2 != dkey or wname not in graph[dkey]: continue
        pw = reachable_with_path(dkey, wname)
        # find plain spin_lock on work side matching an xmit-side lock field
        for f in pw:
            if f not in func_info[dkey]: continue
            plain, _ = locks_in(dkey, f)
            for t, sites in plain.items():
                fld = field_of(t)
                if fld in xlocks:
                    # require the plain lock target text to be structurally similar to an xmit-side target or vice versa
                    for xs in xlocks[fld]:
                        hits.append({
                            "driver": dkey, "work": wname, "work_file": wfile,
                            "work_lock_func": f, "plain_target": t,
                            "plain_sites": [f"{fp}:{ln}" for (fp, ln) in sites],
                            "work_chain": path_to(pw, f),
                            "xmit": xname, "xmit_file": xfile,
                            "xmit_lock_func": xs[0], "xmit_target": xs[3],
                            "xmit_site": f"{xs[1]}:{xs[2]}",
                            "xmit_chain": path_to(px, xs[0]),
                        })
# dedupe
seen = set(); out = []
for h in hits:
    key = (h["driver"], h["work"], h["plain_target"], h["xmit"], h["xmit_target"], h["work_lock_func"], h["xmit_lock_func"])
    if key in seen: continue
    seen.add(key)
    if "ks7010" in h["driver"]: continue
    out.append(h)
out.sort(key=lambda h: (len(h["work_chain"]) + len(h["xmit_chain"])))
print(json.dumps(out, indent=1))
