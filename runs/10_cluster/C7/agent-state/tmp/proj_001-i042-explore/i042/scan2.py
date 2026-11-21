import re, os, subprocess

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

files = sh(f"cd {ROOT} && /usr/bin/rg -l 'tasklet_init\\(|tasklet_setup\\(' --type c drivers/net drivers/staging net/ arch/um 2>/dev/null").split()
napi_files = sh(f"cd {ROOT} && /usr/bin/rg -l 'netif_napi_add' --type c drivers/net drivers/staging net/ 2>/dev/null").split()
allfiles = sorted(set(files + napi_files))

FUNC_RE = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?(?:const\s+)?[A-Za-z_][A-Za-z0-9_]*[\s\*]+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*$')

def get_funcs(src):
    funcs = {}
    lines = src.split('\n')
    i = 0; n = len(lines)
    while i < n:
        m = FUNC_RE.match(lines[i])
        if m:
            name = m.group(1)
            j = i
            while j < n and j < i + 6 and '{' not in lines[j]:
                if ';' in lines[j]:
                    break
                j += 1
            if j < n and '{' in lines[j]:
                depth = 0; started = False; k = j
                while k < n and k < j + 3000:
                    for ch in lines[k]:
                        if ch == '{': depth += 1; started = True
                        elif ch == '}':
                            depth -= 1
                            if started and depth == 0:
                                funcs[name] = (i+1, '\n'.join(lines[i:k+1]), k+1)
                                break
                    if name in funcs: break
                    k += 1
        i += 1
    return funcs

LOCK_RE = re.compile(r'spin_(lock|unlock|lock_irqsave|unlock_irqrestore|lock_irq|unlock_irq|lock_bh|unlock_bh|trylock|trylock_bh)\s*\(\s*([^;]+?)\s*[,)]')

# function call graph edges (approximate, within same file)
CALL_RE_TMPL = r'\b%s\s*\('

results = []
for f in allfiles:
    try:
        src = open(os.path.join(ROOT, f), errors='replace').read()
    except Exception:
        continue
    cb_names = set()
    for m in re.finditer(r'tasklet_init\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,', src):
        cb_names.add(m.group(1))
    for m in re.finditer(r'tasklet_setup\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', src):
        cb_names.add(m.group(1))
    napi_names = set()
    for m in re.finditer(r'netif_napi_add(?:_weight|_dev)?\s*\(\s*[^,]+,\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,', src):
        napi_names.add(m.group(1))
    if not cb_names and not napi_names:
        continue
    funcs = get_funcs(src)
    # build callers of each function
    callers = {}
    for name, (ln, body, end) in funcs.items():
        for callee in funcs:
            if callee == name: continue
            if re.search(r'\b' + re.escape(callee) + r'\s*\(', body):
                callers.setdefault(callee, set()).add(name)
    # propagate: softirq-reachable functions
    soft_reach = set(cb_names) | set(napi_names)
    changed = True
    while changed:
        changed = False
        for name, (ln, body, end) in funcs.items():
            if name in soft_reach: continue
            # is name called by a soft-reach func?
            if name in callers:
                for c in callers[name]:
                    if c in soft_reach and name not in soft_reach:
                        soft_reach.add(name); changed = True
                        break
    lockmap = {}
    for name, (ln, body, end) in funcs.items():
        for m in LOCK_RE.finditer(body):
            flav = m.group(1); expr = m.group(2).strip()
            line = ln + body[:m.start()].count('\n')
            kind = 'soft' if name in soft_reach else 'other'
            lockmap.setdefault(expr, []).append((name, line, flav, kind))
    for expr, uses in lockmap.items():
        soft_locks = [u for u in uses if u[3] == 'soft' and u[2] in ('lock','lock_irq','lock_irqsave','lock_bh')]
        if not soft_locks:
            continue
        plain_other = [u for u in uses if u[3] == 'other' and u[2] in ('lock','trylock')]
        if plain_other:
            has_bh = any(u[2].endswith('_bh') for u in uses)
            # process context check: which callers
            results.append((f, expr, soft_locks, plain_other, has_bh))

with open(os.path.join(os.environ.get('TMPDIR','/tmp'), "i042", "scan2_out.txt"), "w") as fh:
    for f, expr, soft, plain_other, has_bh in results:
        fh.write(f"FILE {f} LOCK {expr} has_bh={has_bh}\n")
        for s in soft[:8]:
            fh.write(f"   SOFT {s[0]}:{s[1]} spin_{s[2]}\n")
        for p in plain_other[:12]:
            fh.write(f"   OTHER {p[0]}:{p[1]} spin_{p[2]}\n")
print("results:", len(results))
