import re, os, sys, subprocess

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

# 1. files with tasklet usage or napi_add in drivers/net, drivers/staging, net/, arch/um
files = sh(f"cd {ROOT} && /usr/bin/rg -l 'tasklet_init\\(|tasklet_setup\\(' --type c drivers/net drivers/staging net/ arch/um 2>/dev/null").split()
napi_files = sh(f"cd {ROOT} && /usr/bin/rg -l 'netif_napi_add' --type c drivers/net drivers/staging net/ 2>/dev/null").split()
allfiles = sorted(set(files + napi_files))

def get_funcs(src):
    """Map function name -> (start_line, body) via simple brace matching."""
    funcs = {}
    # match function definitions at column 0
    pat = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*$')
    lines = src.split('\n')
    i = 0
    while i < len(lines):
        m = pat.match(lines[i])
        if m and '{' in lines[i]:
            name = m.group(1)
            # find body end
            depth = 0
            started = False
            j = i
            while j < len(lines) and j < i + 2000:
                for ch in lines[j]:
                    if ch == '{':
                        depth += 1; started = True
                    elif ch == '}':
                        depth -= 1
                        if started and depth == 0:
                            funcs[name] = (i+1, '\n'.join(lines[i:j+1]), j+1)
                            break
                if name in funcs:
                    break
                j += 1
        i += 1
    return funcs

LOCK_RE = re.compile(r'spin_(lock|unlock|lock_irqsave|unlock_irqrestore|lock_irq|unlock_irq|lock_bh|unlock_bh|trylock)\s*\(\s*([^;]+?)\s*[,)]')

def lock_uses(text):
    out = []
    for m in LOCK_RE.finditer(text):
        expr = m.group(2).strip()
        out.append((m.group(1), expr))
    return out

results = []

for f in allfiles:
    path = os.path.join(ROOT, f)
    try:
        src = open(path, errors='replace').read()
    except Exception:
        continue
    # softirq-side callback names
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
    # map: lock expr -> list of (func, line, flavor, kind)
    lockmap = {}
    for name, (ln, body, end) in funcs.items():
        for flav, expr in lock_uses(body):
            # find line number within body
            idx = body.find(f"spin_{flav}")
            line = ln + body[:idx].count('\n') if idx >= 0 else ln
            kind = 'tasklet' if name in cb_names else ('napi' if name in napi_names else 'other')
            lockmap.setdefault(expr, []).append((name, line, flav, kind))
    # find locks used in tasklet/napi callbacks AND with plain spin_lock elsewhere
    for expr, uses in lockmap.items():
        soft = [u for u in uses if u[3] in ('tasklet','napi') and u[2] == 'lock']
        if not soft:
            continue
        plain_other = [u for u in uses if u[3] == 'other' and u[2] == 'lock']
        if plain_other:
            # check for any bh protection on this lock anywhere
            has_bh = any(u[2].endswith('_bh') for u in uses)
            results.append((f, expr, soft, plain_other, has_bh))

for f, expr, soft, plain_other, has_bh in results:
    print(f"FILE {f} LOCK {expr} has_bh={has_bh}")
    for s in soft:
        print(f"   SOFTIRQ {s[3]} {s[0]}:{s[1]} spin_{s[2]}")
    for p in plain_other[:12]:
        print(f"   OTHER {p[0]}:{p[1]} spin_{p[2]}")
