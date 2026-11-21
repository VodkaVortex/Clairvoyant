import os, re, sys
from collections import defaultdict

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s10"

# 1. collect softirq-side callback bodies: tasklets + NAPI poll functions
tasklet_re = re.compile(r'\btasklet_init\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
decl_tasklet_re = re.compile(r'DECLARE_TASKLET(?:_OLD)?\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
napi_add_re = re.compile(r'netif_napi_add(?:_weight|_tx_weight|_dev)?\s*\([^;]*?([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')

cb_bodies = {}   # fname -> (file, startline)
def find_func_body(text, fname):
    # find definition like: ret? fname(args)\n{
    pat = re.compile(r'^[ \t]*[A-Za-z_][A-Za-z0-9_ \t\*]*\b' + re.escape(fname) + r'\s*\([^;{]*\)\s*\n?\s*\{', re.M)
    for m in pat.finditer(text):
        start = m.start()
        # find matching closing brace
        depth = 0; i = text.index('{', m.start())
        while i < len(text):
            if text[i] == '{': depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    return (text[start:i+1], text[:start].count('\n')+1)
            i += 1
    return None, None

files = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in ('.git',)]
    for fn in filenames:
        if fn.endswith(('.c', '.h', '.cc')):
            files.append(os.path.join(dirpath, fn))
files.sort()

lockcall_re = re.compile(r'\b(spin_lock(?:_irqsave|_irq|_bh)?|spin_trylock(?:_bh)?|local_bh_disable)\s*\(\s*&?\s*([^;()]+?)\s*[,)]')

records = []
n_tasklets = 0; n_napi = 0
for f in files:
    try:
        text = open(f, encoding='utf-8', errors='replace').read()
    except Exception:
        continue
    rel = os.path.relpath(f, ROOT)
    cbs = []
    for m in tasklet_re.finditer(text):
        cbs.append(('tasklet', m.group(1), text[:m.start()].count('\n')+1))
    for m in decl_tasklet_re.finditer(text):
        cbs.append(('tasklet', m.group(1), text[:m.start()].count('\n')+1))
    for m in napi_add_re.finditer(text):
        cbs.append(('napi_poll', m.group(2), text[:m.start()].count('\n')+1))
    for kind, fname, regline in cbs:
        body, defline = find_func_body(text, fname)
        if body is None:
            continue
        if kind == 'tasklet': n_tasklets += 1
        else: n_napi += 1
        locks = lockcall_re.findall(body)
        if locks:
            records.append((kind, fname, rel, defline, regline, locks))

print("tasklet callbacks with bodies:", n_tasklets, " napi polls:", n_napi)
print("=== softirq-side callbacks that take locks ===")
for kind, fname, rel, defline, regline, locks in records:
    lk = "; ".join(sorted(set(f"{op}({arg.strip()})" for op,arg in locks)))
    print(f"{kind:10s} {fname:40s} {rel}:{defline}  [{lk}]")
