import os, re, sys, json, collections
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s10"
SKIP = ("Documentation/", "tools/", "scripts/", "samples/", "usr/")
req_re = re.compile(r'\b(request_irq|devm_request_irq|request_threaded_irq|devm_request_threaded_irq)\s*\(')
name_re = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
lock_re = re.compile(r'\bspin_lock(?:_irqsave|_irq|_bh|_irqsave_nest_lock)?\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)*)')
lock_plain_re = re.compile(r'\bspin_lock\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z0-9_]*)*)')

def lock_expr(raw):
    return re.sub(r'\s+', '', raw)

results = []  # (file, handler, regs)
plainpairs = []
handlers_no_def = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    rel = os.path.relpath(dirpath, ROOT)
    if any(rel.startswith(s) for s in SKIP):
        dirnames[:] = []
        continue
    for fn in filenames:
        if not fn.endswith(('.c', '.h')):
            continue
        path = os.path.join(dirpath, fn)
        try:
            txt = open(path, errors='ignore').read()
        except OSError:
            continue
        regs = req_re.findall(txt)
        if not regs:
            continue
        lines = txt.split('\n')
        # collect registrations with line numbers
        reglines = []
        for i, line in enumerate(lines):
            if req_re.search(line):
                reglines.append((i+1, line))
        results.append((os.path.relpath(path, ROOT), len(regs), reglines))
print("files with irq regs:", len(results))
print("total regs:", sum(r[1] for r in results))
json.dump([(r[0], r[1]) for r in results], open(os.environ.get('TMPDIR','/tmp')+'/irqfiles.json','w'), indent=0)
