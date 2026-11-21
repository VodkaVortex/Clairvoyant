import re, os, sys, subprocess
from collections import defaultdict

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
os.chdir(root)

# handlers_locks.tsv: file, line, handler, kind, lock-expr
hlock = [l.rstrip('\n').split('\t') for l in open(os.path.join(os.environ['TMPDIR'],'handlers_locks.tsv'))]

# cache file contents
cache = {}
def get(f):
    if f not in cache:
        try: cache[f] = open(f, errors='replace').read()
        except: cache[f] = None
    return cache[f]

plain_kinds = {'spin_lock','spin_lock_bh','spin_lock_nosync'}
rows = []
for f,l,h,kind,lock in hlock:
    if kind not in plain_kinds: continue
    src = get(f)
    if src is None: continue
    lines = src.split('\n')
    # find the variable base: e.g. pl->lock -> pl; hw_priv->hwlock -> hw_priv
    m = re.match(r'([A-Za-z_][A-Za-z_0-9]*)\s*(?:->|\.)', lock)
    base = m.group(1) if m else lock
    # count plain spin_lock on this lock expr in file
    lockesc = re.escape(lock)
    pats = {
      'plain': re.compile(r'(?<![_\w])spin_lock\s*\(\s*&?\s*'+lockesc+r'\s*\)'),
      'bh': re.compile(r'(?<![_\w])spin_lock_bh\s*\(\s*&?\s*'+lockesc+r'\s*\)'),
      'irq': re.compile(r'(?<![_\w])spin_lock_irq\s*\(\s*&?\s*'+lockesc+r'\s*\)'),
      'irqsave': re.compile(r'(?<![_\w])spin_lock_irqsave\s*\(\s*&?\s*'+lockesc+r'\s*,'),
    }
    counts = {}
    for k,p in pats.items():
        counts[k] = len(p.findall(src))
    rows.append((f,int(l),h,lock,counts['plain'],counts['bh'],counts['irq'],counts['irqsave']))

with open(os.path.join(os.environ['TMPDIR'],'cross.tsv'),'w') as out:
    for r in sorted(rows, key=lambda r:(-r[4], r[0])):
        out.write('\t'.join(map(str,r))+'\n')
print("rows:", len(rows))
