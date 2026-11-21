import os, re, json
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s10"
TMP = os.environ.get('TMPDIR','/tmp')
handlers = json.load(open(TMP+'/handlers.json'))
rows = []
for f in handlers:
    # load file text
    path = os.path.join(ROOT, f['file'])
    txt = open(path, errors='ignore').read()
    for h in f['handlers']:
        for lk in h['plain_locks']:
            # count plain sites of this lock in file
            plain_re = re.compile(r'\bspin_lock\s*\(\s*&?\s*' + re.escape(lk) + r'\s*\)')
            irq_re = re.compile(r'\bspin_lock_(?:irqsave|irq|bh)(?:_nest_lock)?\s*\(\s*&?\s*' + re.escape(lk) + r'\s*\)')
            nplain = len(plain_re.findall(txt))
            nsafe = len(irq_re.findall(txt))
            # local_bh_disable in file
            bh = txt.count('local_bh_disable')
            rows.append((f['file'], h['handler'], h['reg_line'], lk, nplain, nsafe, bh))
rows.sort(key=lambda r: (-r[4], r[0]))
for r in rows[:60]:
    print(f"{r[0]}: handler={r[1]} reg={r[2]} lock={r[3]} plain_sites={r[4]} safe_sites={r[5]} local_bh_disable={r[6]}")
print("total rows:", len(rows))
