import os, re, json, collections
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"
T = os.environ.get("TMPDIR","/tmp")
data = json.load(open(os.path.join(T, "softirq_cbs.json")))
funcdefs = json.load(open(os.path.join(T, "funcdefs.json")))

cache = {}
def get_lines(rel):
    if rel not in cache:
        cache[rel] = open(os.path.join(ROOT, rel), errors="replace").read().splitlines()
    return cache[rel]

def func_ranges(fname):
    return funcdefs.get(fname, [])

def body(rel, s, e):
    return "\n".join(get_lines(rel)[s-1:e])

lock_re = re.compile(r'spin_lock\s*\(\s*([^()]*?)\s*\)|spin_lock_bh\s*\(\s*([^()]*?)\s*\)|spin_lock_irq\s*\(\s*([^()]*?)\s*\)|spin_lock_irqsave\s*\(\s*([^()]*?)\s*,', re.S)

softirq_funcs = {}
for name, regs in data["tasklet_cbs"].items():
    softirq_funcs[name] = ("tasklet", regs)
for name, regs in data["napi_polls"].items():
    if name not in softirq_funcs:
        softirq_funcs[name] = ("napi", regs)

SKIP = set("if for while switch return sizeof spin_lock spin_unlock spin_lock_bh spin_unlock_bh spin_lock_irq spin_unlock_irq spin_lock_irqsave spin_unlock_irqrestore spin_unlock local_bh_disable local_bh_enable dev_kfree_skb kmalloc kzalloc kfree kcalloc memcpy memset printk dev_err dev_info dev_dbg WARN_ON WARN_ON_ONCE BUG_ON container_of list_for_each_entry_safe list_for_each_entry test_and_set_bit test_and_clear_bit atomic_inc atomic_dec __func__ mod_timer tasklet_schedule tasklet_hi_schedule napi_schedule napi_complete spin_trylock spin_is_locked netif_wake_queue netif_stop_queue __netif_tx_lock __netif_tx_unlock synchronize_irq enable_irq disable_irq do_gettimeofday".split())

def find_locks(rel, s, e):
    b = body(rel, s, e)
    out = []
    for m in lock_re.finditer(b):
        variant = "plain" if m.group(1) is not None else ("bh" if m.group(2) is not None else ("irq" if m.group(3) is not None else "irqsave"))
        expr = next(g for g in m.groups() if g is not None)
        expr = re.sub(r'\s+', ' ', expr).strip()
        out.append((variant, expr))
    return out

results = []  # (lockexpr, variant, softirq_fn, kind, rel, line_no_approx)

def find_line_of(rel, s, expr, variant):
    # find approximate line number within body
    lines = get_lines(rel)
    pat = f"spin_lock" + ("" if variant=="plain" else "_"+variant)
    for i in range(s-1, min(len(lines), s+400)):
        if pat in lines[i] and expr.split()[-1] in lines[i] if expr else False:
            return i+1
    return s

for name, (kind, regs) in softirq_funcs.items():
    for rel, s, e in func_ranges(name):
        for variant, expr in find_locks(rel, s, e):
            results.append((expr, variant, name, kind, rel, s))
        # callees one level deep, same file
        b = body(rel, s, e)
        for cm in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', b):
            callee = cm.group(1)
            if callee in SKIP or callee in softirq_funcs: continue
            for crel, cs, ce in func_ranges(callee):
                if os.path.basename(crel) == os.path.basename(rel) and (cs, ce) != (s, e):
                    for variant, expr in find_locks(crel, cs, ce):
                        results.append((expr, variant, f"{name}->{callee}", kind, crel, cs))

agg = collections.defaultdict(lambda: collections.defaultdict(set))
for expr, variant, fn, kind, rel, s in results:
    agg[expr][variant].add(f"{fn}@{rel}:{s}")

print(f"total softirq-side lock acquisitions: {len(results)}; distinct lock exprs: {len(agg)}")
# Focus: locks that appear with plain variant on softirq side OR any variant — we need all
for expr in sorted(agg.keys()):
    variants = agg[expr]
    line = f"LOCK {expr}: "
    for v, fns in variants.items():
        line += f"[{v}: {len(fns)}] "
    print(line)
    for v, fns in variants.items():
        for f in sorted(fns)[:6]:
            print(f"    {v}: {f}")
