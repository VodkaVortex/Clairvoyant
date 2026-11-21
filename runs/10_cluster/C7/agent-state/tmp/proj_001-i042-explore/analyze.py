import os, re, json, collections
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"
T = os.environ.get("TMPDIR","/tmp")
data = json.load(open(os.path.join(T, "softirq_cbs.json")))
funcdefs = json.load(open(os.path.join(T, "funcdefs.json")))

# map file -> lines cache
cache = {}
def get_lines(rel):
    if rel not in cache:
        p = os.path.join(ROOT, rel)
        cache[rel] = open(p, errors="replace").read().splitlines()
    return cache[rel]

def func_ranges(fname):
    # fname possibly with prefixes; funcdefs keyed by bare name
    return funcdefs.get(fname, [])

# Direct calls from a callback body (resolving local functions only)
call_re = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')

# Collect softirq-side functions: tasklet cbs + napi polls
softirq_funcs = {}
for name, regs in data["tasklet_cbs"].items():
    softirq_funcs[name] = ("tasklet", regs)
for name, regs in data["napi_polls"].items():
    if name not in softirq_funcs:
        softirq_funcs[name] = ("napi", regs)

# Build body text for a function given (rel, s, e)
def body(rel, s, e):
    return "\n".join(get_lines(rel)[s-1:e])

results = []
seen_cands = set()
# We look for spin_lock acquisitions in softirq bodies and in direct callees (1 level deep)
for name, (kind, regs) in softirq_funcs.items():
    for target_kind, which in [("direct", 0), ("callee", 1)]:
        for rel, ln in [(r[0], r[1]) for r in regs]:
            pass
    # iterate over all definition sites of this function name
    for rel, s, e in func_ranges(name):
        b = body(rel, s, e)
        # find lock names
        for m in re.finditer(r'spin_lock(?:_irqsave|_irq|_bh)?\s*\(\s*([^)]*?)\s*\)', b):
            lockexpr = m.group(1)
            results.append((rel, s, e, name, kind, lockexpr, "direct"))
        # callees one level deep
        for cm in call_re.finditer(b):
            callee = cm.group(1)
            if callee in ("if","for","while","switch","return","sizeof","spin_lock","spin_unlock","spin_lock_irqsave","spin_lock_bh","spin_lock_irq","spin_unlock_bh","spin_unlock_irqrestore","spin_unlock_irq","local_bh_disable","local_bh_enable","dev_kfree_skb","kmalloc","kfree","memcpy","memset","printk","netif_","WARN_ON","BUG_ON","container_of","list_for_each_entry_safe","list_for_each_entry","test_and_set_bit","atomic_","__func__"):
                continue
            for crel, cs, ce in func_ranges(callee):
                if crel == rel or crel.endswith(os.path.basename(rel)):
                    cb = body(crel, cs, ce)
                    for m in re.finditer(r'spin_lock(?:_irqsave|_irq|_bh)?\s*\(\s*([^)]*?)\s*\)', cb):
                        results.append((crel, cs, ce, f"{name}->{callee}", kind, m.group(1), "callee"))

# Aggregate: lockexpr -> softirq functions
agg = collections.defaultdict(set)
loc = {}
for rel, s, e, fn, kind, lockexpr, how in results:
    key = lockexpr
    agg[key].add((fn, kind, how))
    loc.setdefault(key, set()).add(rel)

# Now scan whole tree for same-lock process-context acquisitions
# We match lock expression text (strip types) — crude but first pass
report = []
for lockexpr, uses in sorted(agg.items(), key=lambda kv: -len(kv[1])):
    base = lockexpr
    report.append((lockexpr, len(uses), sorted(uses)[:12]))

for lockexpr, n, uses in report[:200]:
    print(f"=== {lockexpr}  ({n} softirq uses)")
    for u in uses:
        print("   ", u)
