import os, re, collections
ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03'
T = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore'
rows = [l.rstrip('\n').split('\t') for l in open(T+'/handler_locks.txt')]
bylock = collections.defaultdict(list)
for rel, line, handler, arg in rows:
    arg = arg.replace('&','').strip()
    # fix truncated args like "(info->lock" -> info->lock
    if arg.startswith('('):
        arg = arg[1:]
    bylock[(rel, arg)].append((int(line), handler))

def handler_body_lines(lines, handler):
    pat = re.compile(r'\b' + re.escape(handler) + r'\s*\(')
    out = set()
    for idx, ln in enumerate(lines):
        if pat.search(ln) and ('irqreturn_t' in ln or 'static' in ln or 'irq_handler_t' in ln):
            k = idx
            while k < len(lines) and '{' not in lines[k] and k - idx < 15:
                k += 1
            end = k
            while end < len(lines) and lines[end] != '}' and end - k < 400:
                end += 1
            for x in range(idx, min(end+1, len(lines))):
                out.add(x)
    return out

results = []
for (rel, arg), sites in bylock.items():
    try:
        lines = open(os.path.join(ROOT, rel), errors='ignore').read().splitlines()
    except Exception:
        continue
    hl = set()
    for line, handler in sites:
        hl |= handler_body_lines(lines, handler)
    # plain spin_lock sites with same arg, outside handler
    pat = re.compile(r'(^|[^_a-z])spin_lock\s*\(\s*&?\s*' + re.escape(arg) + r'\s*\)')
    plain_sites = []
    for idx, ln in enumerate(lines):
        if idx in hl: continue
        if pat.search(ln):
            plain_sites.append((idx+1, ln.strip()[:100]))
    # also lock arg in irq-context helper functions? later; record plain count
    results.append((rel, arg, sites, plain_sites))

results.sort(key=lambda r: -len(r[3]))
with open(T+'/cross.tsv','w') as f:
    for rel, arg, sites, plains in results:
        if not plains: continue
        f.write(f"{rel}\t{arg}\thandler_sites={len(sites)}\tplain_outside={len(plains)}\n")
        for line, handler in sites:
            f.write(f"  HANDLER\t{line}\t{handler}\n")
        for pl, ptxt in plains[:25]:
            f.write(f"  PLAIN\t{pl}\t{ptxt}\n")
print("files with plain-outside matches:", sum(1 for r in results if r[3]))
