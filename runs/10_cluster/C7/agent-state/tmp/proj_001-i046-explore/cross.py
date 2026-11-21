import os, re, collections
ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03'
T = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i046-explore'
rows = [l.rstrip('\n').split('\t') for l in open(T+'/handler_locks.txt')]
# lock arg -> list of (file, line, handler)
bylock = collections.defaultdict(list)
for rel, line, handler, arg in rows:
    bylock[(rel, arg)].append((line, handler))
# for each (file, lockarg): find plain spin_lock sites in the same file outside handlers
spin_re = re.compile(r'spin_lock\s*\(&?([A-Za-z0-9_>\-\[\]\.\(\)]*)')
results = []
for (rel, arg), sites in bylock.items():
    try:
        lines = open(os.path.join(ROOT, rel), errors='ignore').read().splitlines()
    except Exception:
        continue
    handler_lines = set()
    # mark handler body ranges: reuse simple approach - record every line of each handler body
    import re as re2
    for line, handler in sites:
        pat = re2.compile(r'\b' + re2.escape(handler) + r'\s*\(')
        for idx, ln in enumerate(lines):
            if pat.search(ln) and ('irqreturn_t' in ln or 'static' in ln):
                k = idx
                while k < len(lines) and '{' not in lines[k] and k - idx < 12:
                    k += 1
                end = k
                while end < len(lines) and lines[end] != '}':
                    end += 1
                for x in range(idx, min(end+1, len(lines))):
                    handler_lines.add(x)
    # find plain lock sites on same arg outside handler bodies
    argname = arg.replace('&','').strip()
    core = argname.split('->')[-1].split('.')[-1].rstrip(']')
    plain_sites = []
    for idx, ln in enumerate(lines):
        if idx in handler_lines:
            continue
        if re2.search(r'spin_lock\s*\(\s*&?\s*[A-Za-z0-9_\-]+((->|\.)[A-Za-z0-9_]+)*\s*\[?[A-Za-z0-9_]*\]?\s*\)', ln):
            # match same lock expression exactly
            m = re2.search(r'spin_lock\s*\(\s*([^)]+)\)', ln)
            if m and m.group(1).strip() == argname:
                plain_sites.append((idx+1, ln.strip()[:90]))
    if plain_sites:
        results.append((rel, argname, sites, plain_sites))
results.sort(key=lambda r: -len(r[3]))
with open(T+'/cross.tsv','w') as f:
    for rel, argname, sites, plains in results:
        f.write(f"{rel}\t{argname}\thandler_sites={len(sites)}\tplain_outside={len(plains)}\n")
        for line, handler in sites:
            f.write(f"  HANDLER\t{line}\t{handler}\n")
        for pl, ptxt in plains[:20]:
            f.write(f"  PLAIN\t{pl}\t{ptxt}\n")
print(len(results), "files with cross matches")
