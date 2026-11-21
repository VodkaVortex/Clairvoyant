import os, re, sys, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s08"
OUT  = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i052-explore"
FILES = []
for dp, dn, fn in os.walk(ROOT):
    if '/.git' in dp: continue
    for f in fn:
        if f.endswith(('.c','.h')):
            FILES.append(os.path.join(dp, f))

# lock acquisition patterns
LOCK_RE = re.compile(r'\b(?:spin_lock|spin_lock_nested|spin_lock_bh|spin_lock_irq(?:save(?:_nested)?)?|spin_trylock\w*)\s*\(\s*&?\s*([^,);]+?)\s*(?:,\s*[^,);]+)?\s*\)')
def lock_kind(m):
    return m.group(0).split('(')[0].strip()
def lock_name(expr):
    # base identifier: last '->name' or '.name' component
    e = expr.strip()
    e = re.sub(r'^&', '', e).strip()
    mm = re.search(r'([A-Za-z_][A-Za-z0-9_]*)$', e.split('->')[-1].split('.')[-1]) if ('->' in e or '.' in e) else None
    if mm: return mm.group(1)
    mm2 = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', e)
    return mm2.group(1) if mm2 else e

req_re = re.compile(r'\b(devm_)?request(?:_threaded)?_irq\s*\(')
handler_re = re.compile(r'\b(devm_)?request(?:_threaded)?_irq\s*\(\s*([^,]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
# request_threaded_irq(irq, handler, thread_fn, ...)
threaded_re = re.compile(r'\b(devm_)?request_threaded_irq\s*\(\s*([^,]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')

func_start_re = re.compile(r'^(?:static\s+|inline\s+|extern\s+|const\s+)*[A-Za-z_][A-Za-z0-9_ \*]*\**\s*([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*$|^(?:static\s+)?(?:irqreturn_t\s+)([A-Za-z_][A-Za-z0-9_]*)\s*\(')

regs = []   # (file, line, handler, threaded_thread_fn_or_None)
results = []  # per file: handler -> list of (line, kind, lockexpr)

def parse_file(path):
    try:
        txt = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        return None, []
    lines = txt.split('\n')
    # collect registrations
    file_regs = []
    for i, ln in enumerate(lines):
        if req_re.search(ln):
            m = threaded_re.search(ln)
            if m and m.group(3) and m.group(3) != 'NULL':
                file_regs.append((i+1, m.group(3), m.group(4)))  # handler, thread_fn
            else:
                m2 = handler_re.search(ln)
                if m2:
                    file_regs.append((i+1, m2.group(3), None))
    if not file_regs:
        return txt, []
    # build per-line lock map
    locklines = []  # (lineno, kind, expr)
    for i, ln in enumerate(lines):
        for m in LOCK_RE.finditer(ln):
            locklines.append((i+1, lock_kind(m), m.group(1).strip()))
    # function boundaries: naive — find lines that start a function definition
    funcmap = []  # (lineno, name)
    for i, ln in enumerate(lines):
        fm = re.match(r'^(?:[A-Za-z_][A-Za-z0-9_ \t\*]+?)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', ln)
        if fm and not ln.rstrip().endswith(';') and not ln.strip().startswith('#'):
            funcmap.append((i+1, fm.group(1)))
    def func_at(lineno):
        cur = None
        for sl, nm in funcmap:
            if sl <= lineno: cur = nm
            else: break
        return cur
    out = []
    for (rl, handler, threadfn) in file_regs:
        hl = []
        for (lineno, kind, expr) in locklines:
            if func_at(lineno) == handler:
                hl.append((lineno, kind, expr))
        out.append({'file': os.path.relpath(path, ROOT), 'regline': rl, 'handler': handler, 'thread_fn': threadfn, 'locks': hl})
    return txt, out

all_out = []
for p in FILES:
    txt, regs_f = parse_file(p)
    if regs_f:
        all_out.extend(regs_f)

with open(os.path.join(OUT, 'handler_locks.json'), 'w') as f:
    json.dump(all_out, f, indent=1)

# summary: handlers with at least one PLAIN acquisition, and total acquisitions by lock
plain_kinds = ('spin_lock', 'spin_lock_nested')
summary = []
for r in all_out:
    pl = [(l,k,e) for (l,k,e) in r['locks'] if k in plain_kinds and 'try' not in k]
    if pl:
        summary.append(r)
print("registrations parsed:", len(all_out))
print("handlers with >=1 plain spin_lock acquisition:", len(summary))
# candidate files: handler plain lock that ALSO appears as plain elsewhere in same file by another function
import collections
cand_files = collections.defaultdict(list)
# build file-wide plain lock map
file_plain = collections.defaultdict(lambda: collections.defaultdict(list))  # file -> lockbase -> [(line)]
plain_re = re.compile(r'\bspin_lock(?:_nested)?\s*\(\s*&?\s*([^,);]+?)\s*(?:,\s*[^,);]+)?\s*\)')
for p in FILES:
    try: txt = open(p, encoding='utf-8', errors='replace').read()
    except Exception: continue
    for i, ln in enumerate(txt.split('\n')):
        for m in plain_re.finditer(ln):
            file_plain[os.path.relpath(p, ROOT)][lock_name(m.group(1))].append(i+1)

cross = []
for r in summary:
    f = r['file']
    for (l,k,e) in r['locks']:
        if k in plain_kinds:
            base = lock_name(e)
            others = [x for x in file_plain[f].get(base, []) if True]
            # count plain sites of same base lock in file
            cross.append({'file': f, 'handler': r['handler'], 'regline': r['regline'], 'lock': base, 'hline': l, 'plain_sites_in_file': sorted(set(others)), 'n_plain': len(set(others))})
with open(os.path.join(OUT, 'cross.tsv'), 'w') as f:
    for c in sorted(cross, key=lambda x: -x['n_plain']):
        f.write(f"{c['file']}\t{c['handler']}\t{c['regline']}\t{c['lock']}\t{c['hline']}\t{c['n_plain']}\t{','.join(map(str,c['plain_sites_in_file']))}\n")
print("cross rows:", len(cross))
print("top files by plain-site count:")
seen = collections.Counter()
for c in cross:
    seen[(c['file'], c['lock'])] = c['n_plain']
for (f, lk), n in seen.most_common(40):
    print(f"  {f}\t{lk}\t{n}")
