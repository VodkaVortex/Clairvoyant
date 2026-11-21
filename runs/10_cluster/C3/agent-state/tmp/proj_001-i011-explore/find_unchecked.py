import os, re, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C3/public/snapshots/s03"

# find usages: nla_get_XXX(info->attrs[N]) / nla_data(info->attrs[N]) / nla_len(info->attrs[N])
use_re = re.compile(r'\b(nla_get_[a-zA-Z0-9]+|nla_data|nla_len|nla_memcpy|nla_strlcpy)\s*\(\s*(?:info->attrs|attrs)\[([A-Za-z0-9_]+)\]')
# guard patterns: !info->attrs[N] anywhere, or info->attrs[N] used in an if/ternary
def guards_for(text, array, name):
    g = []
    for m in re.finditer(r'!\s*' + re.escape(array) + r'\[' + re.escape(name) + r'\]', text):
        g.append(m.start())
    # positive guard: if (info->attrs[N]) / info->attrs[N] ?
    for m in re.finditer(r'if\s*\(\s*' + re.escape(array) + r'\[' + re.escape(name) + r'\]\s*[\)&|)]', text):
        g.append(m.start())
    return g

results = []
for dirpath, dirs, files in os.walk(ROOT):
    if '/.git' in dirpath: continue
    for f in files:
        if not f.endswith('.c'): continue
        p = os.path.join(dirpath, f)
        try:
            text = open(p, errors='ignore').read()
        except Exception:
            continue
        if 'info->attrs[' not in text and 'attrs[' not in text: continue
        lines = text.split('\n')
        # build line offset index
        for m in use_re.finditer(text):
            array = 'info->attrs' if 'info->attrs' in m.group(0) else 'attrs'
            name = m.group(2)
            line_no = text.count('\n', 0, m.start()) + 1
            # find enclosing function start: search backwards for a line matching '^static ... (' or any top-level fn def; approximate: previous line starting at col0 with '{' preceded by ')'
            # simple approach: collect all function starts via regex
            gpos = guards_for(text, array, name)
            # guard must appear in same file, anywhere (coarse)
            has_guard = len(gpos) > 0
            # determine if guard is within +/- 120 lines (coarse proximity)
            near = any(abs(text.count('\n',0,gp) - line_no) <= 120 for gp in gpos)
            results.append((os.path.relpath(p, ROOT), line_no, name, m.group(0).strip(), has_guard, near))

for r in results:
    rel, ln, name, use, has_guard, near = r
    if not has_guard or not near:
        print(f"{'NOGUARD' if not has_guard else 'FARGUARD'} {rel}:{ln} {use}")
