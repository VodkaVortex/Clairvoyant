#!/usr/bin/env python3
import os, re, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C5/public/snapshots/s02"
EXCLUDE_DIRS = {'tools', 'samples', 'Documentation', 'scripts'}

call_re = re.compile(r'\b(get_user|__get_user|unsafe_get_user|copy_from_user|__copy_from_user|strndup_user|strncpy_from_user|memdup_user|vmemdup_user)\s*\(')

def iter_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel = os.path.relpath(dirpath, ROOT)
        if rel.split(os.sep)[0] in EXCLUDE_DIRS:
            dirnames[:] = []
            continue
        for fn in filenames:
            if fn.endswith('.c'):
                yield os.path.join(dirpath, fn)

hits = []
nfiles = 0
for path in iter_files():
    nfiles += 1
    try:
        src = open(path, errors='replace').read()
    except OSError:
        continue
    if 'get_user' not in src and 'copy_from_user' not in src and 'memdup_user' not in src and 'strndup_user' not in src:
        continue
    lines = src.split('\n')
    # merge physical lines into logical statements starting at fetch lines
    events = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if call_re.search(line) and not line.strip().startswith(('*', '/*', '//')) and '/*' not in line:
            # gather full statement up to ~8 lines until ; or ) balance
            stmt = line
            j = i
            while ';' not in stmt and j - i < 8 and j + 1 < n:
                j += 1
                stmt += ' ' + lines[j].strip()
            kind = call_re.search(stmt).group(1)
            events.append((i, kind, stmt))
            i = j + 1
        else:
            i += 1
    # find same file fetches that share the SAME field-path token (e.g. &up->len)
    # extract argument text of each call
    def arg_of(stmt):
        m = call_re.search(stmt)
        rest = stmt[m.end():]
        depth = 0; out = ''
        for ch in rest:
            if ch == '(': depth += 1
            elif ch == ')':
                if depth == 0: break
                depth -= 1
            elif ch == ',' and depth == 0: break
            out += ch
        return out.strip()
    def tok_of(arg):
        # normalize: strip casts, & and parens
        a = arg
        a = re.sub(r'\(\s*[^()]*?__user\s*\*?\s*\)\s*', '', a)
        a = re.sub(r'^\(\s*[^()]+\s*\)\s*', '', a)
        a = a.strip()
        if a.startswith('&'): a = a[1:]
        a = a.strip()
        if a.startswith('(') and a.endswith(')'): a = a[1:-1].strip()
        m = re.match(r'^([A-Za-z_]\w*(?:\.\w+|\[[^\]]*\]|\->\w+)*)', a)
        return m.group(1) if m else None
    evs = []
    for (ln, kind, stmt) in events:
        arg = arg_of(stmt)
        tok = tok_of(arg)
        evs.append((ln, kind, tok, arg, stmt.strip()[:160]))
    # same token twice within 50 lines, must contain a deref of user pointer (-> or [) 
    bytok = collections.defaultdict(list)
    for ev in evs:
        if ev[2] and ('->' in ev[2] or '.' in ev[2]):
            bytok[ev[2]].append(ev)
    for tok, es in bytok.items():
        for a in range(len(es)):
            for b in range(a+1, len(es)):
                if es[b][0] - es[a][0] <= 50:
                    hits.append({'file': os.path.relpath(path, ROOT), 'tok': tok,
                                 'la': es[a][0]+1, 'lb': es[b][0]+1,
                                 'ka': es[a][1], 'kb': es[b][1],
                                 'arga': es[a][3][:100], 'argb': es[b][3][:100]})
print("files", nfiles, "field-path repeat hits", len(hits))
agg = collections.defaultdict(list)
for h in hits: agg[h['file']].append(h)
for f, hs in sorted(agg.items(), key=lambda kv: -len(kv[1]))[:45]:
    toks = collections.Counter(h['tok'] for h in hs)
    print(f"{len(hs):3d} {f} tokens={dict(toks.most_common(8))}")
json.dump(hits, open(os.path.join(os.environ['TMPDIR'],'field_hits.json'),'w'), indent=1)
