#!/usr/bin/env python3
import os, re, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C5/public/snapshots/s02"
EXCLUDE_DIRS = {'tools', 'samples', 'Documentation', 'scripts'}

call_re = re.compile(r'\b(get_user|__get_user|unsafe_get_user|copy_from_user|__copy_from_user|strndup_user|strncpy_from_user|memdup_user|vmemdup_user)\s*\(')
# pointer-ish first args: a bare identifier or identifier->field / identifier.field / identifier[...] WITHOUT & (destination) and without sizeof
def iter_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel = os.path.relpath(dirpath, ROOT)
        if rel.split(os.sep)[0] in EXCLUDE_DIRS:
            dirnames[:] = []
            continue
        for fn in filenames:
            if fn.endswith('.c'):
                yield os.path.join(dirpath, fn)

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
    events = []
    i = 0; n = len(lines)
    while i < n:
        line = lines[i]
        if call_re.search(line) and not line.strip().startswith(('*','/*','//')) and '/*' not in line:
            stmt = line; j = i
            while ';' not in stmt and j - i < 10 and j + 1 < n:
                j += 1
                stmt += ' ' + lines[j].strip()
            kind = call_re.search(stmt).group(1)
            events.append((i, kind, stmt))
            i = j + 1
        else:
            i += 1
    # pointer source args: starts with (cast)ident or ident; contains __user-ness implicitly via -> or [ ] or bare ptr var
    ptr_events = []
    for (ln, kind, stmt) in events:
        arg = arg_of(stmt)
        if not arg or arg.startswith('&'):  # &x is a destination for get_user
            # but get_user(dest, &src) - we want the SECOND arg for get_user
            pass
        if kind in ('get_user','__get_user','unsafe_get_user'):
            # second arg is the source
            rest = stmt
            m = call_re.search(rest)
            after = rest[m.end():]
            # find second top-level arg
            depth = 0; args = []; cur = ''
            started = False
            for ch in after:
                if ch == '(': depth += 1
                elif ch == ')':
                    if depth == 0: break
                    depth -= 1
                elif ch == ',' and depth == 0:
                    args.append(cur); cur = ''; continue
                cur += ch
            args.append(cur)
            src_arg = args[1].strip() if len(args) >= 2 else None
        else:
            src_arg = arg
        if not src_arg: continue
        a = src_arg
        a = re.sub(r'^\(\s*[^()]*?__user\s*\*?\s*\)\s*', '', a)
        a = re.sub(r'^\(\s*[^()]+\s*\)\s*', '', a)
        a = a.strip()
        if a.startswith('&'): a = a[1:].strip()
        if a.startswith('(') and a.endswith(')'): a = a[1:-1].strip()
        # only pointer-ish: contains -> or [ or is an identifier not a local kernel buffer? heuristics: contains -> or [ ]
        if '->' in a or ('[' in a and ']' in a):
            m2 = re.match(r'^([A-Za-z_]\w*(?:(?:\.\w+)|(?:->\w+)|(?:\[[^\]]*\]))*)', a)
            if m2:
                ptr_events.append((ln, kind, m2.group(1), stmt.strip()[:160], a[:100]))
    # same pointer-path token appearing in >=2 fetch events within 60 lines
    bytok = collections.defaultdict(list)
    for ev in ptr_events:
        bytok[ev[2]].append(ev)
    for tok, es in bytok.items():
        for a in range(len(es)):
            for b in range(a+1, len(es)):
                if es[b][0] - es[a][0] <= 60:
                    hits.append({'file': os.path.relpath(path, ROOT), 'tok': tok,
                                 'la': es[a][0]+1, 'lb': es[b][0]+1,
                                 'ka': es[a][1], 'kb': es[b][1],
                                 'arga': es[a][4][:100], 'argb': es[b][4][:100]})
print("files", nfiles, "pointer-path repeat hits", len(hits))
agg = collections.defaultdict(list)
for h in hits: agg[h['file']].append(h)
for f, hs in sorted(agg.items(), key=lambda kv: -len(kv[1]))[:50]:
    toks = collections.Counter(h['tok'] for h in hs)
    print(f"{len(hs):3d} {f} tokens={dict(toks.most_common(8))}")
json.dump(hits, open(os.path.join(os.environ['TMPDIR'],'ptr_hits.json'),'w'), indent=1)
