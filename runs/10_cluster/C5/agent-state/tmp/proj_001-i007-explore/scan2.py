#!/usr/bin/env python3
import os, re, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C5/public/snapshots/s02"
EXCLUDE_DIRS = {'tools', 'samples', 'Documentation', 'scripts'}

call_re = re.compile(r'\b(get_user|__get_user|unsafe_get_user|copy_from_user|__copy_from_user|strndup_user|strncpy_from_user|memdup_user|vmemdup_user)\s*\(')
# first argument extraction up to comma at depth 0 (handles casts/parens)
arg1_re = re.compile(r'\(([^()]*(?:\([^()]*\)[^()]*)*)')

def first_arg(text):
    m = call_re.search(text)
    if not m: return None, None
    kind = m.group(1)
    rest = text[m.end():]
    am = arg1_re.match(rest)
    if not am: return kind, rest[:60]
    return kind, am.group(1).strip()

def user_ptr_tokens(arg):
    # strip casts like (type __user *)x or (void __user *)x
    arg = re.sub(r'^\(\s*[\w\s\*]+?__user\s*\*\s*\)\s*', '', arg)
    arg = re.sub(r'^\(\s*[\w\s\*]+?\*\s*\)\s*', '', arg)
    # take base token for deref: *(...) -> inner
    if arg.startswith('*'):
        arg = arg[1:].strip()
        if arg.startswith('(') and arg.endswith(')'):
            arg = arg[1:-1]
    # reduce array indexing / member chain to base pointer
    m = re.match(r'^([A-Za-z_]\w*)', arg)
    if m: return m.group(1)
    return None

def iter_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel = os.path.relpath(dirpath, ROOT)
        if rel.split(os.sep)[0] in EXCLUDE_DIRS:
            dirnames[:] = []
            continue
        for fn in filenames:
            if fn.endswith(('.c', '.h')):
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
    # record per-line (kind, argtoken, lineno); join continuation lines roughly
    events = []
    for i, line in enumerate(lines):
        # skip comments crudely
        if '/*' in line or line.strip().startswith('*') or line.strip().startswith('//'):
            continue
        if call_re.search(line):
            kind, arg = first_arg(line)
            if kind:
                tok = user_ptr_tokens(arg or '')
                events.append((i, kind, tok, line.strip()))
    # find repeated same-token fetches within 40 lines
    bytok = collections.defaultdict(list)
    for ev in events:
        if ev[2] and len(ev[2]) > 2:  # ignore tiny tokens
            bytok[ev[2]].append(ev)
    for tok, evs in bytok.items():
        for a in range(len(evs)):
            for b in range(a+1, len(evs)):
                if evs[b][0] - evs[a][0] <= 40:
                    hits.append({
                        'file': os.path.relpath(path, ROOT),
                        'token': tok,
                        'a': evs[a], 'b': evs[b],
                    })
print("files", nfiles, "same-token repeat hits", len(hits))
agg = collections.defaultdict(list)
for h in hits:
    agg[h['file']].append(h)
ranked = sorted(agg.items(), key=lambda kv: -len(kv[1]))
for f, hs in ranked[:70]:
    toks = collections.Counter(h['token'] for h in hs)
    print(f"{len(hs):3d} {f} tokens={dict(toks.most_common(6))}")
json.dump([{'file':h['file'],'token':h['token'],'la':h['a'][0]+1,'lb':h['b'][0]+1,'ka':h['a'][1],'kb':h['b'][1],'sa':h['a'][3][:100],'sb':h['b'][3][:100]} for h in hits], open(os.path.join(os.environ['TMPDIR'],'token_hits.json'),'w'), indent=1)
