import re, os, sys, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12"
TDIR = os.path.join(os.environ["TMPDIR"], "i041")

func_def_re = re.compile(r'^(?:[A-Za-z_][A-Za-z0-9_ \t\*]*?)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
lock_call_re = re.compile(r'\bspin_(lock|unlock|lock_bh|unlock_bh|lock_irq|unlock_irq|lock_irqsave|unlock_irqrestore|trylock|lock_bh_nested)\s*\(\s*([^;]*?)\s*\)')

def strip_comments(text):
    # remove comments (keep newlines for line numbers)
    out = []
    i = 0; n = len(text)
    while i < n:
        if text.startswith('/*', i):
            j = text.find('*/', i+2)
            if j < 0: break
            out.append('\n' * text.count('\n', i, j+2)); i = j+2
        elif text.startswith('//', i):
            j = text.find('\n', i)
            if j < 0: j = n
            out.append('\n' * text.count('\n', i, j)); i = j
        elif text[i] == '"':
            j = i+1
            while j < n and text[j] != '"':
                if text[j] == '\\': j += 1
                j += 1
            out.append(text[i:j+1]); i = j+1
        else:
            out.append(text[i]); i += 1
    return ''.join(out)

def line_of(offsets, pos):
    import bisect
    return bisect.bisect_right(offsets, pos)

def parse_functions(text):
    """Return list of (name, start_line, end_line) for top-level functions."""
    lines = text.split('\n')
    funcs = []
    depth = 0
    cur_start = None
    cur_name = None
    i = 0
    # find candidate function headers at depth 0
    pos = 0
    line_starts = [0]
    for k, ch in enumerate(text):
        if ch == '\n': line_starts.append(k+1)
    n = len(text)
    while pos < n:
        if depth == 0:
            m = re.search(r'\n([A-Za-z_][A-Za-z0-9_ \t\*]*?\b([A-Za-z_][A-Za-z0-9_]*)[ \t]*\([^;{)]*\)[ \t]*)\n?\{', text[pos:])
            if not m: break
            hdr_start = pos + m.start(1)
            name = m.group(2)
            brace = pos + m.end() - 1
            # skip if this is a control statement
            if name in ('if','for','while','switch','return','sizeof','else','do'):
                pos = pos + m.end()
                continue
            cur_start = brace
            cur_name = name
            # find matching brace
            d = 0; j = brace
            while j < n:
                c = text[j]
                if c == '{': d += 1
                elif c == '}':
                    d -= 1
                    if d == 0: break
                elif c == '"':
                    j += 1
                    while j < n and text[j] != '"':
                        if text[j]=='\\': j+=1
                        j += 1
                j += 1
            start_line = line_of(line_starts, hdr_start)
            end_line = line_of(line_starts, j)
            funcs.append((name, start_line, end_line))
            pos = j+1
        else:
            break
    return funcs

def get_tasklet_callbacks(text):
    """tasklet_init(&x, callback, ...) / tasklet_setup(&x, cb) — callback name possibly multiline."""
    cbs = set()
    for m in re.finditer(r'tasklet_(?:init|hi_init|setup)\s*\(', text):
        seg = text[m.end():m.end()+200]
        # find second argument (after first comma at paren depth 0 within call)
        depth = 1; i = 0; args = []; cur = ''
        while i < len(seg) and depth > 0:
            c = seg[i]
            if c in '([': depth += 1
            elif c in ')]':
                depth -= 1
                if depth == 0: break
            elif c == ',' and depth == 1:
                args.append(cur); cur = ''
                i += 1; continue
            cur += c
            i += 1
        args.append(cur)
        if len(args) >= 2:
            cb = args[1].strip()
            # strip casts
            cb = re.sub(r'^\([^)]*\)\s*', '', cb)
            cb = cb.split('\n')[0].strip().rstrip(',')
            mm = re.match(r'&?([A-Za-z_][A-Za-z0-9_]*)', cb)
            if mm: cbs.add(mm.group(1))
    return cbs

def get_napi_polls(text):
    """netif_napi_add(dev, &napi, poll, weight) — poll is 3rd arg (sometimes 4th with weight first in older trees)."""
    polls = set()
    for m in re.finditer(r'netif_napi_add\s*\(', text):
        seg = text[m.end():m.end()+250]
        depth = 1; i = 0; args = []; cur = ''
        while i < len(seg) and depth > 0:
            c = seg[i]
            if c in '([': depth += 1
            elif c in ')]':
                depth -= 1
                if depth == 0: break
            elif c == ',' and depth == 1:
                args.append(cur); cur = ''
                i += 1; continue
            cur += c
            i += 1
        args.append(cur)
        # find an arg that looks like a function name (identifier, not &ptr, not number)
        for a in args:
            a2 = a.strip().split('\n')[0].strip().rstrip(',')
            mm = re.match(r'^&?([A-Za-z_][A-Za-z0-9_]*)$', a2)
            if mm:
                nm = mm.group(1)
                if nm not in ('napi',):  # heuristic: name that is a poll fn
                    polls.add(nm)
    return polls

def norm_lock_expr(arg):
    arg = arg.strip()
    arg = re.sub(r'^&', '', arg).strip()
    return arg

def analyze_file(path):
    try:
        raw = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        return None
    text = strip_comments(raw)
    funcs = parse_functions(text)
    tasklet_cbs = get_tasklet_callbacks(text)
    napi_polls = get_napi_polls(text)
    softirq_fns = set()
    for f,(s,e) in [(f,(s,e)) for f,s,e in funcs]:
        if f in tasklet_cbs or f in napi_polls:
            softirq_fns.add(f)
    # lock sites
    sites = []  # (lockexpr, mode, line, func)
    for m in lock_call_re.finditer(text):
        mode = m.group(1)
        arg = m.group(2)
        # handle irqsave two-arg
        line = text.count('\n', 0, m.start()) + 1
        # enclosing function
        fn = None
        for name, s, e in funcs:
            if s <= line <= e:
                fn = name; break
        expr = norm_lock_expr(arg)
        if not expr or len(expr) > 60: continue
        sites.append((expr, mode, line, fn))
    return {
        'funcs': funcs,
        'tasklet_cbs': sorted(tasklet_cbs),
        'napi_polls': sorted(napi_polls),
        'softirq_fns': sorted(softirq_fns),
        'sites': sites,
    }

def main():
    tasklet_files = [l.strip() for l in open(os.path.join(TDIR,'tasklet_files.txt')) if l.strip()]
    napi_files = [l.strip() for l in open(os.path.join(TDIR,'napi_files.txt')) if l.strip()]
    files = sorted(set(tasklet_files + napi_files))
    results = {}
    for rel in files:
        path = os.path.join(ROOT, rel) if not rel.startswith('/') else rel
        if not os.path.exists(path): continue
        r = analyze_file(path)
        if r: results[rel] = r
    json.dump(results, open(os.path.join(TDIR,'site_analysis.json'),'w'), indent=1)
    # candidates: lock taken plain in a softirq fn AND plain elsewhere
    cands = []
    for rel, r in results.items():
        softirq_fns = set(r['softirq_fns'])
        by_lock = collections.defaultdict(list)
        for expr, mode, line, fn in r['sites']:
            if mode in ('lock','trylock','unlock','unlock_irq','unlock_bh','unlock_irqrestore'):
                continue
            by_lock[expr].append((mode, line, fn))
        for expr, lst in by_lock.items():
            soft_plain = [(m,l,f) for m,l,f in lst if f in softirq_fns and m in ('lock','trylock')]
            other_plain = [(m,l,f) for m,l,f in lst if f not in softirq_fns and m in ('lock',)]
            bh_users = [(m,l,f) for m,l,f in lst if m=='lock_bh']
            irq_users = [(m,l,f) for m,l,f in lst if m in ('lock_irq','lock_irqsave')]
            if soft_plain and other_plain:
                cands.append({
                    'file': rel, 'lock': expr,
                    'softirq_sites': [(f,l,m) for m,l,f in soft_plain],
                    'other_plain': [(f,l,m) for m,l,f in other_plain],
                    'bh_users': [(f,l) for m,l,f in bh_users],
                    'irq_users': [(f,l) for m,l,f in irq_users],
                })
    json.dump(cands, open(os.path.join(TDIR,'candidates.json'),'w'), indent=1)
    print("files analyzed:", len(results))
    print("candidates:", len(cands))
    for c in cands:
        print(f"{c['file']} lock={c['lock']}")
        print(f"   softirq: {c['softirq_sites']}")
        print(f"   other_plain: {c['other_plain'][:8]}")
        print(f"   bh: {c['bh_users'][:4]} irq: {c['irq_users'][:4]}")

if __name__ == '__main__':
    main()
