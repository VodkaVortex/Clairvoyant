import re, os, json

BASE = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s05"

def extract_call(text, start_idx):
    depth = 0; i = start_idx; in_str = None
    while i < len(text):
        c = text[i]
        if in_str:
            if c == '\\': i += 2; continue
            if c == in_str: in_str = None
        else:
            if c in '"\'': in_str = c
            elif c == '(': depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0: return text[start_idx+1:i], i
        i += 1
    return None, None

def split_args(argstr):
    args = []; depth = 0; cur = []; in_str = None; i = 0
    while i < len(argstr):
        c = argstr[i]
        if in_str:
            cur.append(c)
            if c == '\\':
                if i+1 < len(argstr): cur.append(argstr[i+1])
                i += 2; continue
            if c == in_str: in_str = None
        else:
            if c in '"\'': in_str = c; cur.append(c)
            elif c in '([': depth += 1; cur.append(c)
            elif c in ')]': depth -= 1; cur.append(c)
            elif c == ',' and depth == 0:
                args.append(''.join(cur).strip()); cur = []
            else: cur.append(c)
        i += 1
    if cur: args.append(''.join(cur).strip())
    return args

call_pat = re.compile(r'\b(devm_)?request_(threaded_)?irq\s*\(')
regs = []
for dirpath, dirs, files in os.walk(os.path.join(BASE, 'drivers')):
    dirs[:] = [d for d in dirs if d not in ('.git',)]
    for fn in files:
        if not fn.endswith('.c') and not fn.endswith('.h'):
            continue
        p = os.path.join(dirpath, fn)
        try:
            text = open(p, errors='replace').read()
        except Exception:
            continue
        for m in call_pat.finditer(text):
            argstr, _ = extract_call(text, m.end() - 1)
            if argstr is None: continue
            args = split_args(argstr)
            if len(args) < 4: continue
            is_threaded = m.group(2) is not None
            handler = args[1].strip()
            thread_fn = args[2].strip() if is_threaded and len(args) > 2 else None
            lineno = text.count('\n', 0, m.start()) + 1
            rel = os.path.relpath(p, BASE)
            regs.append({'file': rel, 'line': lineno, 'handler': handler,
                         'threaded': is_threaded, 'thread_fn': thread_fn})
json.dump(regs, open(os.environ['TMPDIR'] + '/i048/regs_full.json', 'w'))
print("total registrations:", len(regs))
simple = [r for r in regs if r['handler'].isidentifier()]
print("simple handler names:", len(simple), "unique:", len(set(r['handler'] for r in simple)))
thr = [r for r in regs if r['threaded']]
print("threaded registrations:", len(thr))
