import os, re, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
SCAN_DIRS = ["drivers/net/wireless", "drivers/staging", "net", "drivers/net", "net/wireless", "drivers/usb", "sound", "drivers/tty", "drivers/media"]

data = json.load(open(os.path.join(os.environ['TMPDIR'],'i016','timer_callbacks.json')))
timer_callbacks = data["timer_callbacks"]  # fname -> (file,line,setup)
hrtimer_handlers = set((h[0]) for h in data["hrtimer_handlers"])

# build global symbol table: fname -> list of (file, line_start, line_end, lines)
all_files = []
for d in SCAN_DIRS:
    p = os.path.join(ROOT, d)
    if not os.path.isdir(p): continue
    for dirpath, _, fnames in os.walk(p):
        for f in fnames:
            if f.endswith('.c'):
                all_files.append(os.path.join(dirpath, f))

def parse_functions(lines):
    funcs = {}  # name -> (start_idx, end_idx)
    i = 0
    n = len(lines)
    cur = None
    while i < n:
        l = lines[i]
        if cur is None:
            m = re.match(r'^(?:[A-Za-z_][A-Za-z0-9_]*[\s\*]+)+([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
            if m and not l.strip().endswith(';') and 'if' not in l.split('(')[0].split()[-1:]:
                name = m.group(1)
                # find opening brace within next few lines
                j = i
                depth_paren = 0
                found_open = False
                while j < min(i+8, n):
                    depth_paren += lines[j].count('(') - lines[j].count(')')
                    if depth_paren == 0:
                        if '{' in lines[j]:
                            found_open = True
                            start = j
                            break
                        else:
                            break
                    j += 1
                if found_open:
                    depth = 0
                    k = start
                    while k < n:
                        depth += lines[k].count('{') - lines[k].count('}')
                        if depth == 0:
                            funcs.setdefault(name, []).append((i, k))
                            cur = (name, k+1)  # resume after function end
                            break
                        k += 1
                    i = k + 1
                    continue
        i += 1
    return funcs

lockcall_re = re.compile(r'\b(spin_(?:un)?lock(?:_bh|_irqsave|_irqrestore|_irq|_nested|_trylock|_trylock_bh)?|spin_trylock(?:_bh)?)\s*\(\s*([^;]+?)\)\s*;')

def mode(fn):
    if 'irqsave' in fn or 'irqrestore' in fn: return 'irqsave'
    if fn.endswith('_bh') or fn.endswith('_bh(') or '_bh' in fn: return 'bh'
    if 'irq' in fn: return 'irq'
    return 'plain'

# For each timer callback function, collect lock acquisitions in its body (across the tree)
# Build index of function definitions per file and a global map from function name -> definition
defs = {}  # fname -> list of (relpath, start, end, body_lines)
for fp in all_files:
    try: lines = open(fp, errors='ignore').read().split('\n')
    except: continue
    funcs = parse_functions(lines)
    rel = os.path.relpath(fp, ROOT)
    for name, spans in funcs.items():
        for (s,e) in spans:
            defs.setdefault(name, []).append((rel, s, e, lines[s:e+1]))

results = []
for fname, setup_info in timer_callbacks.items():
    if fname not in defs:
        continue
    for (rel, s, e, body) in defs[fname]:
        locks = []
        for idx, l in enumerate(body):
            for m in lockcall_re.finditer(l):
                mode_ = mode(m.group(1))
                locks.append((mode_, m.group(1), m.group(2)[:80], s+idx+1, l.strip()[:140]))
        if locks:
            # keep callbacks whose body takes at least one spin lock of any kind
            results.append({"func": fname, "file": rel, "start": s+1, "end": e+1,
                            "setup": setup_info, "locks": locks})

# hrtimer handlers similarly
for fname in sorted(hrtimer_handlers):
    if fname not in defs: continue
    for (rel, s, e, body) in defs[fname]:
        locks = []
        for idx, l in enumerate(body):
            for m in lockcall_re.finditer(l):
                locks.append((mode(m.group(1)), m.group(1), m.group(2)[:80], s+idx+1, l.strip()[:140]))
        if locks:
            results.append({"func": fname+" [hrtimer]", "file": rel, "start": s+1, "end": e+1,
                            "setup": "hrtimer", "locks": locks})

json.dump(results, open(os.path.join(os.environ['TMPDIR'],'i016','timer_locks.json'),'w'), indent=1)
print("timer callbacks with spin_lock calls in body:", len(results))
# print the ones with plain locks
plain = [r for r in results if any(l[0]=='plain' for l in r["locks"])]
print("with plain spin_lock:", len(plain))
for r in plain:
    print(r["file"], r["func"], [ (l[0], l[3], l[2][:50]) for l in r["locks"] if l[0]=='plain'])
