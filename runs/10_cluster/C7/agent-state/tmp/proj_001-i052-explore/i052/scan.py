import re, os, sys, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s08"
REG = re.compile(r'\b(?:devm_)?request(?:_threaded)?_irq\s*\(')
IDENT = r'[A-Za-z_][A-Za-z0-9_]*'

# collect files with irq registration
reg_files = []
for dirpath, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in ('.git',)]
    for f in files:
        if f.endswith(('.c', '.h')):
            p = os.path.join(dirpath, f)
            try:
                with open(p, 'r', errors='replace') as fh:
                    t = fh.read()
            except OSError:
                continue
            if REG.search(t):
                reg_files.append((p, t))

def find_body(text, name):
    """Find definition of function `name` and return (start_offset_of_body, end, line)."""
    # match `name(` preceded by non-ident char and followed by ... ) {  -- heuristic
    for m in re.finditer(r'(?<![A-Za-z0-9_])' + re.escape(name) + r'\s*\(', text):
        i = m.end()
        depth = 1
        # skip to matching close paren
        while i < len(text) and depth > 0:
            c = text[i]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            elif c == '"':
                i += 1
                while i < len(text) and text[i] != '"':
                    if text[i] == '\\':
                        i += 1
                    i += 1
            i += 1
        # skip whitespace/comments to find '{'
        j = i
        while j < len(text):
            if text[j] in ' \t\r\n':
                j += 1
            elif text.startswith('//', j):
                j = text.find('\n', j)
                if j == -1:
                    j = len(text)
            elif text.startswith('/*', j):
                k = text.find('*/', j)
                j = k + 2 if k != -1 else len(text)
            else:
                break
        if j < len(text) and text[j] == '{':
            # ensure not a call followed by { (unlikely)
            # find matching brace
            depth = 0
            k = j
            in_str = None
            while k < len(text):
                c = text[k]
                if in_str:
                    if c == '\\':
                        k += 2
                        continue
                    if c == in_str:
                        in_str = None
                elif c in '"\'':
                    in_str = c
                elif c == '/' and text.startswith('//', k):
                    k = text.find('\n', k)
                    if k == -1:
                        k = len(text)
                elif c == '/' and text.startswith('/*', k):
                    e = text.find('*/', k)
                    k = e + 2 if e != -1 else len(text)
                elif c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        return (j, k, text.count('\n', 0, m.start()) + 1)
                k += 1
    return None

LOCK_TAKE = re.compile(r'\b(spin_lock(?:_irqsave|_irq|_bh|_nested)?|read_lock|write_lock|_raw_spin_lock(?:_irqsave|_irq|_bh)?)\s*\(\s*&?\s*([^,\s]+(?:\s*->\s*[A-Za-z0-9_]+)*)')
# simpler: capture lock expression up to ',' or ')'
LOCK_ANY = re.compile(r'\b(spin_lock|spin_lock_nested|read_lock|write_lock)\s*\(')

def lock_takes(text, rng=None):
    """Yield (line, kind, lockexpr, flags_var) for each plain/variant take in text (optionally range)."""
    seg = text if rng is None else text[rng[0]:rng[1]]
    base = 0 if rng is None else rng[0]
    out = []
    for m in re.finditer(r'\b(spin_lock|_raw_spin_lock|read_lock|write_lock)(\w*)\s*\(', seg):
        kind = m.group(1)
        variant = m.group(2)  # '', '_nested', '_irqsave', '_irq', '_bh'
        if variant not in ('', '_nested', '_irqsave', '_irq', '_bh'):
            continue
        # parse args
        i = m.end()
        depth = 1
        args = []
        cur = ''
        while i < len(seg) and depth > 0:
            c = seg[i]
            if c == '(':
                depth += 1
                cur += c
            elif c == ')':
                depth -= 1
                if depth > 0:
                    cur += c
            elif c == ',' and depth == 1:
                args.append(cur.strip())
                cur = ''
            else:
                cur += c
            i += 1
        args.append(cur.strip())
        lock = args[0] if args else ''
        lock = re.sub(r'\s+', '', lock)
        # handle unlock matching not needed
        line = seg.count('\n', 0, m.start()) + seg[:base].count('\n') + 1 if False else text.count('\n', 0, base + m.start()) + 1
        out.append((line, kind, variant, lock))
    return out

results = []
handler_stats = collections.Counter()
for p, text in reg_files:
    rel = os.path.relpath(p, ROOT)
    # find registrations and handler names
    handlers = set()
    for m in REG.finditer(text):
        seg = text[m.start():m.start() + 600]
        # parse args roughly: request_irq(irq, handler, flags, name, dev)
        # find first arg boundary... easier: find identifiers matching known handler style
        # capture 2nd arg of request_irq / 2nd (handler) of devm_request_irq / 2nd (handler) of request_threaded_irq (handler, thread)
        i = m.end()
        depth = 1
        args = []
        cur = ''
        while i < len(text) and depth > 0 and i < m.start() + 1500:
            c = text[i]
            if c == '(':
                depth += 1
                cur += c
            elif c == ')':
                depth -= 1
                if depth > 0:
                    cur += c
            elif c == ',' and depth == 1:
                args.append(cur.strip())
                cur = ''
            else:
                cur += c
            i += 1
        args.append(cur.strip())
        fn = None
        base = REG_TYPE = text[m.start():m.end()]
        if 'request_threaded_irq' in base:
            if len(args) >= 2:
                fn = args[1]
        elif 'devm_request_irq' in base:
            if len(args) >= 3:
                fn = args[2]
        else:
            if len(args) >= 2:
                fn = args[1]
        if not fn:
            continue
        fn = fn.strip()
        if re.fullmatch(IDENT, fn):
            handlers.add(fn)
    if not handlers:
        continue
    # find handler bodies in this file and their plain lock takes
    hlocks = {}  # handler -> list of (line, lock)
    for h in handlers:
        b = find_body(text, h)
        if not b:
            handler_stats['unresolved'] += 1
            continue
        handler_stats['resolved'] += 1
        takes = lock_takes(text, (b[0], b[1]))
        for (line, kind, variant, lock) in takes:
            if variant == '' or variant == '_nested':
                hlocks.setdefault(h, []).append((line, lock))
    if not hlocks:
        continue
    # map lock expr -> handler lines
    lock_to_h = collections.defaultdict(list)
    for h, lst in hlocks.items():
        for (line, lock) in lst:
            lock_to_h[lock].append((h, line))
    if not lock_to_h:
        continue
    # all lock takes in file
    all_takes = lock_takes(text)
    rows = []
    for lock, hlines in lock_to_h.items():
        plain_nonh = []
        irqsave_nonh = 0
        bh_nonh = 0
        for (line, kind, variant, l2) in all_takes:
            if l2 != lock:
                continue
            if any(line == hl for (_, hl) in hlines):
                continue
            if variant == '' or variant == '_nested':
                plain_nonh.append(line)
            elif variant == '_irqsave' or variant == '_irq':
                irqsave_nonh += 1
            elif variant == '_bh':
                bh_nonh += 1
        if plain_nonh:
            rows.append({
                'file': rel, 'lock': lock,
                'handlers': [(h, l) for (h, l) in hlines],
                'plain_nonhandler': plain_nonh,
                'irqsave_nonhandler': irqsave_nonh,
                'bh_nonhandler': bh_nonh,
            })
    if rows:
        results.extend(rows)

with open(os.path.join(os.environ.get('TMPDIR', '/tmp'), 'i052', 'cross.json'), 'w') as f:
    json.dump(results, f, indent=1)
print('files with irq reg:', len(reg_files))
print('handlers resolved:', handler_stats['resolved'], 'unresolved:', handler_stats['unresolved'])
print('candidate lock rows:', len(results))
results.sort(key=lambda r: -(len(r['plain_nonhandler'])))
for r in results[:60]:
    print(f"{r['file']}: lock={r['lock']} hdl={r['handlers']} plain_nonh={r['plain_nonhandler'][:8]} irqsave_nonh={r['irqsave_nonhandler']} bh={r['bh_nonhandler']}")
