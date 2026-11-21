import os, re, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"
TMP = os.environ['TMPDIR']

func_start_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\([A-Za-z0-9_, \t\*&]*\)$')

def read(p):
    with open(p, 'r', errors='replace') as f:
        return f.read()

# Pass 1: for each .c file with request_irq, record (handler_name -> set of lock expressions inside handler body)
# Pass 2: for each file, map lock expression -> list of (line, kind) for ALL acquisitions
# Cross-index: lock expression taken inside a handler body AND taken with plain spin_lock somewhere else in same file.

def find_function_body(lines, name):
    """Return (start_line_idx, indent_open, body_span) for function definition `name`."""
    pat = re.compile(r'\b' + re.escape(name) + r'\s*\(')
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('*') or s.startswith('/*') or s.startswith('//'): continue
        if pat.search(ln) and not re.search(r'->|\.', ln.split(name)[0]):
            # crude: find the line ending with ')' then '{'
            j = i
            sig = ln
            while sig.count('(') > sig.count(')') and j+1 < len(lines):
                j += 1; sig += ' ' + lines[j].strip()
            # check this is a definition: previous non-empty line should not be ',' or start with word? just take it
            # find opening brace after j
            k = j
            while k < len(lines) and k < j + 10:
                if '{' in lines[k]: break
                k += 1
            if k >= len(lines) or k >= j+10: continue
            # if the name match is a call (line contains '=' or ends with ';'), skip
            joined = ' '.join(lines[i:k+1])
            if re.search(re.escape(name) + r'\s*\([^;{]*\)\s*;', joined):  # call statement
                continue
            # find matching close brace
            depth = 0; started = False; end = None
            for m in range(k, min(k+4000, len(lines))):
                for ch in lines[m]:
                    if ch == '{': depth += 1; started = True
                    elif ch == '}':
                        depth -= 1
                        if started and depth == 0:
                            end = m; break
                if end is not None: break
            if end is None: continue
            return (i, k, end)  # (def line, brace line, end line)
    return None

lock_acq_re = re.compile(r'\bspin_lock\s*\(\s*([^;]+?)\s*\)\s*;')
lock_irqsave_re = re.compile(r'\bspin_lock_irqsave\s*\(\s*([^;,]+?)\s*,')
lock_irq_re = re.compile(r'\bspin_lock_irq\s*\(\s*([^;]+?)\s*\)\s*;')
lock_bh_re = re.compile(r'\bspin_lock_bh\s*\(\s*([^;]+?)\s*\)\s*;')

def norm(expr):
    return re.sub(r'\s+', '', expr.strip())

cand_rows = []
per_file = {}
site_count = 0
for dirpath, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d != '.git']
    for fn in files:
        if not fn.endswith('.c'): continue
        p = os.path.join(dirpath, fn)
        try: src = read(p)
        except: continue
        if 'request_irq' not in src and 'request_threaded_irq' not in src: continue
        lines = src.split('\n')
        # find request sites in this file
        reqsites = []
        for i, ln in enumerate(lines):
            if re.search(r'\b(?:devm_)?request(?:_threaded)?_irq\s*\(', ln):
                call = ln; j = i
                while call.count('(') > call.count(')') and j+1 < len(lines) and j-i < 8:
                    j += 1; call += ' ' + lines[j]
                m = re.search(r'_irq\s*\((.*)', call)
                if not m: continue
                args = m.group(1)
                # balance parens from here
                depth = 0; bal = ''
                for ch in args:
                    if ch=='(': depth+=1
                    if ch==')':
                        if depth==0: break
                        depth-=1
                    bal += ch
                parts, d2, cur = [], 0, ''
                for ch in bal:
                    if ch=='(': d2+=1
                    if ch==')': d2-=1
                    if ch==',' and d2==0: parts.append(cur.strip()); cur=''
                    else: cur+=ch
                parts.append(cur.strip())
                if len(parts) < 2: continue
                handler = parts[1].strip()
                reqsites.append((i+1, handler))
        if not reqsites: continue
        site_count += len(reqsites)
        handlers = set()
        for _, h in reqsites:
            h = h.strip()
            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', h):
                handlers.add(h)
        if not handlers: continue
        # lock acquisition map: expr -> list of (line, kind)
        lockmap = collections.defaultdict(list)
        for i, ln in enumerate(lines):
            for kind, rx in (('plain', lock_acq_re), ('irqsave', lock_irqsave_re), ('irq', lock_irq_re), ('bh', lock_bh_re)):
                for m in rx.finditer(ln):
                    lockmap[norm(m.group(1))].append((i+1, kind))
        # handler body locks
        hlocks = {}
        for h in handlers:
            body = find_function_body(lines, h)
            if not body: continue
            _, bl, el = body
            for i in range(bl, el+1):
                ln = lines[i]
                for kind, rx in (('plain', lock_acq_re), ('irqsave', lock_irqsave_re), ('irq', lock_irq_re), ('bh', lock_bh_re)):
                    for m in rx.finditer(ln):
                        hlocks.setdefault(h, []).append((norm(m.group(1)), kind, i+1))
        if not hlocks: continue
        rel = os.path.relpath(p, ROOT)
        per_file[rel] = dict(reqsites=reqsites, lockmap={k:v for k,v in lockmap.items()}, hlocks=hlocks)

json.dump(per_file, open(TMP + '/per_file.json','w'))
print("files analyzed:", len(per_file), "irq sites:", site_count)
