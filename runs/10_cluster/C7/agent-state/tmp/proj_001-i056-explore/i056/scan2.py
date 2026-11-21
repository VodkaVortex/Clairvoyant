import os, re, json, bisect
from collections import defaultdict

ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12'
OUT = os.path.join(os.environ['TMPDIR'], 'i056')
os.makedirs(OUT, exist_ok=True)

API_ARGS = {'request_irq': 2, 'devm_request_irq': 3, 'request_threaded_irq': 2}
irq_call = re.compile(r'\b(request_irq|devm_request_irq|request_threaded_irq)\s*\(')
lock_re = re.compile(r'\b(spin_lock|spin_trylock|spin_lock_irq|spin_lock_irqsave|spin_lock_bh|spin_trylock_bh|spin_trylock_irq|spin_trylock_irqsave|spin_lock_nested|spin_lock_irqsave_nested|spin_lock_bh_nested)\s*\(\s*(?:&\s*)?([^,\s\)]+)')

files = []
for dirpath, dirs, fns in os.walk(ROOT):
    if '/.git' in dirpath: continue
    for fn in fns:
        if fn.endswith('.c'):
            files.append(os.path.join(dirpath, fn))

def split_args(text):
    """split argument text on top-level commas"""
    args, depth, cur = [], 0, ''
    i = 0
    while i < len(text):
        c = text[i]
        if c in '([{': depth += 1
        elif c in ')]}': depth -= 1
        elif c == '"' :
            cur += c; i += 1
            while i < len(text) and text[i] != '"':
                if text[i] == '\\': cur += text[i]; i += 1
                cur += text[i]; i += 1
            cur += '"'; i += 1; continue
        if c == ',' and depth == 0:
            args.append(cur.strip()); cur = ''
        else:
            cur += c
        i += 1
    if cur.strip(): args.append(cur.strip())
    return args

records = []  # per file: functions with (start,end,name), locks inside, irq registrations
summary = {}

for f in sorted(files):
    rel = os.path.relpath(f, ROOT)
    try:
        src = open(f, errors='replace').read()
    except Exception:
        continue
    lines = src.split('\n')
    # strip comments/strings for parsing (keep map to real lines via offsets)
    # simple approach: process per-char, record line numbers
    masked = []
    in_block = False
    for ln in lines:
        out = []
        i = 0
        in_str = False
        while i < len(ln):
            c = ln[i]
            if in_block:
                if c == '*' and i+1 < len(ln) and ln[i+1] == '/':
                    in_block = False; out.append('  '); i += 2; continue
                out.append(' ' if c != '\t' else '\t'); i += 1; continue
            if in_str:
                if c == '\\': out.append('  '); i += 2; continue
                if c == '"': in_str = False
                out.append(' '); i += 1; continue
            if c == '/' and i+1 < len(ln) and ln[i+1] == '/':
                out.append(' ' * (len(ln) - i)); break
            if c == '/' and i+1 < len(ln) and ln[i+1] == '*':
                in_block = True; out.append('  '); i += 2; continue
            if c == '"': in_str = True; out.append(' '); i += 1; continue
            out.append(c); i += 1
        masked.append(''.join(out))
    mtext = '\n'.join(masked)
    # function definitions: track brace depth; a '{' at depth 0 preceded by ')' on the same logical region
    funcs = []  # (name, start_line, end_line)
    depth = 0
    # find all top-level function bodies
    # iterate char positions with line tracking
    line_of = None
    # build index: for each char index -> line number
    nlpos = [-1]
    for i, c in enumerate(mtext):
        if c == '\n': nlpos.append(i)
    # function start heuristic: regex over mtext for name(...) { at depth 0
    # find positions of '{' with depth 0
    opens = []
    d = 0
    for i, c in enumerate(mtext):
        if c == '{':
            if d == 0: opens.append(i)
            d += 1
        elif c == '}':
            d -= 1
    # for each top-level block, try to find the function name by looking back from '{'
    for o in opens:
        # find matching close
        d2 = 0; close = None
        for j in range(o, len(mtext)):
            if mtext[j] == '{': d2 += 1
            elif mtext[j] == '}':
                d2 -= 1
                if d2 == 0: close = j; break
        if close is None: continue
        head = mtext[max(0, o-600):o]
        # last identifier followed by (...) before '{'
        m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\([^()]*\)\s*(?:\n|\s)*$', head)
        if not m:
            # multi-line params: find last '(' ... matching ... ')'
            m2 = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', head)
            if not m2: continue
            name = m2.group(1)
            # check the rest is a param list: balance parens from m2 end
            p = head.find('(', m2.end()-1)
            bal = 0; ok = True
            for j in range(p, len(head)):
                if head[j] == '(': bal += 1
                elif head[j] == ')':
                    bal -= 1
                    if bal == 0:
                        rest = head[j+1:].strip()
                        if rest == '' or all(ch in ' \t\n' for ch in rest):
                            name = m2.group(1)
                        else:
                            ok = False
                        break
            if not ok or bal != 0:
                continue
        else:
            name = m.group(1)
        if name in ('if', 'for', 'while', 'switch', 'sizeof', 'return', 'else', 'do'):
            continue
        sl = bisect.bisect_right(nlpos, o)   # 1-based line of '{'
        el = bisect.bisect_right(nlpos, close)
        # function signature line: find line of name start
        sigline = bisect.bisect_right(nlpos, o - len(head) + m.start()) if False else sl
        funcs.append((name, sigline, el))
    if not funcs: continue
    # locks and irq registrations inside each function
    fstarts = [x[1] for x in funcs]
    def funcof(line):
        idx = bisect.bisect_right(fstarts, line) - 1
        while idx >= 0:
            n, s, e = funcs[idx]
            if s <= line <= e: return n
            idx -= 1
        return None
    data = []
    interesting = False
    for i, ln in enumerate(masked, 1):
        if irq_call.search(ln) or 'spin_lock' in ln or 'spin_trylock' in ln or 'spin_unlock' in ln:
            data.append((i, lines[i-1]))
    if not data: continue
    summary[rel] = dict(funcs=funcs, data=data, nlines=len(lines))

# Second pass: handler registration extraction with argument positions
pairs = []
handler_defs = {}
fileinfo = {}
for rel, info in summary.items():
    path = os.path.join(ROOT, rel)
    src = open(path, errors='replace').read()
    lines = src.split('\n')
    masked = []
    in_block = False
    for ln in lines:
        out = []
        i = 0; in_str = False
        while i < len(ln):
            c = ln[i]
            if in_block:
                if c == '*' and i+1 < len(ln) and ln[i+1] == '/':
                    in_block = False; out.append('  '); i += 2; continue
                out.append(' ' if c != '\t' else '\t'); i += 1; continue
            if in_str:
                if c == '\\': out.append('  '); i += 2; continue
                if c == '"': in_str = False
                out.append(' '); i += 1; continue
            if c == '/' and i+1 < len(ln) and ln[i+1] == '/':
                out.append(' ' * (len(ln)-i)); break
            if c == '/' and i+1 < len(ln) and ln[i+1] == '*':
                in_block = True; out.append('  '); i += 2; continue
            if c == '"': in_str = True; out.append(' '); i += 1; continue
            out.append(c); i += 1
        masked.append(''.join(out))
    mtext = '\n'.join(masked)
    fileinfo[rel] = (lines, masked)

    for m in irq_call.finditer(mtext):
        api = m.group(1)
        p = mtext.find('(', m.end()-1)
        bal = 0
        for j in range(p, len(mtext)):
            if mtext[j] == '(': bal += 1
            elif mtext[j] == ')':
                bal -= 1
                if bal == 0: break
        argtext = mtext[p+1:j]
        args = split_args(argtext)
        pos = API_ARGS[api]
        if len(args) < pos + 1: continue
        h = args[pos-1].strip()
        hname = re.sub(r'^&', '', h)
        hname = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)', hname)
        if not hname: continue
        hname = hname.group(1)
        line = mtext[:m.start()].count('\n') + 1
        pairs.append((rel, line, api, hname))

print("irq registrations with handler names:", len(pairs))
# resolve handler defs
resolved = 0
cross = []
for (rel, rline, api, hname) in pairs:
    if rel not in summary: continue
    funcs = summary[rel]['funcs']
    target = None
    for (n, s, e) in funcs:
        if n == hname:
            target = (n, s, e); break
    if not target: continue
    n, s, e = target
    resolved += 1
    lines, masked = fileinfo[rel]
    hlocks = []
    for i in range(s, e+1):
        for lm in lock_re.finditer(masked[i-1]):
            hlocks.append((i, lm.group(1), lm.group(2)))
    if not hlocks: continue
    plain_hlocks = [(i, k, ex) for (i, k, ex) in hlocks if k in ('spin_lock', 'spin_trylock')]
    if not plain_hlocks: continue
    # all lock sites in file with same expression
    for i, ln in enumerate(masked, 1):
        if s <= i <= e: continue
        for lm in lock_re.finditer(ln):
            if lm.group(2) in [ex for (_, _, ex) in plain_hlocks] and lm.group(1) in ('spin_lock', 'spin_trylock', 'spin_lock_nested'):
                cross.append((rel, rline, api, hname, s, e, i))

print("resolved in-file handlers:", resolved, "cross pairs (plain handler lock + plain other):", len(cross))
with open(os.path.join(OUT, 'cross2.tsv'), 'w') as fh:
    fh.write("file\tregline\tapi\thandler\tdefstart\tdefend\totherplainline\n")
    for r in cross:
        fh.write('\t'.join(str(x) for x in r) + '\n')
# save handler lock inventory for files with plain handler locks
with open(os.path.join(OUT, 'plain_handler_locks.txt'), 'w') as fh:
    for (rel, rline, api, hname) in pairs:
        if rel not in summary: continue
        funcs = summary[rel]['funcs']
        for (n, s, e) in funcs:
            if n == hname:
                lines, masked = fileinfo[rel]
                for i in range(s, e+1):
                    for lm in lock_re.finditer(masked[i-1]):
                        fh.write(f"{rel}\t{rline}\t{api}\t{hname}\t{i}\t{lm.group(1)}\t{lm.group(2)}\n")
                break
