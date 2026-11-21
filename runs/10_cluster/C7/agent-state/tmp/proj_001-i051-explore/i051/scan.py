#!/usr/bin/env python3
# Extract hardirq-handler lock usage and cross-index with plain spin_lock sites per file.
import os, re, sys, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s07"
SKIP_DIRS = {"Documentation", "tools", "samples", "scripts", "usr"}

# regexes
re_irqreg = re.compile(r'\b(?:devm_)?request(?:_threaded)?_irq\s*\(')
# handler arg extraction: we'll parse arguments of the call via paren matching
re_func_def = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(')
re_spin_plain = re.compile(r'\bspin_lock\s*\(\s*([^);]+?)\s*\)')
re_spin_irq = re.compile(r'\bspin_lock_(?:irqsave|irq|bh)\s*\(')

def find_files():
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if f.endswith('.c'):
                out.append(os.path.join(dirpath, f))
    return out

def parse_call_args(text, start):
    # start = index of '('
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return text[start+1:i], i
        elif c == '"' or c == "'":
            q = c; i += 1
            while i < n and text[i] != q:
                if text[i] == '\\': i += 1
                i += 1
        i += 1
    return None, None

def strip_comments(text):
    # keep newlines to preserve line numbers
    text = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), text, flags=re.S)
    text = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group(0)), text)
    return text

def get_handler_names(text):
    """Return list of (handler_name, line, kind) for irq registrations."""
    res = []
    for m in re_irqreg.finditer(text):
        args, end = parse_call_args(text, m.end()-1)
        if args is None:
            continue
        # split top-level commas
        parts, depth, cur = [], 0, ''
        i = 0
        while i < len(args):
            c = args[i]
            if c in '([': depth += 1
            elif c in ')]': depth -= 1
            elif c == '"' or c == "'":
                q = c; cur += c; i += 1
                while i < len(args) and args[i] != q:
                    if args[i] == '\\': cur += args[i]; i += 1
                    cur += args[i]; i += 1
                cur += args[i] if i < len(args) else ''
                i += 1
                continue
            if c == ',' and depth == 0:
                parts.append(cur); cur = ''
            else:
                cur += c
            i += 1
        parts.append(cur)
        parts = [p.strip() for p in parts]
        # request_irq(irq, handler, flags, name, dev) ; threaded: irq, handler, thread_fn, flags, name, dev
        handler = None
        if 'threaded' in m.group(0):
            if len(parts) >= 3:
                handler = parts[1]
                threadfn = parts[2]
            else:
                handler = None; threadfn = None
            kind = 'threaded'
        else:
            handler = parts[1] if len(parts) >= 2 else None
            threadfn = None
            kind = 'plain'
        line = text[:m.start()].count('\n') + 1
        if handler:
            hname = re.sub(r'^&', '', handler).strip()
            res.append((hname, line, kind, threadfn))
    return res

def find_function_body(text, fname):
    """Return (start_idx, end_idx, line) of the body of function fname, else None."""
    # find definitions like: rettype fname(...) ... { }
    pat = re.compile(r'\b' + re.escape(fname) + r'\s*\(')
    for m in pat.finditer(text):
        # must be a definition: preceding token not part of call chain -> check char before match
        pre = text[max(0, m.start()-30):m.start()]
        # skip if it's a call inside parens? Heuristic: if preceded by '=' or '(' likely reference; but definitions usually at line start after return type
        args, close = parse_call_args(text, m.end()-1)
        if args is None:
            continue
        # after close, expect optional whitespace/attributes then '{'
        rest = text[close+1:close+200]
        rest_stripped = rest.lstrip()
        if rest_stripped.startswith('{') or re.match(r'__\w+|reentrant|^\s*(?:__init|__read_mostly|noinline|inline|__always_inline)\b', rest_stripped) and '{' in rest[:120]:
            # find the opening brace
            bi = text.find('{', close+1)
            if bi == -1 or bi > close + 200:
                continue
            # match braces
            depth = 0
            i = bi
            n = len(text)
            in_str = None
            while i < n:
                c = text[i]
                if in_str:
                    if c == '\\': i += 2; continue
                    if c == in_str: in_str = None
                elif c in '"\'':
                    in_str = c
                elif c == '/':
                    if i+1 < n and text[i+1] == '*':
                        j = text.find('*/', i+2)
                        i = j+2 if j != -1 else n
                        continue
                    if i+1 < n and text[i+1] == '/':
                        j = text.find('\n', i)
                        i = j if j != -1 else n
                        continue
                elif c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        return (bi, i+1, text[:bi].count('\n')+1)
                i += 1
    return None

def main():
    files = find_files()
    report = {}
    stats = collections.Counter()
    for path in files:
        try:
            raw = open(path, errors='replace').read()
        except Exception:
            continue
        text = strip_comments(raw)
        handlers = get_handler_names(text)
        if not handlers:
            continue
        # unique handler names (exclude NULL)
        uniq = {}
        for hname, line, kind, threadfn in handlers:
            if hname in ('NULL', '0', '') or re.match(r'^[A-Z_0-9]+$', hname) and hname.isupper():
                # macro handler name - keep, we may resolve later
                pass
            uniq.setdefault(hname, []).append((line, kind))
        # find bodies and lock usage inside
        handler_info = {}
        for hname, occurrences in uniq.items():
            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', hname):
                stats['unresolvable_name'] += 1
                continue
            body = find_function_body(text, hname)
            if body is None:
                stats['no_body'] += 1
                handler_info[hname] = None
                continue
            s, e, line = body
            bodytext = text[s:e]
            plain = []
            irqv = []
            for lm in re_spin_plain.finditer(bodytext):
                lock = lm.group(1).strip()
                plain.append((lock, text[:s+lm.start()].count('\n')+1))
            for lm in re_spin_irq.finditer(bodytext):
                irqv.append(text[:s+lm.start()].count('\n')+1)
            handler_info[hname] = {'body_line': line, 'plain_locks': plain, 'irq_locks': len(irqv)}
            stats['handlers_resolved'] += 1
        # gather plain locks of interest
        for hname, info in handler_info.items():
            if info and info['plain_locks']:
                rel = os.path.relpath(path, ROOT)
                report.setdefault(rel, []).append({'handler': hname, 'reg_lines': [o[0] for o in uniq[hname]], 'info': info})
    out = os.path.join(os.environ.get('TMPDIR','/tmp'), 'i051', 'handler_locks.json')
    with open(out, 'w') as f:
        json.dump({'report': report, 'stats': dict(stats)}, f, indent=1)
    print("files scanned:", len(files))
    print("stats:", dict(stats))
    print("files with plain-lock handlers:", len(report))

main()
