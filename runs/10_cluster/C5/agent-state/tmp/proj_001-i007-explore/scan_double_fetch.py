import re, os, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C5/public/snapshots/s02"

FETCH = re.compile(r'\b(get_user|__get_user|copy_from_user|copy_from_iter|copy_from_iter_full|strncpy_from_user|unsafe_copy_from_user|memdup_user|vmemdup_user|__copy_from_user_inatomic|compat_get_user|compat_copy_from_user)\s*\(')

func_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&\(\),]*\)[ \t]*\n?\{', re.M)

def find_funcs(src):
    out = []
    for m in func_re.finditer(src):
        sig = m.group(0)
        nm = re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', sig)
        name = nm[-1] if nm else '?'
        if name in ('if','for','while','switch','sizeof','return','defined','else'): continue
        b = src.index('{', m.start())
        depth = 0; j = b
        ln = len(src)
        while j < ln:
            c = src[j]
            if c == '{': depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0: break
            j += 1
        start_line = src.count('\n', 0, m.start()) + 1
        end_line = src.count('\n', 0, j) + 1
        if end_line - start_line > 400: continue
        out.append((name, start_line, end_line, src[b:j]))
    return out

def calls_in(body):
    res = []
    for m in FETCH.finditer(body):
        start = m.end(); depth = 1; j = start
        while j < len(body) and depth > 0:
            if body[j] == '(': depth += 1
            elif body[j] == ')': depth -= 1
            j += 1
        args = body[start:j-1]
        parts = []; d=0; cur=''
        for ch in args:
            if ch in '([': d += 1
            elif ch in ')]': d -= 1
            elif ch == ',' and d == 0:
                parts.append(cur); cur=''
            else: cur += ch
        parts.append(cur)
        fname = m.group(1)
        if 'get_user' in fname:
            arg = parts[1].strip() if len(parts)>=2 else ''
        else:
            arg = parts[1].strip() if len(parts)>=2 else ''
        res.append((fname, arg))
    return res

hits = []
count_scanned = 0
for dirpath, dirnames, filenames in os.walk(ROOT):
    # skip tools & selftests (userspace)
    relp = os.path.relpath(dirpath, ROOT)
    if relp.startswith('tools') or relp.startswith('samples') or relp.startswith('usr'):
        dirnames[:] = []
        continue
    for fn in filenames:
        if not fn.endswith('.c'): continue
        p = os.path.join(dirpath, fn)
        try:
            src = open(p, 'r', errors='replace').read()
        except Exception:
            continue
        for (name, sl, el, body) in find_funcs(src):
            if 'get_user' not in body and 'copy_from_user' not in body and 'copy_from_iter' not in body and 'strncpy_from_user' not in body and 'memdup_user' not in body:
                continue
            count_scanned += 1
            cl = calls_in(body)
            if len(cl) < 2: continue
            tok_counts = {}
            for (f, a) in cl:
                if a:
                    tok_counts[a] = tok_counts.get(a, 0) + 1
            doubled = {t:c for t,c in tok_counts.items() if c>=2 and len(t)<60 and '&' not in t[:1]}
            if doubled:
                rel = os.path.relpath(p, ROOT)
                hits.append((sum(doubled.values()), rel, name, sl, el, len(cl), sorted(doubled.items())[:6]))

hits.sort(key=lambda h: (-h[0], h[1]))
print("functions-with-fetches scanned:", count_scanned)
print("total candidate functions:", len(hits))
for h in hits:
    print(f"score={h[0]} :: {h[1]} :: {h[2]} (lines {h[3]}-{h[4]}) nfetch={h[5]} doubled={h[6]}")
