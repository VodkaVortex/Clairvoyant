import re, json, os, sys
from collections import defaultdict

ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s06'

def strip_comments_keep_lines(text):
    out = []; i = 0; n = len(text)
    while i < n:
        c = text[i]
        if c == '/' and i+1 < n and text[i+1] == '*':
            j = text.find('*/', i+2)
            if j == -1: j = n-2
            seg = text[i:j+2]
            out.append(''.join(ch if ch == '\n' else ' ' for ch in seg))
            i = j+2
        elif c == '/' and i+1 < n and text[i+1] == '/':
            j = text.find('\n', i)
            if j == -1: j = n
            out.append(' ' * (j-i)); i = j
        else:
            out.append(c); i += 1
    return ''.join(out)

def scan_functions(lines):
    funcs = {}
    depth = 0
    pending = None
    cur_start = None
    n = len(lines)
    for i, l in enumerate(lines):
        if depth == 0:
            ls = l.strip()
            if ls and not ls.startswith('#') and '(' in l and ']' not in l.split('(')[0]:
                j = i; buf = ''; found = None
                while j < n and j < i+12:
                    buf += lines[j]
                    pd = buf.count('(') - buf.count(')')
                    if pd <= 0 and '{' in lines[j]:
                        found = j; break
                    if pd <= 0 and ';' in lines[j]:
                        break
                    j += 1
                if found is not None:
                    head = buf[:buf.find('(')]
                    m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', head)
                    if m and m.group(1) not in ('if','for','while','switch','return','sizeof','else','do','case'):
                        pending = m.group(1); cur_start = i
        for ch in l:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0 and pending is not None:
                    funcs[pending] = (cur_start+1, i+1)
                    pending = None; cur_start = None
                if depth < 0: depth = 0
    return funcs

def analyze(files_with_locks, outpath):
    """files_with_locks: dict path -> set of lock exprs (with & stripped consistently).
    Produces per-file: function map + every lock acquisition line with function and lock kind."""
    LOCKKIND = re.compile(r'spin_lock(_irqsave|_irqsave_nested|_bh|_irq|_nested)?\s*\(')
    report = {}
    for path, locks in files_with_locks.items():
        try:
            text = open(os.path.join(ROOT, path), encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        st = strip_comments_keep_lines(text)
        lines = st.split('\n')
        funcs = scan_functions(lines)
        flist = sorted(funcs.items(), key=lambda kv: kv[1][0])
        def owner(ln):
            for name,(s,e) in flist:
                if s <= ln <= e: return (name, s, e)
            return None
        sites = []
        for i, l in enumerate(lines):
            for m in LOCKKIND.finditer(l):
                kind = m.group(1) or ''
                # extract full arg
                rest = l[m.end():]
                am = re.match(r'\s*([^;]+?)\s*\)', rest)
                if not am: continue
                lockexpr = am.group(1).strip()
                sites.append({'line': i+1, 'kind': kind, 'lock': lockexpr,
                              'func': owner(i+1)})
        report[path] = {'funcs': funcs, 'sites': sites}
    with open(outpath, 'w') as f:
        json.dump(report, f)
    return report

if __name__ == '__main__':
    files_with_locks = json.load(open(sys.argv[1]))
    analyze(files_with_locks, sys.argv[2])
    print("done")
