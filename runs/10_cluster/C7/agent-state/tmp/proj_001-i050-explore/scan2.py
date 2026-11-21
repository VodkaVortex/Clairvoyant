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

KW = set('if for while switch return sizeof else do case'.split())

def scan_functions(lines):
    funcs = {}
    depth = 0
    pending = None
    cur_start = None
    n = len(lines)
    for i, l in enumerate(lines):
        if depth == 0:
            ls = l.strip()
            if ls and not ls.startswith('#') and '(' in l:
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
                    if m and m.group(1) not in KW:
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

def line_to_func(funcs, ln):
    for name,(s,e) in funcs.items():
        if s <= ln <= e:
            return (name, s, e)
    return None

if __name__ == '__main__':
    path = sys.argv[1]
    text = open(os.path.join(ROOT, path), encoding='utf-8', errors='replace').read()
    st = strip_comments_keep_lines(text)
    lines = st.split('\n')
    funcs = scan_functions(lines)
    json.dump(funcs, open(os.environ['TMPDIR']+'/funcs_test.json','w'))
    # verify braces balance
    bal = sum(l.count('{')-l.count('}') for l in lines)
    print("brace balance:", bal, "functions:", len(funcs))
    print("ring_msix:", funcs.get('ring_msix'))
