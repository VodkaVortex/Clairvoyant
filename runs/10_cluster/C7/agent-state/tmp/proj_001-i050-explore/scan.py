import re, json, os, sys
from collections import defaultdict

ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s06'

def strip_comments_keep_lines(text):
    """Replace comments with spaces, preserving newlines and string literals crudely."""
    out = []
    i = 0
    n = len(text)
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
            out.append(' ' * (j-i))
            i = j
        elif c == '"':
            j = i+1
            while j < n and text[j] != '"':
                if text[j] == '\\': j += 1
                j += 1
            out.append(text[i:j+1]); i = j+1
        elif c == "'":
            j = i+1
            while j < n and text[j] != "'":
                if text[j] == '\\': j += 1
                j += 1
            out.append(text[i:j+1]); i = j+1
        else:
            out.append(c); i += 1
    return ''.join(out)

FUNC_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(')

def scan_functions(lines):
    """Return dict name -> (start_line, end_line) for file-scope function definitions."""
    funcs = {}
    depth = 0
    cur_start = None
    pending_name = None
    i = 0
    n = len(lines)
    while i < n:
        l = lines[i]
        if depth == 0:
            ls = l.strip()
            if ls and not ls.startswith('#') and '(' in l and not ls.startswith(('typedef','static_assert')):
                # candidate signature start
                # look ahead up to ~10 lines for '{' before ';'
                j = i
                buf = ''
                found = None
                while j < n and j < i+12:
                    buf += lines[j]
                    # find first '{' after the paren depth returns to 0
                    pd = buf.count('(') - buf.count(')')
                    if pd <= 0 and '{' in lines[j]:
                        found = j; break
                    if pd <= 0 and ';' in lines[j]:
                        break
                    j += 1
                if found is not None:
                    # extract name: last identifier before the first '(' in buf up to found line
                    head = buf[:buf.find('(')]
                    m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', head)
                    if m:
                        name = m.group(1)
                        if name not in ('if','for','while','switch','return','sizeof','else'):
                            cur_start = i
                            pending_name = name
        # count braces
        for ch in l:
            if ch == '{':
                if depth == 0 and pending_name and cur_start == i:
                    pass
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0 and pending_name is not None:
                    funcs[pending_name] = (cur_start+1, i+1)
                    pending_name = None
                    cur_start = None
                if depth < 0: depth = 0
        i += 1
    return funcs

# testing on one file
if __name__ == '__main__':
    p = sys.argv[1]
    text = open(os.path.join(ROOT, p), encoding='utf-8', errors='replace').read()
    st = strip_comments_keep_lines(text)
    assert st.count('\n') == text.count('\n'), (st.count('\n'), text.count('\n'))
    lines = st.split('\n')
    funcs = scan_functions(lines)
    for name,(s,e) in sorted(funcs.items(), key=lambda kv: kv[1][0]):
        print(name, s, e)
