import re, sys, os, subprocess

root = "snapshots/s03" if False else "."
pull_re = re.compile(r'\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|__pskb_pull|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|skb_unclone|pskb_expand_head|skb_share_check)\s*\(')
# variables that look like pointers into skb data (pointer decl with * or casts)
cap_re = re.compile(r'^\s*(?:const\s+)?(?:struct\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?(?:skb|[^;]*skb|[^;]*skb->data|[^;]*skb_header_pointer[^;]*)', re.M)

def functions(src):
    """Yield (start_line, funcname, body) using brace matching, skipping comments/strings roughly."""
    # strip comments and strings while preserving newlines
    def clean(s):
        out = []
        i = 0
        n = len(s)
        in_lc = in_bc = in_str = in_chr = False
        while i < n:
            c = s[i]
            nxt = s[i+1] if i+1 < n else ''
            if in_lc:
                if c == '\n': out.append(c); in_lc = False
                i += 1; continue
            if in_bc:
                if c == '*' and nxt == '/': in_bc = False; i += 2; continue
                if c == '\n': out.append(c)
                i += 1; continue
            if in_str:
                if c == '\\': i += 2; continue
                if c == '"': in_str = False
                i += 1; continue
            if in_chr:
                if c == '\\': i += 2; continue
                if c == "'": in_chr = False
                i += 1; continue
            if c == '/' and nxt == '/': in_lc = True; i += 2; continue
            if c == '/' and nxt == '*': in_bc = True; i += 2; continue
            if c == '"': in_str = True; i += 1; continue
            if c == "'": in_chr = True; i += 1; continue
            out.append(c); i += 1
        return ''.join(out)
    s = clean(src)
    lines = s.split('\n')
    func_start_re = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    i = 0
    n = len(s)
    while i < n:
        # find next '{' at file scope approximation: track brace depth
        pass
    # simpler: iterate lines, find lines that look like func sig ending with '{'
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        m = re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*\(', line)
        if m and '{' in line:
            name = m.group(1)
            # collect until braces balance
            depth = line.count('{') - line.count('}')
            start = idx
            j = idx + 1
            while depth > 0 and j < len(lines):
                depth += lines[j].count('{') - lines[j].count('}')
                j += 1
            yield (start+1, name, '\n'.join(lines[start:j]))  # 1-based start line
            idx = j
        else:
            idx += 1

results = []
for dirpath, dirs, files in os.walk(root):
    if '/.git' in dirpath: continue
    for f in files:
        if not f.endswith('.c'): continue
        p = os.path.join(dirpath, f)
        try:
            src = open(p, errors='ignore').read()
        except: continue
        for (sl, name, body) in functions(src):
            plines = [(i+1, l) for i, l in enumerate(body.split('\n')) if pull_re.search(l)]
            if not plines: continue
            # find pointer captures
            caps = []
            for i, l in enumerate(body.split('\n')):
                m = re.match(r'\s*(?:const\s+)?(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+);', l)
                if m and re.search(r'skb|hdr|data|p\b', m.group(3)):
                    caps.append((sl+i, m.group(2), l.strip()))
            if len(plines) >= 1 and caps:
                results.append((p, sl, name, plines, caps))

for (p, sl, name, plines, caps) in results:
    print(f"=== {p}:{sl} {name}()")
    for (ln, l) in plines:
        print(f"  PULL l{sl+ln-1}: {l.strip()[:110]}")
    for (ln, var, l) in caps[:12]:
        print(f"  CAP  l{sl+ln-1}: {var} = {l[:110]}")
