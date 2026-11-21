import re, os, subprocess, sys

ROOT = "."
srcs = []
for top in ("drivers", "net"):
    for dirpath, dirnames, filenames in os.walk(top):
        for fn in filenames:
            if fn.endswith(".c"):
                srcs.append(os.path.join(dirpath, fn))

# tasklet callback names
tl_names = set()
pat_tl = re.compile(r'(?:tasklet_init|tasklet_setup)\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)')
pat_decl = re.compile(r'DECLARE_TASKLET[^ (]*\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)')
for f in srcs:
    try:
        t = open(f, errors='ignore').read()
    except OSError:
        continue
    for m in pat_tl.finditer(t):
        tl_names.add((f, m.group(1)))
    for m in pat_decl.finditer(t):
        tl_names.add((f, m.group(1)))

def func_body(text, name):
    # find definition: name( ... ) { ... }  (basic brace matcher, return start line)
    for m in re.finditer(re.escape(name) + r'\s*\(', text):
        # ensure it looks like a definition: preceding token is type or start
        start = m.start()
        pre = text[max(0, start-120):start]
        if re.search(r'[;{}]\s*$', pre) or pre.strip()=='' :
            pass
        # check next non-space char after matching paren is '{'
        i = m.end()-1
        depth = 0
        j = i
        while j < len(text):
            c = text[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        k = j+1
        while k < len(text) and text[k] in ' \t\r\n':
            k += 1
        if k < len(text) and text[k] == '{':
            # match braces
            d = 0
            p = k
            in_str = in_chr = in_lc = in_bc = False
            while p < len(text):
                c = text[p]
                if in_lc:
                    if c == '\n': in_lc = False
                elif in_bc:
                    if c == '*' and text[p+1:p+2] == '/': in_bc = False; p += 1
                elif in_str:
                    if c == '\\': p += 1
                    elif c == '"': in_str = False
                elif in_chr:
                    if c == '\\': p += 1
                    elif c == "'": in_chr = False
                else:
                    if c == '/' and text[p+1:p+2] == '/': in_lc = True
                    elif c == '/' and text[p+1:p+2] == '*': in_bc = True; p += 1
                    elif c == '"': in_str = True
                    elif c == "'": in_chr = True
                    elif c == '{': d += 1
                    elif c == '}':
                        d -= 1
                        if d == 0:
                            return text[k:p+1], text.count('\n', 0, k) + 1
                p += 1
    return None, None

results = []
for f, name in sorted(tl_names):
    try:
        text = open(f, errors='ignore').read()
    except OSError:
        continue
    body, line = func_body(text, name)
    if body is None:
        continue
    if re.search(r'\bspin_lock\s*\(', body) and not re.search(r'\bspin_lock_bh\s*\(|local_bh_disable\s*\(', body):
        locks = re.findall(r'spin_lock(?:_nested)?\s*\(\s*&?\s*([^),]+)', body)
        results.append((f, name, line, [l.strip() for l in locks]))

print("=== tasklet callbacks with plain spin_lock (no _bh/local_bh_disable in body) ===")
for f, name, line, locks in results:
    print(f"{f}: {name} (def line {line}) locks={locks}")
print(f"total: {len(results)}")
