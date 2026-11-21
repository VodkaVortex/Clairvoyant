import re, os

root = os.getcwd()
out = os.popen("/usr/bin/rg -l 'netif_napi_add' --type c drivers net").read()
files = [l.strip() for l in out.splitlines() if l.strip()]
for f in files:
    p = os.path.join(root, f)
    try:
        src = open(p, errors='replace').read()
    except Exception:
        continue
    for m in re.finditer(r'netif_napi_add\s*\(', src):
        i = m.end(); depth = 1; j = i
        while j < len(src) and depth:
            if src[j] == '(': depth += 1
            elif src[j] == ')': depth -= 1
            j += 1
        args = src[i:j-1]
        # strip newlines and split top-level commas
        args = re.sub(r'\s+', ' ', args)
        parts, depth, cur = [], 0, ''
        for ch in args:
            if ch in '([': depth += 1
            elif ch in ')]': depth -= 1
            if ch == ',' and depth == 0:
                parts.append(cur.strip()); cur = ''
            else:
                cur += ch
        parts.append(cur.strip())
        if len(parts) >= 4:
            fn = re.sub(r'[^A-Za-z_0-9]', '', parts[3])
            if not fn or fn.isdigit():
                continue
            # find definition
            dm = re.search(r'\b' + re.escape(fn) + r'\s*\(\s*(?:struct\s+napi_struct|struct\s*napi_struct\s*\*)', src)
            if not dm:
                dm = re.search(r'(?:^|\n)[^\n]*\b' + re.escape(fn) + r'\s*\([^;]*\)\s*\{', src)
            if not dm:
                continue
            body = src[dm.end():dm.end()+5000]
            nxt = re.search(r'\n[A-Za-z_0-9 \*]+\([^;{}]*\)\s*\n\{', body)
            seg = body[:nxt.start()] if nxt else body[:4000]
            locks = re.findall(r'spin_lock\s*\(\s*([^)]+?)\s*\)', seg)
            if locks:
                line = src[:dm.start()].count('\n') + 1
                print(f"{f}:{line}: NAPI poll {fn} plain-locks {sorted(set(l.strip() for l in locks))}")
