import re, os

root = os.getcwd()
# gather files with netif_napi_add
out = os.popen("/usr/bin/rg -l 'netif_napi_add' --type c drivers net").read()
files = [l.strip() for l in out.splitlines() if l.strip()]

for f in files:
    p = os.path.join(root, f)
    try:
        src = open(p, errors='replace').read()
    except Exception:
        continue
    # extract poll function names from netif_napi_add(..., func, ...)
    for m in re.finditer(r'netif_napi_add(?:_weight)?\s*\(', src):
        # parse args crudely: take up to matching paren, split by commas at depth 0
        i = m.end(); depth = 1; j = i
        while j < len(src) and depth:
            if src[j] == '(': depth += 1
            elif src[j] == ')': depth -= 1
            j += 1
        args = src[i:j-1]
        parts = re.split(r',(?![^()]*\))', args)
        if len(parts) >= 4:
            fn = parts[3].strip()
            fn = re.sub(r'[^A-Za-z_0-9]', '', fn)
            if not fn:
                continue
            dm = re.search(r'(?:^|\n)[A-Za-z_0-9 \*]+\b' + re.escape(fn) + r'\s*\(', src)
            if not dm:
                continue
            body = src[dm.end():dm.end()+4000]
            nxt = re.search(r'\n[A-Za-z_0-9 \*]+\([^;]*\)\s*\n\{', body)
            seg = body[:nxt.start()] if nxt else body[:3000]
            locks = re.findall(r'spin_lock\s*\(\s*([^)]+?)\s*\)', seg)
            if locks:
                line = src[:dm.end()].count('\n') + 1
                print(f"{f}:{line}: NAPI poll {fn} plain-locks {set(lock.strip() for lock in locks)}")
