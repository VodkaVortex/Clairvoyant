import re, os

root = os.getcwd()
out = os.popen("/usr/bin/rg -l 'netif_napi_add' --type c drivers net").read()
files = [l.strip() for l in out.splitlines() if l.strip()]
count=0
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
        parts = [x.strip() for x in args.split(',')]
        if len(parts) >= 4:
            fn = re.sub(r'[^A-Za-z_0-9]', '', parts[3])
            if not fn:
                continue
            dm = re.search(r'\b' + re.escape(fn) + r'\s*\(', src)
            if not dm:
                continue
            line = src[:dm.start()].count('\n') + 1
            count+=1
            print(f"{f}:{line}: napi poll fn {fn}")
print("total", count)
