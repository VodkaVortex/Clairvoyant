import re, glob

roots = ["drivers/hwmon", "drivers/thermal"]
for root in roots:
    for path in glob.glob(root + "/**/*.c", recursive=True):
        try:
            src = open(path, errors="replace").read()
        except Exception:
            continue
        for m in re.finditer(r'^static\s+(?:ssize_t|int|void)\s+(\w*_store)\s*\(', src, re.M):
            start = m.start()
            startline = src[:start].count("\n")
            body_m = re.search(r'\{', src[start:])
            if not body_m: continue
            bidx = start + body_m.start()
            depth = 0
            i = bidx
            while i < len(src):
                if src[i] == '{': depth += 1
                elif src[i] == '}':
                    depth -= 1
                    if depth == 0: break
                i += 1
            body = src[bidx:i+1]
            endline = src[:i].count("\n")
            nob = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
            nob = re.sub(r'//.*', '', nob)
            hits = []
            for ln in nob.split("\n"):
                if re.search(r'[^/*\s]\s*/\s*[^/*=]', ln) or re.search(r'[^=!\s]\s*%\s*\w', ln):
                    if '*/' in ln: continue
                    hits.append(ln.strip())
            if hits:
                print(f"=== {path} :: {m.group(1)} ({startline+1}-{endline+1})")
                for h in hits:
                    print(f"    {h}")
