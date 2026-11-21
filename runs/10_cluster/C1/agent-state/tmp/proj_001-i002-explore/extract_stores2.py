import re, glob

roots = ["drivers/hwmon", "drivers/thermal"]
for root in roots:
    for path in glob.glob(root + "/**/*.c", recursive=True):
        try:
            src = open(path, errors="replace").read()
        except Exception:
            continue
        # collect all store function bodies (any signature)
        for m in re.finditer(r'\n(\w[\w\s\*]*?)\b(\w*_store)\s*\(', src):
            start = m.start()
            startline = src[:start].count("\n")
            body_m = re.search(r'\{', src[start:])
            if not body_m: continue
            bidx = start + body_m.start()
            depth = 0; i = bidx
            while i < len(src):
                if src[i] == '{': depth += 1
                elif src[i] == '}':
                    depth -= 1
                    if depth == 0: break
                i += 1
            if i - bidx > 4000: continue
            body = src[bidx:i+1]
            endline = src[:i].count("\n")
            nob = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
            nob = re.sub(r'//.*', '', nob)
            hits = []
            for ln in nob.split("\n"):
                # division: '/' preceded by non-'*' and non-space operator chars, followed by non-'/' 
                if re.search(r'[\w\)\]]\s*/\s*[\w\(]', ln) and '//' not in ln:
                    if re.search(r'\*/', ln) or ln.strip().startswith('*'): continue
                    if '#' in ln.split('/')[0] and 'include' in ln: continue
                    hits.append(ln.strip())
            if hits:
                print(f"=== {path} :: {m.group(2)} ({startline+1}-{endline+1})")
                for h in hits:
                    print(f"    {h}")
