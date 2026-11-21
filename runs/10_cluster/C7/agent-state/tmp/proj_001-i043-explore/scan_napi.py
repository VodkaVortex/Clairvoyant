import re, os, sys
napi_files = []
for dirpath, dirs, files in os.walk("."):
    if "/.git" in dirpath: continue
    for f in files:
        if f.endswith(".c"):
            p = os.path.join(dirpath, f)
            try: t = open(p, errors="ignore").read()
            except: continue
            if "netif_napi_add" in t:
                napi_files.append(p)
sys.stderr.write("napi files: %d\n" % len(napi_files))
results = []
for p in napi_files:
    t = open(p, errors="ignore").read()
    lines = t.split("\n")
    polls = []
    for i, ln in enumerate(lines):
        m = re.search(r"netif_napi_add\s*\([^;]*?,\s*([A-Za-z_0-9]+)\s*,\s*[0-9A-Za-z_]+", ln)
        if m: polls.append((m.group(1), i+1))
        else:
            # multi-line form: find name in following 6 lines
            if "netif_napi_add" in ln:
                seg = "\n".join(lines[i:i+7])
                m2 = re.search(r"netif_napi_add\s*\(\s*&[^,]+,\s*([A-Za-z_0-9]+)\s*,", seg)
                if m2: polls.append((m2.group(1), i+1))
    if not polls: continue
    for fn, ln in polls:
        m = re.search(r"(?:^|\n)[A-Za-z_0-9 \t\*]*\b%s\s*\(" % re.escape(fn), t)
        if not m: continue
        start = t.find(m.group(0)) + len(m.group(0))
        b = t.find("{", start)
        if b < 0: continue
        depth = 0
        for j in range(b, len(t)):
            c = t[j]
            if c == "{": depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0: break
        body = t[b:j+1]
        nl = t[:b].count("\n")
        plines = []
        bl = body.split("\n")
        for k, ln2 in enumerate(bl):
            if re.search(r"\bspin_lock\s*\(", ln2):
                plines.append((nl+k+1, ln2.strip()))
        if plines:
            results.append((p, fn, ln, plines, len(body.split("\n"))))
for r in sorted(results):
    print("%s | poll %s (add at %d) | %s" % (r[0], r[1], r[2], "; ".join("L%d %s" % (a,b) for a,b in r[3][:10])))
