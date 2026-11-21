import re, json, os, sys, collections

handlers = json.load(open(sys.argv[1]))
root = sys.argv[2] if len(sys.argv)>2 else "."

# Load file line cache
filecache = {}
def get_lines(path):
    if path not in filecache:
        try:
            filecache[path] = open(path, errors='replace').read().splitlines()
        except Exception:
            filecache[path] = None
    return filecache[path]

# regex for lock acquisitions with lock arg
lock_re = re.compile(r'\b(spin_lock|spin_lock_irqsave|spin_lock_irq|spin_lock_bh|spin_trylock|spin_trylock_irqsave|spin_lock_nested|spin_lock_irqsave_nested)\s*\(\s*&?\s*([^),]+)')
read_lock_re = re.compile(r'\b(read_lock|write_lock)\(\s*&?\s*([^),]+)')
def expr_norm(e):
    return re.sub(r'\s+','',e).strip().lstrip('&')

out = []
miss = 0
for h in handlers:
    hexpr = h.get("handler_expr") or ""
    # handler must be a simple identifier (function name)
    name = expr_norm(hexpr)
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
        miss += 1
        continue
    # search for definition "static irqreturn_t name(" or "irqreturn_t name(" in same file
    lines = get_lines(h["path"])
    if lines is None:
        miss += 1; continue
    defline = None
    for idx, l in enumerate(lines):
        if re.search(r'\b'+re.escape(name)+r'\s*\(', l) and ('irqreturn_t' in l or 'static' in l or 'inline' in l):
            # crude definition detection
            if re.search(r'(?:^|\s)'+re.escape(name)+r'\s*\(', l) and not re.search(r'(?:&|\.)\s*'+re.escape(name)+r'\s*\(', l):
                defline = idx; break
    if defline is None:
        miss += 1; continue
    # find function body: from defline, find first '{' then match braces
    i = defline
    while i < len(lines) and '{' not in lines[i]:
        if ';' in lines[i]:
            break
        i += 1
    if i >= len(lines) or '{' not in lines[i]:
        miss += 1; continue
    depth = 0; started = False; body_start = i; body_end = None
    j = i
    while j < len(lines):
        depth += lines[j].count('{') - lines[j].count('}')
        if '{' in lines[j]: started = True
        if started and depth <= 0:
            body_end = j; break
        j += 1
    if body_end is None:
        miss += 1; continue
    body_lines = lines[body_start:body_end+1]
    locks = []
    for off, bl in enumerate(body_lines):
        for m in lock_re.finditer(bl):
            locks.append({"func": name, "line": body_start+off+1, "api": m.group(1), "lock": m.group(2).strip(), "code": bl.strip()})
        for m in read_lock_re.finditer(bl):
            locks.append({"func": name, "line": body_start+off+1, "api": m.group(1)+"?", "lock": m.group(2).strip(), "code": bl.strip()})
    if locks:
        out.append({"handler": name, "path": h["path"], "reg_line": h["line"], "api": h["api"],
                    "def_line": defline+1, "body": (body_start+1, body_end+1), "locks": locks})

json.dump(out, open(sys.argv[3] if len(sys.argv)>3 else "/dev/stdout","w"), indent=1)
print("handlers with locks:", len(out), "handler-name unresolved:", miss, file=sys.stderr)
