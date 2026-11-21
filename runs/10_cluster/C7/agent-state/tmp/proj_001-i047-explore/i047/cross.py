import re, json, sys, collections, os

hl = json.load(open(sys.argv[1]))  # handler_locks.json
plain_api = {"spin_lock","spin_trylock","spin_lock_nested"}
targets = {}
for h in hl:
    for l in h["locks"]:
        if l["api"] in plain_api:
            targets.setdefault(h["path"], set()).add(l["lock"])

lock_res = re.compile(r'\b(spin_lock|spin_lock_irqsave|spin_lock_irq|spin_lock_bh|spin_trylock|spin_trylock_irqsave|spin_lock_nested|spin_lock_irqsave_nested|spin_lock_bh)\s*\(\s*&?\s*([^),]+)')

def norm(e): return re.sub(r'\s+','',e).strip().lstrip('&').rstrip()

def functions(path):
    lines = open(path, errors='replace').read().splitlines()
    # find function definition starts: line matching r'^[A-Za-z_].*\(' and next non-empty line ends with ')' or '{'
    funcs = []  # (name, start_line_idx)
    for i, l in enumerate(lines):
        m = re.match(r'^(?:static\s+|inline\s+|extern\s+|const\s+|unsigned\s+|struct\s+|enum\s+|[A-Za-z_][A-Za-z0-9_]*\s+)*([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
        if m and not l.lstrip().startswith(('if','for','while','switch','return','else','}')) and (l.endswith(')') or l.rstrip().endswith(',') or True):
            # heuristics: ensure not a call: previous line should end with ';' '}' '{' or '' 
            if i>0:
                prev = lines[i-1].rstrip()
                if prev and not prev.endswith((';','}','{','\\','*/',':')) and not prev.endswith(','):
                    continue
            else:
                continue
            # body must start with '{' within few lines
            j = i
            depth_p = 0
            found_open = False
            while j < len(lines) and j < i+15:
                depth_p += lines[j].count('(') - lines[j].count(')')
                if '{' in lines[j] and depth_p <= 0:
                    found_open = True
                    break
                if ';' in lines[j] and depth_p <= 0:
                    break
                j += 1
            if found_open:
                funcs.append((m.group(1), i))
    return lines, funcs

def enclosing(funcs, idx):
    best = None
    for name, start in funcs:
        if start <= idx:
            best = (name, start)
        else:
            break
    return best

out = {}
for path, locks in targets.items():
    try:
        lines, funcs = functions(path)
    except Exception as e:
        continue
    normlocks = {norm(x) for x in locks}
    sites = []
    for i, l in enumerate(lines):
        for m in lock_res.finditer(l):
            lk = norm(m.group(2))
            if lk in normlocks:
                encl = enclosing(funcs, i)
                sites.append({"line": i+1, "api": m.group(1), "lock": lk, "func": encl[0] if encl else "?", "code": l.strip()})
    out[path] = {"locks": sorted(normlocks), "sites": sites}

json.dump(out, open(sys.argv[2],"w"), indent=1)
print("files:", len(out))
