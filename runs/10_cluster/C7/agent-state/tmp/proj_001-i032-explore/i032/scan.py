import re, os, subprocess, sys

SNAP = "snapshots/s03"
# files with tasklet schedule or napi in drivers/net, drivers/staging, net
files = subprocess.run(["rg","-l","tasklet_schedule|tasklet_hi_schedule|netif_napi_add|napi_schedule",SNAP,"-g","*.c"],capture_output=True,text=True).stdout.split()
# filter to relevant dirs
files = [f for f in files if "/drivers/net/" in f or "/drivers/staging/" in f or "/net/" in f or "/drivers/usb/" in f or "/drivers/atm/" in f or "/drivers/isdn/" in f or "/drivers/char/" in f]
print(len(files),"files", file=sys.stderr)

def find_funcs(src):
    # map function name -> (start,end)
    lines = src.split("\n")
    funcs = {}
    i = 0
    n = len(lines)
    while i < n:
        m = re.match(r'^[A-Za-z_][A-Za-z0-9_ \*\t]*\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', lines[i])
        if m and not lines[i].lstrip().startswith(("#","//","*","/*")) and not re.match(r'^(if|for|while|switch|return|sizeof|else)$', m.group(1)):
            name = m.group(1)
            # find opening brace at end of line or next lines
            j = i
            depth = 0
            started = False
            # look ahead up to 5 lines for '{'
            k = j
            found_brace = False
            while k < n and k <= j+6:
                if "{" in lines[k]:
                    found_brace = True
                    break
                if ";" in lines[k] and k > j:
                    break
                k += 1
            if not found_brace:
                i += 1
                continue
            # scan to matching brace
            p = k
            while p < n:
                for ch in lines[p]:
                    if ch == "{":
                        depth += 1; started = True
                    elif ch == "}":
                        depth -= 1
                        if started and depth == 0:
                            funcs[name] = (i, p)
                            break
                if name in funcs:
                    break
                p += 1
            if name in funcs:
                i = funcs[name][1] + 1
                continue
            i = k + 1
        else:
            i += 1
    return funcs, lines

def line_body(lines, rng):
    return "\n".join(lines[rng[0]:rng[1]+1])

def locks_in(body):
    # returns set of lock "names" acquired via spin_lock* in body
    names = set()
    for m in re.finditer(r'spin_lock(?:_irqsave|_irq|_bh|_nested|_irqsave_nested)?\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_\.\->\[\]]*)', body):
        names.add(m.group(1))
    return names

results = []
for f in files:
    try:
        src = open(f, errors="replace").read()
    except Exception:
        continue
    if "spin_lock" not in src:
        continue
    funcs, lines = find_funcs(src)
    if not funcs:
        continue
    # identify tasklet callback function names and napi poll names
    soft_funcs = set()
    for m in re.finditer(r'DECLARE_TASKLET(?:_OLD)?\s*\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)', src):
        soft_funcs.add(m.group(2))
    for m in re.finditer(r'tasklet_init\s*\([^;]*?', src):
        seg = m.group(0)
        m2 = re.search(r',\s*([A-Za-z_][A-Za-z0-9_]*)\s*,', src[m.end():m.end()+200])
        if m2: soft_funcs.add(m2.group(1))
    for m in re.finditer(r'tasklet_init\s*\(\s*&?[A-Za-z0-9_\.\->]+\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,', src):
        soft_funcs.add(m.group(1))
    for m in re.finditer(r'netif_napi_add(?:_exclusive|_dev)?\s*\([^,]*,[^,]*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,', src):
        soft_funcs.add(m.group(1))
    # old form: netif_napi_add(dev, &priv->napi, poll, weight) covered above
    if not soft_funcs:
        continue
    # gather locks in softirq functions
    soft_locks = {}
    for fn in soft_funcs:
        if fn in funcs:
            body = line_body(lines, funcs[fn])
            for lk in locks_in(body):
                soft_locks.setdefault(lk, fn)
    if not soft_locks:
        continue
    # find plain spin_lock( uses of those locks anywhere in file
    for lk, fn in soft_locks.items():
        # get base lock name: strip struct deref to last identifier
        base = re.split(r'[\.\->]', lk)[-1]
        for m in re.finditer(r'^.*spin_lock\s*\(\s*&?\s*([A-Za-z_][A-Za-z0-9_\.\->\[\]]*)', src, re.M):
            tgt = m.group(1)
            if tgt == lk or re.split(r'[\.\->]', tgt)[-1] == base and base not in ("lock","priv","dev","hw","port"):
                lineno = src[:m.start()].count("\n")+1
                # which function
                owner = None
                for fn2,(a,b) in funcs.items():
                    if a <= lineno-1 <= b:
                        owner = fn2; break
                results.append((f, lineno, lk, fn, tgt, owner, lines[lineno-1].strip()[:100]))

for r in results:
    print("|".join(str(x) for x in r))
