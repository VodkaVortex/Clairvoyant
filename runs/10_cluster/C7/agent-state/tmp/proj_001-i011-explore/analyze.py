import os, re, sys, json
from collections import defaultdict

def list_c_files(root):
    out = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            if f.endswith(('.c',)):
                out.append(os.path.join(dp, f))
    return out

FUNC_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(')

def parse_file(path):
    """Return dict funcname -> dict(file, start, end, body, header)."""
    with open(path, 'r', errors='replace') as f:
        src = f.read()
    lines = src.split('\n')
    funcs = {}
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = FUNC_RE.match(line)
        if m and not line.strip().startswith(('#', '//', '*', '/*')) and '=' not in line.split('(')[0]:
            # candidate definition: find '{' within next few lines and previous line not ending with ';'
            j = i
            hdr = line
            # gather until we find '{' or ';'
            k = i
            while k < n and '{' not in lines[k] and ';' not in lines[k]:
                k += 1
            if k < n and '{' in lines[k] and not lines[k].strip().startswith('else'):
                name = m.group(1)
                # skip control statements and macros
                if name in ('if','for','while','switch','return','sizeof','defined') or '__' == name[:2]:
                    i = k + 1
                    continue
                # brace matching
                depth = 0
                started = False
                e = k
                while e < n:
                    for ch in lines[e]:
                        if ch == '{':
                            depth += 1; started = True
                        elif ch == '}':
                            depth -= 1
                            if started and depth == 0:
                                break
                    if started and depth <= 0:
                        break
                    e += 1
                body = '\n'.join(lines[k:e+1])
                if name not in funcs:
                    funcs[name] = dict(file=path, start=i+1, end=e+1, body=body, header=hdr)
                i = e + 1
                continue
        i += 1
    return funcs

LOCK_RE = re.compile(r'spin_(lock|unlock|trylock|lock_bh|unlock_bh|lock_irq|unlock_irq|lock_irqsave|unlock_irqrestore|trylock_bh|lock_nested|lock_bh_nested|trylock_irqsave)\s*\(\s*([^;]*?)\s*[,)]')

def lock_acqs(body):
    res = []
    for m in LOCK_RE.finditer(body):
        kind = m.group(1)
        arg = re.sub(r'\s+', '', m.group(2))
        # cut at comma for irqsave (second arg is flags)
        res.append((kind, arg))
    return res

def norm(arg):
    return arg

def main(driver_roots, xmit_files):
    # parse all files
    funcs = {}
    for root in driver_roots:
        for f in list_c_files(root):
            for name, info in parse_file(f).items():
                if name not in funcs:
                    funcs[name] = info
    # find xmit entry functions
    entries = []
    for xf in xmit_files:
        try:
            src = open(xf, errors='replace').read()
        except OSError:
            continue
        for m in re.finditer(r'\.ndo_start_xmit\s*=\s*([A-Za-z_][A-Za-z0-9_]*)', src):
            entries.append(m.group(1))
    # build call graph: func -> set of called names
    allnames = set(funcs.keys())
    calls = {}
    for name, info in funcs.items():
        ids = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', info['body']))
        calls[name] = (ids & allnames)
    # BFS from entries
    reach = {}
    frontier = list(set(entries))
    seen = set(frontier)
    depth = {e: 0 for e in frontier}
    while frontier:
        cur = frontier.pop()
        for c in calls.get(cur, ()):
            if c not in seen:
                seen.add(c)
                depth[c] = depth[cur] + 1
                frontier.append(c)
    reach = seen
    # locks in xmit-reachable functions
    xmit_locks = defaultdict(list)
    for name in reach:
        info = funcs.get(name)
        if not info: continue
        for kind, arg in lock_acqs(info['body']):
            xmit_locks[arg].append((kind, info['file'], info['start'], name))
    # all lock sites
    all_locks = defaultdict(list)
    for name, info in funcs.items():
        for kind, arg in lock_acqs(info['body']):
            all_locks[arg].append((kind, info['file'], info['start'], name))
    print("ENTRIES:", entries)
    print("\n== Locks acquired in xmit-reachable functions ==")
    for arg, sites in sorted(xmit_locks.items()):
        plain_outside = [s for s in all_locks.get(arg, []) if s[3] not in reach and s[0] in ('lock','unlock','trylock','lock_nested')]
        print(f"\nLOCK {arg}")
        for kind, f, ln, fn in sites[:12]:
            print(f"   [xmit-reach d={depth.get(fn)}] {kind:14s} {os.path.relpath(f)}:{ln} in {fn}()")
        if plain_outside:
            print("   -- NOT-xmit-reachable acquisition sites (plain):")
            for kind, f, ln, fn in plain_outside[:12]:
                print(f"      [outside] {kind:14s} {os.path.relpath(f)}:{ln} in {fn}()")

if __name__ == '__main__':
    xmit_files = sys.argv[1].split(',')
    roots = sys.argv[2].split(',')
    main(roots, xmit_files)
