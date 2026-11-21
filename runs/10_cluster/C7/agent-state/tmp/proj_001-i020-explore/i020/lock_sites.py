import re, os, sys, glob

S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s05"

def load_funcs(src):
    """Return list of (name, start_line, end_line, is_static) via brace matching from line starts."""
    funcs = []
    lines = src.split('\n')
    # find function definitions at top level: line matching name(args) { or next line {
    pat = re.compile(r'^(?:static\s+|inline\s+|__always_inline\s+|const\s+|struct\s+\w+[\s\*]|unsigned\s+|int\s+|void\s+|long\s+|bool\s+|enum\s+\w+\s+|u\d+\s+|s\d+\s+|char\s+|[A-Za-z_][\w]*\s*\*?\s*)+?(\w+)\s*\(')
    i = 0
    n = len(lines)
    while i < n:
        m = pat.match(lines[i])
        if m and '{' in lines[i]:
            name = m.group(1)
            # brace count from this line to matching close
            depth = lines[i].count('{') - lines[i].count('}')
            j = i
            while depth > 0 and j < n - 1:
                j += 1
                depth += lines[j].count('{') - lines[j].count('}')
            funcs.append((name, i + 1, j + 1))
            i = j + 1
            continue
        i += 1
    return funcs

def enclosing(funcs, line):
    for name, s, e in funcs:
        if s <= line <= e:
            return name, s
    return None, None

lockre = re.compile(r'spin_lock(?:_bh|_irqsave|_irq|_irqrestore|_bh_restore)?\s*\(\s*&?([A-Za-z_][\w\.\->\[\]]*)')

def scan(paths, lockexpr, base):
    """find all lock acquisition sites of lockexpr regex in paths"""
    out = []
    pat = re.compile(r'spin_lock(?:_bh|_irqsave|_irq|_irqrestore)?\s*\(\s*&?\s*' + re.escape(lockexpr))
    for p in paths:
        src = open(p, errors='replace').read()
        funcs = load_funcs(src)
        for m in pat.finditer(src):
            line = src[:m.start()].count('\n') + 1
            fn, fs = enclosing(funcs, line)
            variant = 'bh' if '_bh' in m.group(0) else ('irqsave/irq' if re.search(r'_irq', m.group(0)) else 'plain')
            out.append((os.path.relpath(p, base), line, variant, fn))
    return out

if __name__ == '__main__':
    lockexpr = sys.argv[1]
    dirs = sys.argv[2:]
    paths = []
    for d in dirs:
        p = os.path.join(S, d)
        if os.path.isfile(p):
            paths.append(p)
        else:
            paths += glob.glob(os.path.join(p, '**', '*.c'), recursive=True)
            paths += glob.glob(os.path.join(p, '**', '*.h'), recursive=True)
    for r in scan(paths, lockexpr, S):
        print(f"{r[0]}:{r[1]}\t{r[2]}\t{r[3]}")
