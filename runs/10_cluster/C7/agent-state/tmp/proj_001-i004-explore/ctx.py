import re, sys
path, var = sys.argv[1], sys.argv[2]
src = open(path, errors="ignore").read()
lines = src.split("\n")
# collect function definition start lines (col 0, C definition style)
defs = []
for i, l in enumerate(lines):
    m = re.match(r'^(?:static\s+|inline\s+|const\s+|unsigned\s+|struct\s+[A-Za-z0-9_]+\s*\*?\s*)*[A-Za-z_][A-Za-z0-9_]*[\s\*]+([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
    if m and not l.startswith(("if","for","while","switch","return","}","else")) and not l.lstrip().startswith(("*","/")):
        defs.append((i, m.group(1)))
defs.sort()
import bisect
starts = [d[0] for d in defs]
for i, l in enumerate(lines):
    if re.search(r"spin_lock\(&" + re.escape(var), l):
        k = bisect.bisect_right(starts, i) - 1
        fn = defs[k][1] if k >= 0 else "?"
        print(f"{i+1}: {fn}: {l.strip()}")
