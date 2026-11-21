import re, os

root = os.getcwd()
files = [l.strip() for l in open(os.environ['TMPDIR'] + '/timer_files.txt') if l.strip()]

def read(p):
    try:
        return open(os.path.join(root, p), errors='replace').read().splitlines()
    except Exception:
        return []

cb_map = {}
for f in files:
    lines = read(f)
    if not lines:
        continue
    joined = '\n'.join(lines)
    # handle multi-line setup_timer( ... ) via regex on joined text with offsets
    for m in re.finditer(r'(?:setup_timer|timer_setup)\s*\(\s*&?\s*(?:[A-Za-z_0-9>\.\[\]]+)?[\.\/]?\s*,?\s*', joined):
        pass
    # simpler: line-based plus continuation-aware approach
    i = 0
    n = len(lines)
    while i < n:
        # search across up to 6 lines joined
        chunk = '\n'.join(lines[i:i+6])
        m = re.search(r'(?:setup_timer|timer_setup)\s*\(\s*&[A-Za-z_0-9\.\>\[\]]*?[\.>]([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,', chunk)
        if not m:
            m2 = re.search(r'(?:setup_timer|timer_setup)\s*\(\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,', chunk)
            if m2 and 'timer' in lines[i] or (m2 and '_setup_timer' not in chunk.split('(')[0]):
                m = m2
        if m:
            cb = m.group(2)
            # find line number of the match start within chunk
            prefix = chunk[:m.start()]
            ln = i + 1 + prefix.count('\n')
            cb_map.setdefault((f, cb), []).append(ln)
            # advance past this registration
            i = ln
        else:
            i += 1

print("unique (file,callback):", len(cb_map))
with open(os.environ['TMPDIR'] + '/timer_callbacks2.txt', 'w') as out:
    for (f, cb), lns in sorted(cb_map.items()):
        out.write(f"{f}\t{cb}\t{','.join(map(str,sorted(set(lns))))}\n")
