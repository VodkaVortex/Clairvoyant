import re, sys, subprocess, os

root = os.getcwd()
files = [l.strip() for l in open(os.environ['TMPDIR'] + '/timer_files.txt') if l.strip()]

def read(p):
    try:
        return open(os.path.join(root, p), errors='replace').read().splitlines()
    except Exception:
        return []

results = []
for f in files:
    lines = read(f)
    if not lines:
        continue
    # find timer callback registrations: setup_timer(&t, cb, arg) / timer_setup(&t, cb, flags)
    for i, ln in enumerate(lines):
        m = re.search(r'(?:setup_timer|timer_setup)\s*\(\s*&(?:[A-Za-z_0-9>.]+\.)?([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,', ln)
        if m:
            results.append((f, i+1, m.group(2)))

# unique callback names per file
cb_map = {}
for f, ln, cb in results:
    cb_map.setdefault((f, cb), []).append(ln)

print("total timer registrations:", len(results))
print("unique (file,callback):", len(cb_map))
with open(os.environ['TMPDIR'] + '/timer_callbacks.txt', 'w') as out:
    for (f, cb), lns in sorted(cb_map.items()):
        out.write(f"{f}\t{cb}\t{','.join(map(str,lns))}\n")
