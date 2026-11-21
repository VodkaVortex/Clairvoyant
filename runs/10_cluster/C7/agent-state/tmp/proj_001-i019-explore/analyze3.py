import re, os

root = os.getcwd()
files = [l.strip() for l in open(os.environ['TMPDIR'] + '/timer_files.txt') if l.strip()]

def read(p):
    try:
        return open(os.path.join(root, p), errors='replace').read()
    except Exception:
        return ''

cb_map = {}
for f in files:
    text = read(f)
    if not text:
        continue
    # match setup_timer(&X.Y, cb, ...) or setup_timer(&X, cb, ...) or setup_timer(var, cb, ...)
    for m in re.finditer(r'\b(?:setup_timer|timer_setup)\s*\(([^;]*?)\)\s*;', text, re.S):
        args = m.group(1)
        first_comma = args.find(',')
        if first_comma < 0:
            continue
        first = args[:first_comma].strip()
        rest = args[first_comma+1:]
        second_comma = rest.find(',')
        if second_comma < 0:
            continue
        cb = rest[:second_comma].strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', cb):
            continue
        if cb in ('setup_timer', 'timer_setup'):
            continue
        # line number
        line = text[:m.start()].count('\n') + 1
        cb_map.setdefault((f, cb), []).append(line)

print("unique (file,callback):", len(cb_map))
with open(os.environ['TMPDIR'] + '/timer_callbacks3.txt', 'w') as out:
    for (f, cb), lns in sorted(cb_map.items()):
        out.write(f"{f}\t{cb}\t{','.join(map(str,sorted(set(lns))))}\n")
