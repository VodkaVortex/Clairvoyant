import os, re, sys, json

root = 'snapshots/s09'
skip = {'Documentation','tools','samples','scripts','rust','usr'}

reg_pat = re.compile(r'\b(?:timer_setup|setup_timer|__setup_timer|DEFINE_TIMER)\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)')
fn_ptr_pat = re.compile(r'\.function\s*=\s*([A-Za-z_0-9]+)\s*,')
dw_pat = re.compile(r'\bINIT_DELAYED_WORK\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)')

registered = {}   # fname -> list of (file,line,kind)
files = []
for dirpath, dirnames, filenames in os.walk(root):
    if any(p in skip for p in dirpath.split(os.sep)):
        continue
    for fn in filenames:
        if fn.endswith('.c'):
            files.append(os.path.join(dirpath, fn))

for p in files:
    try:
        src = open(p, errors='replace').read()
    except OSError:
        continue
    for m in reg_pat.finditer(src):
        registered.setdefault(m.group(1), []).append((p, src[:m.start()].count('\n')+1, 'timer'))
    for m in fn_ptr_pat.finditer(src):
        registered.setdefault(m.group(1), []).append((p, src[:m.start()].count('\n')+1, 'fnptr'))
    for m in dw_pat.finditer(src):
        registered.setdefault(m.group(1), []).append((p, src[:m.start()].count('\n')+1, 'dwork'))

# Now find definitions of those functions in all files and scan bodies
defpat_cache = {}
results = []
for p in files:
    try:
        src = open(p, errors='replace').read()
    except OSError:
        continue
    lines = src.split('\n')
    # simple heuristic: look for "fname(" preceded by return type at line start
    for fname in registered:
        if fname not in src:
            continue
        pat = re.compile(r'(?:^|\n)((?:[A-Za-z_][A-Za-z_0-9 \t\*]*?)\b' + re.escape(fname) + r'\s*\([^;{]*\)\s*\{)', re.M)
        for dm in pat.finditer(src):
            i = src.find('{', dm.end()-1)
            if i == -1:
                continue
            depth = 0
            j = i
            while j < len(src):
                c = src[j]
                if c == '{': depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0: break
                j += 1
            body = src[i:j]
            has_plain = re.search(r'\bspin_lock\s*\(', body)
            has_bh = re.search(r'spin_lock_bh|local_bh_disable', body)
            if has_plain and not has_bh:
                line = src[:dm.start(1)].count('\n')+1
                results.append((fname, p, line, tuple(registered[fname]), src[i:j][:2000]))
            break

for fname, p, line, regs, body in results:
    print(f"=== {fname}  {p}:{line}  regs={list(regs)}")
print(f"\nTOTAL: {len(results)}")
