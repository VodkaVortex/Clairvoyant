import os, re, sys

root = '.'
# collect registrations: timer_setup(&x->t, fn, ...), setup_timer(&x->t, fn, arg), DEFINE_TIMER(name, fn), .function = fn
reg_pat = re.compile(r'(?:timer_setup|setup_timer|DEFINE_TIMER|mod_timer_pinned|__setup_timer)\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)')
fn_ptr_pat = re.compile(r'\.function\s*=\s*([A-Za-z_0-9]+)')
hrtimer_pat = re.compile(r'(?:hrtimer_init|HRTIMER_MODE)[^\n]*', )
dw_pat = re.compile(r'INIT_DELAYED_WORK\s*\(\s*[^,]+,\s*([A-Za-z_0-9]+)')
timer_var_pat = re.compile(r'(?:timer_setup|setup_timer|__setup_timer)\s*\(\s*&?\s*([A-Za-z_0-9\.\->\-]+)\s*,')

targets = {}  # fn -> (file, line, regtype)

for dirpath, dirnames, filenames in os.walk(root):
    # skip some trees to bound effort
    if any(part in ('Documentation','tools','samples','scripts','rust','usr') for part in dirpath.split(os.sep)):
        continue
    for fn in filenames:
        if not fn.endswith('.c'):
            continue
        p = os.path.join(dirpath, fn)
        try:
            with open(p, 'r', errors='replace') as f:
                src = f.read()
        except OSError:
            continue
        for m in reg_pat.finditer(src):
            targets.setdefault(m.group(1), []).append((p, src[:m.start()].count('\n')+1, 'timer_setup'))
        for m in fn_ptr_pat.finditer(src):
            targets.setdefault(m.group(1), []).append((p, src[:m.start()].count('\n')+1, '.function='))
        for m in dw_pat.finditer(src):
            targets.setdefault(m.group(1), []).append((p, src[:m.start()].count('\n')+1, 'delayed_work'))

results = []
for fn, regs in sorted(targets.items()):
    # find definition in any file
    for dirpath, dirnames, filenames in os.walk(root):
        if any(part in ('Documentation','tools','samples','scripts','rust','usr') for part in dirpath.split(os.sep)):
            continue
        for f2 in filenames:
            if not f2.endswith('.c'):
                continue
            p = os.path.join(dirpath, f2)
            try:
                with open(p, 'r', errors='replace') as fh:
                    src = fh.read()
            except OSError:
                continue
            # find function definition
            defpat = re.compile(r'(?:^|\n)[ \t]*(?:static\s+)?(?:void|int|enum\s+\w+|unsigned\s+long|u32|bool)[ \t\n]+' + re.escape(fn) + r'\s*\(', re.M)
            for dm in defpat.finditer(src):
                start = dm.start()
                # extract body: naive brace matching
                i = src.find('{', dm.end())
                if i == -1: continue
                depth = 0
                j = i
                while j < len(src):
                    c = src[j]
                    if c == '{': depth += 1
                    elif c == '}':
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                body = src[i:j]
                line = src[:dm.start()].count('\n') + 1
                has_plain = re.search(r'\bspin_lock\s*\(', body)
                has_bh = re.search(r'spin_lock_bh|local_bh_disable', body)
                if has_plain and not has_bh:
                    results.append((fn, p, line, regs))
                break  # only first def
        # note: walking whole tree per fn is slow; break after found? we can't easily know; but we scan everything each time - too slow. Restructure.
# Too slow approach; but let's just print results found so far
for fn, p, line, regs in results:
    print(f"{fn}\t{p}:{line}\t{regs}")
