import re, os, sys

S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s05"
roots = ["drivers", "net"]

# find candidate files containing timer_setup/setup_timer/DEFINE_TIMER/hrtimer function assignments
timer_files = []
for root in roots:
    for dirpath, _, files in os.walk(os.path.join(S, root)):
        for f in files:
            if f.endswith(('.c',)):
                p = os.path.join(dirpath, f)
                try:
                    src = open(p, errors='replace').read()
                except Exception:
                    continue
                if ('timer_setup(' in src or 'setup_timer(' in src or 'DEFINE_TIMER' in src
                    or 'hrtimer_init' in src or 'INIT_DELAYED_WORK' in src):
                        timer_files.append((p, src))

def func_body(src, name):
    # find definition: name(type args)\n{
    m = re.search(r'\b' + re.escape(name) + r'\s*\([^;{)]*\)\s*\{', src)
    if not m:
        # try name(...) possibly across lines
        m = re.search(r'\b' + re.escape(name) + r'\s*\([^;]*?\)\s*\{', src, re.S)
    if not m:
        return None
    start = m.end()  # after '{'
    depth = 1
    i = start
    while i < len(src) and depth > 0:
        c = src[i]
        if c == '{': depth += 1
        elif c == '}': depth -= 1
        i += 1
    return src[m.start():i]

plain_lock = re.compile(r'spin_lock\s*\(')
locks_taken = re.compile(r'spin_lock(?:_bh|_irqsave|_irq)?\s*\(\s*&?([^),]+)')

results = []
for p, src in timer_files:
    cbs = set()
    for m in re.finditer(r'timer_setup\s*\(\s*[^,]+,\s*(\w+)\s*,', src):
        cbs.add(('timer_list', m.group(1)))
    for m in re.finditer(r'setup_timer\s*\(\s*[^,]+,\s*(\w+)\s*,', src):
        cbs.add(('setup_timer', m.group(1)))
    for m in re.finditer(r'DEFINE_TIMER\s*\([^,]*,\s*(\w+)\s*,', src):
        cbs.add(('DEFINE_TIMER', m.group(1)))
    # hrtimer: .function = name
    for m in re.finditer(r'function\s*=\s*(\w+)\s*,', src):
        cbs.add(('hrtimer_fn', m.group(1)))
    for m in re.finditer(r'\.function\s*=\s*(\w+)', src):
        cbs.add(('dot_function', m.group(1)))
    # timer_list struct member: .function = name  (timer_list also uses .function)
    for kind, cb in cbs:
        if cb in ('delayed_work_timer_fn',):
            continue
        body = func_body(src, cb)
        if body is None:
            continue
        if plain_lock.search(body):
            # collect lock args and line number
            locknames = set()
            for lm in locks_taken.finditer(body):
                locknames.add(lm.group(1).strip())
            line = src[:body and src.find(body)].count('\n') + 1
            results.append((p, kind, cb, line, sorted(locknames)))

for r in sorted(results):
    rel = os.path.relpath(r[0], S)
    print(f"{rel}\t{r[1]}\t{r[2]}\tdefline~{r[3]}\tlocks={','.join(r[4])}")
