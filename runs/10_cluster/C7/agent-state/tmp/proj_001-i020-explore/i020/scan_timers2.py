import re, os

S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s05"
roots = ["drivers", "net"]

def func_body_and_start(src, name):
    ms = list(re.finditer(r'\b' + re.escape(name) + r'\s*\(', src))
    for m in ms:
        # check it's a definition: next non-space char after matching ')' is '{'
        depth = 0
        i = m.end()
        while i < len(src):
            c = src[i]
            if c == '(':
                depth += 1
            elif c == ')':
                if depth == 0:
                    break
                depth -= 1
            i += 1
        # skip whitespace
        j = i + 1
        while j < len(src) and src[j] in ' \t\n':
            j += 1
        if j < len(src) and src[j] == '{':
            start = j + 1
            depth = 1
            k = start
            while k < len(src) and depth > 0:
                c = src[k]
                if c == '{': depth += 1
                elif c == '}': depth -= 1
                k += 1
            line = src[:m.start()].count('\n') + 1
            return src[m.start():k], line
    return None, None

plain_lock = re.compile(r'\bspin_lock\s*\(')
lockarg = re.compile(r'spin_lock\s*\(\s*&?([^),]+)')

timer_files = []
for root in roots:
    for dirpath, _, files in os.walk(os.path.join(S, root)):
        for f in files:
            if f.endswith('.c'):
                p = os.path.join(dirpath, f)
                src = open(p, errors='replace').read()
                if ('timer_setup(' in src or 'setup_timer(' in src or 'DEFINE_TIMER' in src
                    or 'INIT_DELAYED_WORK' in src):
                    timer_files.append((p, src))

rows = []
for p, src in timer_files:
    cbs = set()
    for m in re.finditer(r'timer_setup\s*\(\s*[^,]+,\s*(\w+)\s*,', src):
        cbs.add(m.group(1))
    for m in re.finditer(r'setup_timer\s*\(\s*[^,]+,\s*(\w+)\s*,', src):
        cbs.add(m.group(1))
    for m in re.finditer(r'DEFINE_TIMER\s*\([^,]*,\s*(\w+)\s*,', src):
        cbs.add(m.group(1))
    # delayed_work struct member .work = func or INIT_DELAYED_WORK(&x, f)
    for m in re.finditer(r'INIT_DELAYED_WORK\s*\(\s*[^,]+,\s*(\w+)\s*\)', src):
        cbs.add(m.group(1))
    # hrtimer .function =
    for m in re.finditer(r'function\s*=\s*(\w+)\s*,', src):
        cbs.add(m.group(1))
    for cb in cbs:
        if cb in ('delayed_work_timer_fn',):
            continue
        body, line = func_body_and_start(src, cb)
        if body is None:
            continue
        if plain_lock.search(body):
            locks = sorted(set(lm.group(1).strip() for lm in lockarg.finditer(body)))
            rows.append((os.path.relpath(p, S), cb, line, locks))

for r in sorted(rows):
    print(f"{r[0]}\t{r[1]}\tline={r[2]}\t{','.join(r[3])}")
print(f"TOTAL: {len(rows)}")
