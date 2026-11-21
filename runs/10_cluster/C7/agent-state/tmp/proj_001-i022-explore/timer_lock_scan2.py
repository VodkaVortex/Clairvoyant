#!/usr/bin/env python3
import re, os, json

BASE = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s07"

def read_file(p):
    with open(p, "r", errors="replace") as f:
        return f.read()

def func_spans(src):
    spans = {}
    for m in re.finditer(r'^([A-Za-z_][A-Za-z0-9_ \t\*&]*?)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', src, re.M):
        start = m.start(2)
        i = src.find('(', m.end(2)-1)
        if i < 0: continue
        depth = 0; j = i
        while j < len(src):
            c = src[j]
            if c == '(': depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0: break
            j += 1
        if depth != 0: continue
        k = j + 1
        while True:
            while k < len(src) and src[k] in ' \t\r\n': k += 1
            if src.startswith('/*', k):
                e = src.find('*/', k); k = e + 2 if e >= 0 else len(src)
            elif src.startswith('//', k):
                e = src.find('\n', k); k = e + 1 if e >= 0 else len(src)
            else:
                break
        if k >= len(src) or src[k] != '{': continue
        # strip comments/strings while brace-matching
        depth = 0; b = k; instr = False; cmt = 0
        while b < len(src):
            c = src[b]
            if cmt == 1:
                if src.startswith('*/', b): cmt = 0; b += 1
            elif cmt == 2:
                if c == '\n': cmt = 0
            elif instr:
                if c == '\\': b += 1
                elif c == '"': instr = False
            else:
                if src.startswith('/*', b): cmt = 1; b += 1
                elif src.startswith('//', b): cmt = 2
                elif c == '"': instr = True
                elif c == "'": 
                    # char literal
                    e = b + 1
                    while e < len(src) and src[e] != "'":
                        if src[e] == '\\': e += 1
                        e += 1
                    b = e
                elif c == '{': depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0: break
            b += 1
        name = m.group(2)
        if name in ('if','for','while','switch','return','sizeof','else','do','EXPORT_SYMBOL','module_param','DEFINE_SPINLOCK','DEFINE_TIMER'): continue
        line = src[:start].count('\n') + 1
        prev = spans.get(name)
        if prev is None or (b - start) > (prev[1] - prev[0]):
            spans[name] = (start, b, line)
    return spans

def lock_calls_in(src, a, b):
    out = []
    i = a
    # remove comments to avoid false matches
    seg = src[a:b]
    seg = re.sub(r'/\*.*?\*/', ' ', seg, flags=re.S)
    seg = re.sub(r'//[^\n]*', ' ', seg)
    off = a
    for m in re.finditer(r'\b(spin_lock|spin_unlock|spin_lock_irqsave|spin_unlock_irqrestore|spin_lock_bh|spin_unlock_bh|spin_lock_irq|spin_unlock_irq|spin_trylock|spin_trylock_bh)\s*\(', seg):
        j = m.end()
        depth = 1
        while j < len(seg) and depth > 0:
            if seg[j] == '(': depth += 1
            elif seg[j] == ')': depth -= 1
            j += 1
        arg = seg[m.end():j-1]
        first = arg.split(',')[0].strip().lstrip('&').strip()
        out.append((m.start()+off, m.group(1), first))
    return out

results = []
for root, dirs, files in os.walk(BASE):
    dirs[:] = [d for d in dirs if d not in ('.git',)]
    for fn in files:
        if not fn.endswith(('.c', '.h')): continue
        p = os.path.join(root, fn)
        try: src = read_file(p)
        except Exception: continue
        if not any(t in src for t in ('timer_setup','setup_timer','DEFINE_TIMER','hrtimer_init','.function')): continue
        timers = {}
        for m in re.finditer(r'timer_setup\s*\(\s*&?([A-Za-z0-9_>\.\-\[\]]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,', src):
            timers.setdefault(m.group(2), []).append(('timer_setup', src[:m.start()].count('\n')+1))
        for m in re.finditer(r'setup_timer\s*\(\s*&?([A-Za-z0-9_>\.\-\[\]]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,', src):
            timers.setdefault(m.group(2), []).append(('setup_timer', src[:m.start()].count('\n')+1))
        for m in re.finditer(r'DEFINE_TIMER\s*\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)', src):
            timers.setdefault(m.group(2), []).append(('DEFINE_TIMER', src[:m.start()].count('\n')+1))
        for m in re.finditer(r'\.function\s*=\s*([A-Za-z_][A-Za-z0-9_]*)', src):
            timers.setdefault(m.group(1), []).append(('.function=', src[:m.start()].count('\n')+1))
        if not timers: continue
        spans = func_spans(src)
        for cb, regs in timers.items():
            if cb not in spans: continue
            a, b, line = spans[cb]
            locks = lock_calls_in(src, a, b)
            plain = [(src[:p0].count('\n')+1, lk) for (p0, op, lk) in locks if op == 'spin_lock']
            other = [(src[:p0].count('\n')+1, op, lk) for (p0, op, lk) in locks if op != 'spin_lock']
            if not plain: continue
            rel = os.path.relpath(p, BASE)
            results.append({'file': rel, 'cb': cb, 'cb_line': line, 'n_regs': len(regs), 'regs': regs[:3],
                            'plain_locks': plain, 'other_ops': other[:6]})

print(json.dumps(results, indent=1))
