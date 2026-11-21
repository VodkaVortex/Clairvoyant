#!/usr/bin/env python3
import re, os, sys, json

BASE = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s07"

def read_file(p):
    with open(p, "r", errors="replace") as f:
        return f.read()

# find function definition ranges: name(args) { ... } at top level
func_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&\(\)#]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*?\)\s*$\n\{', re.M)

def func_spans(src):
    spans = {}
    for m in re.finditer(r'^([A-Za-z_][A-Za-z0-9_ \t\*&]*?)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', src, re.M):
        # check that this looks like start of a definition: matching paren then '{'
        start = m.start(2)
        i = src.find('(', m.end(2)-1)
        if i < 0: continue
        depth = 0
        j = i
        while j < len(src):
            c = src[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if depth != 0: continue
        # skip newlines/whitespace/comments to next non-space char
        k = j + 1
        # skip comments
        while True:
            while k < len(src) and src[k] in ' \t\r\n': k += 1
            if src.startswith('/*', k):
                e = src.find('*/', k)
                k = e + 2 if e >= 0 else len(src)
            elif src.startswith('//', k):
                e = src.find('\n', k)
                k = e + 1 if e >= 0 else len(src)
            else:
                break
        if k >= len(src) or src[k] != '{':
            continue
        # find matching brace
        depth = 0
        b = k
        instr = False
        while b < len(src):
            c = src[b]
            if instr:
                if c == '\\': b += 1
                elif c == '"': instr = False
            else:
                if c == '"': instr = True
                elif c == '{': depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0: break
            b += 1
        name = m.group(2)
        if name in ('if', 'for', 'while', 'switch', 'return', 'sizeof', 'else', 'do'):
            continue
        line = src[:start].count('\n') + 1
        prev = spans.get(name)
        if prev is None or (b - start) > (prev[1] - prev[0]):
            spans[name] = (start, b, line)
    return spans

lock_re = re.compile(r'\bspin_lock(?:_irqsave|_irq|_bh|_irqsave_nest_lock)?\s*\(\s*&?\s*([^,\)\s]+(?:\.[A-Za-z0-9_]+|->[A-Za-z0-9_]+)*)')

def lock_kinds_in(src, a, b):
    out = []
    for m in re.finditer(r'\bspin_lock(_irqsave|_irq|_bh)?\s*\(', src[a:b]):
        # capture the lock argument
        i = m.end()
        depth = 1
        j = i
        while j < len(src) and depth > 0:
            if src[j] == '(': depth += 1
            elif src[j] == ')': depth -= 1
            j += 1
        arg = src[i:j-1].strip()
        # strip flags arg
        if ',' in arg:
            arg = arg.split(',')[0].strip()
        arg = arg.lstrip('&').strip()
        out.append((m.start() + a, arg, m.group(1) or ''))
    return out

results = []
for root, dirs, files in os.walk(BASE):
    dirs[:] = [d for d in dirs if d not in ('.git',)]
    for fn in files:
        if not fn.endswith(('.c', '.h')): continue
        p = os.path.join(root, fn)
        try:
            src = read_file(p)
        except Exception:
            continue
        if 'timer_setup' not in src and 'setup_timer' not in src and 'DEFINE_TIMER' not in src and 'hrtimer_init' not in src and 'hrtimer_setup' not in src:
            continue
        # collect timer callback names
        timers = {}
        for m in re.finditer(r'timer_setup\s*\(\s*&?([A-Za-z0-9_>\.\-\[\]]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,', src):
            timers.setdefault(m.group(2), []).append(('timer_setup', src[:m.start()].count('\n')+1, m.group(0)[:80]))
        for m in re.finditer(r'setup_timer\s*\(\s*&?([A-Za-z0-9_>\.\-\[\]]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,', src):
            timers.setdefault(m.group(2), []).append(('setup_timer', src[:m.start()].count('\n')+1, m.group(0)[:80]))
        for m in re.finditer(r'DEFINE_TIMER\s*\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)', src):
            timers.setdefault(m.group(2), []).append(('DEFINE_TIMER', src[:m.start()].count('\n')+1, m.group(0)[:80]))
        for m in re.finditer(r'hrtimer_init\s*\(\s*&?([A-Za-z0-9_>\.\-\[\]]+)\s*,', src):
            pass
        for m in re.finditer(r'\.function\s*=\s*([A-Za-z_][A-Za-z0-9_]*)', src):
            timers.setdefault(m.group(1), []).append(('.function=', src[:m.start()].count('\n')+1, m.group(0)[:80]))
        if not timers: continue
        spans = func_spans(src)
        for cb, regs in timers.items():
            if cb not in spans: continue
            a, b, line = spans[cb]
            body = src[a:b]
            locks = lock_kinds_in(src, a, b)
            locks = [(p0, lk, kind) for (p0, lk, kind) in locks]
            if not locks: continue
            # plain locks only
            plain = [(p0, lk) for (p0, lk, kind) in locks if kind == '']
            if not plain: continue
            rel = os.path.relpath(p, BASE)
            results.append({'file': rel, 'cb': cb, 'cb_line': line, 'regs': regs,
                            'plain_locks': [(src[:p0].count('\n')+1, lk) for (p0, lk) in plain],
                            'other_locks': [(src[:p0].count('\n')+1, lk, kind) for (p0, lk, kind) in locks if kind != '']})

print(json.dumps(results, indent=1))
