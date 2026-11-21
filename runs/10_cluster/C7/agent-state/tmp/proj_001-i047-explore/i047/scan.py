import os, re, sys, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s04"
DIRS = ["drivers","net","sound","fs","kernel","mm","lib","security","block","ipc","virt","arch","samples","tools","init","crypto","firmware","usr"]

reg_re = re.compile(r'\b(request_irq|devm_request_irq|request_threaded_irq|devm_request_threaded_irq|request_percpu_irq|devm_request_any_context_irq)\s*\(')
funcdef_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\s*$')

def strip_comments(text):
    # keep line numbers: replace comment content with spaces
    text = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), text, flags=re.S)
    text = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group(0)), text)
    return text

lock_call_re = re.compile(r'\b(spin_lock|spin_lock_bh|spin_lock_irq|spin_lock_irqsave|spin_trylock|spin_trylock_bh|spin_trylock_irqsave|spin_unlock|spin_unlock_bh|spin_unlock_irq|spin_unlock_irqrestore|spin_lock_nested|spin_lock_irqsave_nested|read_lock|read_lock_irqsave|write_lock|write_lock_irqsave|_raw_spin_lock|_raw_spin_unlock|_raw_spin_lock_bh|_raw_spin_lock_irqsave)\s*\(')

results = []  # per file: registrations and lock call sites
for d in DIRS:
    base = os.path.join(ROOT, d)
    if not os.path.isdir(base): continue
    for dirpath, dirnames, filenames in os.walk(base):
        for fn in filenames:
            if not fn.endswith(('.c','.h')): continue
            p = os.path.join(dirpath, fn)
            try:
                src = open(p, encoding='utf-8', errors='replace').read()
            except Exception:
                continue
            if 'request_irq' not in src and 'request_threaded_irq' not in src:
                continue
            lines = src.split('\n')
            regs = []  # (line_no, macro, handler_expr, threaded)
            for i, ln in enumerate(lines):
                m = reg_re.search(ln)
                if not m: continue
                # handler is the 2nd arg for request_irq/devm; for threaded it's 3rd
                # grab a window of text to parse args
                j = i
                buf = ln
                while buf.count('(') > buf.count(')') and j+1 < len(lines) and j - i < 12:
                    j += 1
                    buf += '\n' + lines[j]
                args = buf[m.end():]
                depth = 0; cur = ''; arglist = []
                for ch in args:
                    if ch == '(': depth += 1; cur += ch
                    elif ch == ')':
                        if depth == 0: break
                        depth -= 1; cur += ch
                    elif ch == ',' and depth == 0:
                        arglist.append(cur); cur = ''
                    else: cur += ch
                arglist.append(cur)
                macro = m.group(1)
                threaded = 'threaded' in macro
                if threaded:
                    hidx = 2
                else:
                    hidx = 1
                if len(arglist) > hidx:
                    h = arglist[hidx].strip()
                    h = ' '.join(h.split())
                    regs.append((i+1, macro, h, threaded, j+1))
            if regs:
                results.append((os.path.relpath(p, ROOT), regs))

json.dump(results, open(os.environ['TMPDIR'] + '/i047/regs.json','w'))
print("files with registrations:", len(results))
print("total registrations:", sum(len(r) for _, r in results))
