#!/usr/bin/env python3
import os, re, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s07"
TMP = os.path.join(os.environ.get('TMPDIR','/tmp'), 'i051')

data = json.load(open(os.path.join(TMP, 'handler_locks.json')))
report = data['report']

re_spin_plain = re.compile(r'\bspin_lock\s*\(\s*([^);]+?)\s*\)')
re_spin_irq = re.compile(r'\bspin_lock_(?:irqsave|irq)\s*\(\s*([^);]+?)\s*,')

def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), text, flags=re.S)
    text = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group(0)), text)
    return text

rows = []
for rel, entries in report.items():
    path = os.path.join(ROOT, rel)
    raw = open(path, errors='replace').read()
    text = strip_comments(raw)
    # all plain spin_lock sites in file with line numbers
    plain_sites = []  # (line, lock)
    for m in re_spin_plain.finditer(text):
        line = text[:m.start()].count('\n') + 1
        plain_sites.append((line, m.group(1).strip()))
    irq_sites = []
    for m in re_spin_irq.finditer(text):
        line = text[:m.start()].count('\n') + 1
        irq_sites.append((line, m.group(1).strip()))
    for ent in entries:
        handler = ent['handler']
        info = ent['info']
        for lock, hline in info['plain_locks']:
            # normalize lock expression: strip leading & 
            lockn = lock.lstrip('&').strip()
            # count plain sites matching same expression elsewhere in file
            same_plain = [(l, lk) for (l, lk) in plain_sites if lk.lstrip('&').strip() == lockn]
            same_irq = [(l, lk) for (l, lk) in irq_sites if lk.lstrip('&').strip() == lockn]
            handler_sites = [(l, lk) for (l, lk) in plain_sites if lk.lstrip('&').strip() == lockn and info['body_line'] <= l <= info['body_line'] + 400]
            other_plain = [s for s in same_plain if not (info['body_line'] <= s[0] <= info['body_line']+400)]
            if len(same_plain) >= 2:
                rows.append({
                    'file': rel, 'handler': handler, 'lock': lockn,
                    'handler_line': info['body_line'],
                    'reg_lines': ent['reg_lines'],
                    'plain_sites': same_plain,
                    'irqsave_sites': same_irq,
                    'n_other_plain': len(other_plain),
                })

rows.sort(key=lambda r: (r['n_other_plain'], len(r['plain_sites'])), reverse=True)
with open(os.path.join(TMP, 'cross.tsv'), 'w') as f:
    for r in rows:
        f.write(f"{r['file']}\t{r['handler']}\t{r['lock']}\thline={r['handler_line']}\treg={r['reg_lines']}\tplain={[s[0] for s in r['plain_sites']]}\tirqsave={[s[0] for s in r['irqsave_sites']]}\tn_other={r['n_other_plain']}\n")
print(len(rows), "rows")
for r in rows[:60]:
    print(f"{r['file']} | {r['handler']} | {r['lock']} | plain={len(r['plain_sites'])} irqsave={len(r['irqsave_sites'])}")
