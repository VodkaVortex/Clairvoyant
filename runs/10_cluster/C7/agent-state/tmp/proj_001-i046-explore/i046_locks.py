import os, re, subprocess, json, sys
from collections import defaultdict

root = os.getcwd()
tmp = os.environ['TMPDIR']

handlers = json.load(open(os.path.join(tmp, 'i046_handlers.json')))

files = subprocess.run(['find', root, '-name', '*.c'], capture_output=True, text=True).stdout.split('\n')
files = [f for f in files if f]

# Parse functions per file: name -> (start_idx_of_body, body, line)
func_start = re.compile(r'(?:^|\n)((?:[A-Za-z_][A-Za-z0-9_]*[ \t\n]+|[ \t\*])*?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\([^;{)]*\)[ \t\n]*)(?:\n|\s)*\{')

file_funcs = {}   # relpath -> {name: (body, start_line)}
file_text = {}

funcdef_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)\)\s*\{', re.M)

for path in files:
    try:
        text = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        continue
    rel = os.path.relpath(path, root)
    funcs = {}
    for m in funcdef_re.finditer(text):
        name = m.group(1)
        # brace match
        i = m.end() - 1
        depth = 0
        j = i
        n = len(text)
        while j < n:
            c = text[j]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    break
            elif c == '"' or c == "'":
                # skip string/char
                q = c
                j += 1
                while j < n and text[j] != q:
                    if text[j] == '\\':
                        j += 1
                    j += 1
            elif text[j:j+2] == '//':
                while j < n and text[j] != '\n':
                    j += 1
            elif text[j:j+2] == '/*':
                j = text.find('*/', j)
                if j < 0:
                    break
            j += 1
        if depth == 0 and j < n:
            body = text[m.end():j]
            line = text.count('\n', 0, m.start()) + 1
            funcs.setdefault(name, (body, line))
    if funcs:
        file_funcs[rel] = funcs
        file_text[rel] = text

print('parsed %d files with functions' % len(file_funcs), file=sys.stderr)

lock_call = re.compile(r'\b(spin_lock|spin_lock_bh|spin_lock_irq|spin_lock_irqsave|spin_trylock|spin_trylock_bh|spin_trylock_irq|spin_trylock_irqsave|read_lock|read_lock_bh|read_lock_irqsave|write_lock|write_lock_bh|write_lock_irqsave)\s*\(')
arg_extract = re.compile(r'\(([^()]*(?:\([^()]*\)[^()]*)*)\)')

# For each handler, gather lock acquisitions in body + same-file callees (depth<=3)
handler_locks = {}  # handler -> list of (lockexpr, flavor, where)

call_re = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')

def locks_in(body, rel, funcs, depth, seen):
    res = []
    if depth > 3:
        return res
    for m in lock_call.finditer(body):
        # extract first arg after paren (may have nested parens - use manual scan)
        i = body.index('(', m.end()-1)
        depthp = 0
        cur = []
        j = i
        n = len(body)
        while j < n:
            c = body[j]
            if c == '(':
                depthp += 1
                if depthp == 1:
                    j += 1; continue
            elif c == ')':
                depthp -= 1
                if depthp == 0:
                    break
            elif c == ',' and depthp == 1:
                break
            if depthp >= 1:
                cur.append(c)
            j += 1
        expr = ''.join(cur).strip()
        line = body.count('\n', 0, m.start()) + 1
        res.append((expr, m.group(1), line))
    # recurse into same-file callees
    callees = set(call_re.findall(body))
    for c in callees:
        if c in seen or c not in funcs:
            continue
        seen2 = seen | {c}
        sub_body, sub_line = funcs[c]
        for (expr, fl, line) in locks_in(sub_body, rel, funcs, depth+1, seen2):
            res.append((expr, fl, c))
    return res

for hname, rels in handlers.items():
    for rel in rels:
        funcs = file_funcs.get(rel)
        if not funcs or hname not in funcs:
            continue
        body, line = funcs[hname]
        got = locks_in(body, rel, funcs, 0, {hname})
        if got:
            handler_locks.setdefault(hname, []).append({'file': rel, 'handler_line': line, 'locks': [{'expr': e, 'flavor': f, 'where': w} for (e, f, w) in got]})

json.dump(handler_locks, open(os.path.join(tmp, 'i046_handler_locks.json'), 'w'), indent=1)
print('handlers with locks (direct+nested same-file):', len(handler_locks), file=sys.stderr)
