import os, re, subprocess, json, sys

root = os.getcwd()
tmp = os.environ['TMPDIR']

# find all plain lock/unlock acquisition sites with enclosing function + file
plain = re.compile(r'^[ \t]*(?:spin_lock|spin_lock_bh)\s*\(', re.M)

files = subprocess.run(['find', root, '-name', '*.c'], capture_output=True, text=True).stdout.split('\n')
files = [f for f in files if f]

funcdef_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)\)\s*\{', re.M)

# Build index: file -> list of (funcname, start, end, startline)
file_index = {}
for path in files:
    try:
        text = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        continue
    rel = os.path.relpath(path, root)
    spans = []
    for m in funcdef_re.finditer(text):
        i = m.end() - 1
        depth = 0
        j = i
        n = len(text)
        ok = True
        while j < n:
            c = text[j]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    break
            elif c == '"' or c == "'":
                q = c; j += 1
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
                    ok = False; break
            j += 1
        if ok and depth == 0 and j < n:
            spans.append((m.start(), j+1, m.group(1)))
    if spans:
        file_index[rel] = (text, spans)

json.dump({k: v[1] for k, v in file_index.items()}, open(os.path.join(tmp, 'i046_filespans.json'), 'w'))
print('indexed %d files' % len(file_index), file=sys.stderr)
