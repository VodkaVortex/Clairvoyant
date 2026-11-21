import re, os, sys, hashlib

root = '.'
results = []

func_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\(')  # rough
get_re = re.compile(r'(?:__)?(?:get_user|get_user_unaligned)\s*\(\s*[^,]+,\s*(.+?)\s*\)\s*;')
cfu_re = re.compile(r'(?:__)?copy_from_user\s*\(\s*[^,]+,\s*([^,]+),\s*([^,)]+)\s*\)')

for dirpath, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in ('.git',)]
    for fn in files:
        if not fn.endswith('.c'):
            continue
        path = os.path.join(dirpath, fn)
        if path.startswith(('./tools/', './samples/', './Documentation/')):
            continue
        try:
            lines = open(path, errors='ignore').read().split('\n')
        except Exception:
            continue
        # naive function segmentation: track brace depth; record start line
        depth = 0
        func_start = None
        func_header = None
        buf = []
        def flush(buf, func_header, func_start, path):
            if not buf: return
            text = '\n'.join(buf)
            # get_user duplicated target
            targets = {}
            for m in get_re.finditer(text):
                t = re.sub(r'\s+', '', m.group(1))
                targets.setdefault(t, []).append(func_start + text[:m.start()].count('\n'))
            for t, ls in targets.items():
                if len(ls) > 1:
                    results.append((path, func_start, func_header.strip(), 'get_user dup', t, ls))
            # copy_from_user duplicated source
            srcs = {}
            for m in cfu_re.finditer(text):
                t = re.sub(r'\s+', '', m.group(1)) + '|' + re.sub(r'\s+','',m.group(2))
                srcs.setdefault(t, []).append(func_start + text[:m.start()].count('\n'))
            for t, ls in srcs.items():
                if len(ls) > 1:
                    results.append((path, func_start, func_header.strip(), 'copy_from_user dup', t, ls))
        i = 0
        for idx, line in enumerate(lines):
            o = len(line) - len(line.lstrip())
            if depth == 0 and o == 0 and '(' in line and not line.strip().startswith(('#', '}', '/', '*', '//')) and not line.strip().endswith(';'):
                # candidate function header line
                func_header = line
                func_start = idx + 1
            if depth == 0 and line.strip().endswith(';') and buf:
                flush(buf, func_header, func_start, path); buf = []
            depth += line.count('{') - line.count('}')
            if depth > 0 and func_header is not None and func_start is not None and idx + 1 >= func_start:
                buf.append(line)
            if depth == 0 and buf:
                flush(buf, func_header, func_start, path); buf = []
                func_header = None; func_start = None
        if buf:
            flush(buf, func_header, func_start, path)

for r in results:
    path, fs, fh, kind, tgt, ls = r
    print(f"{path}:{ls[0]},{ls[-1]}|{kind}|{tgt[:80]}|{fh[:70]}")
