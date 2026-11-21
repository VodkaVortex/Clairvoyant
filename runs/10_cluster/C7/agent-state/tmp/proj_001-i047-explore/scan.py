import re, os, json, collections

root = "."
tdir = os.environ["TMPDIR"]

handler_names = set()
# (file, line, handler, register_kind)
regs = []

def add(path, line, h, kind):
    regs.append((path, line, h, kind))
    handler_names.add(h)

pat_ri = re.compile(r'\b(?:devm_)?request_irq\s*\(\s*([^,]+?),\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
pat_rti = re.compile(r'\brequest_threaded_irq\s*\(\s*([^,]+?),\s*([^,]+?),\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')

for dirpath, dirs, files in os.walk(root):
    for f in files:
        if not (f.endswith('.c') or f.endswith('.h')):
            continue
        p = os.path.join(dirpath, f)
        try:
            with open(p, errors='replace') as fh:
                lines = fh.readlines()
        except Exception:
            continue
        for i, ln in enumerate(lines, 1):
            for m in pat_ri.finditer(ln):
                kind = 'devm' if 'devm_' in ln[:m.start()+10] else 'plain'
                add(p, i, m.group(2), kind)
            for m in pat_rti.finditer(ln):
                add(p, i, m.group(3), 'threaded_primary')

# also plain request_irq with 'devm_' prefix check done crudely
with open(os.path.join(tdir, "registrations.tsv"), "w") as out:
    for path, line, h, kind in regs:
        out.write(f"{path}\t{line}\t{h}\t{kind}\n")

# map handler name -> definition file(s) via ctags-ish regex
definitions = collections.defaultdict(list)
pat_def = re.compile(r'\bstatic\s+[^;{}]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*$')
c_files = []
for dirpath, dirs, files in os.walk(root):
    for f in files:
        if f.endswith('.c'):
            c_files.append(os.path.join(dirpath, f))

for p in c_files:
    try:
        with open(p, errors='replace') as fh:
            lines = fh.readlines()
    except Exception:
        continue
    for i, ln in enumerate(lines, 1):
        s = ln.rstrip('\n')
        if 'static' in s and '(' in s and not s.lstrip().startswith('*') and not s.lstrip().startswith('//'):
            m = re.search(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', s)
            if m and m.group(1) in handler_names:
                definitions[m.group(1)].append((p, i))

with open(os.path.join(tdir, "handler_defs.json"), "w") as out:
    json.dump({k: v for k, v in definitions.items()}, out, indent=0)

print("registrations:", len(regs))
print("unique handlers:", len(handler_names))
print("handlers with defs:", len(definitions))
