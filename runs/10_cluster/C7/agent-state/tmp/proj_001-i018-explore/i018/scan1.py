import re, os, sys, json, collections

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"
EXCLUDE_DIRS = ("drivers/staging/ks7010",)  # seed driver: never report

# 1. collect C files
cfiles = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    rel = os.path.relpath(dirpath, ROOT)
    if rel.startswith("tools") or rel.startswith("Documentation") or rel.startswith("scripts") or rel.startswith("samples") or rel.startswith("usr"):
        dirnames[:] = []
        continue
    for f in filenames:
        if f.endswith(".c"):
            cfiles.append(os.path.join(rel, f))
print("cfiles:", len(cfiles), file=sys.stderr)

func_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*$')
lock_res = [
    re.compile(r'\bspin_lock\s*\(\s*(.*?)\s*\)'),
    re.compile(r'\bspin_lock_irqsave\s*\(\s*(.*?),'),
    re.compile(r'\bspin_lock_irq\s*\(\s*(.*?)\s*\)'),
    re.compile(r'\bspin_lock_bh\s*\(\s*(.*?)\s*\)'),
]

# parse functions: naive brace matching
functions = {}  # name -> list of (file, startline, body)
locksites = []  # (file, line, kind, lockexpr, funcname)
cur = None

def parse_file(path):
    try:
        with open(os.path.join(ROOT, path), errors='replace') as fh:
            lines = fh.readlines()
    except Exception:
        return
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = func_re.match(line.rstrip())
        if m and not line.lstrip().startswith(("#", "//", "*", "/*", "return", "if", "for", "while", "switch", "else", "EXPORT")):
            name = m.group(1)
            # find opening brace within next few lines
            j = i
            depth = 0
            started = False
            # skip to first '{'
            k = i
            while k < n and '{' not in lines[k] and k < i + 6:
                # abort if ';' appears (prototype)
                if ';' in lines[k]:
                    break
                k += 1
            if k < n and '{' in lines[k]:
                # count depth from k
                d = 0
                p = k
                while p < n:
                    d += lines[p].count('{') - lines[p].count('}')
                    if d == 0 and p >= k:
                        break
                    p += 1
                body = "".join(lines[i:p+1])
                functions.setdefault(name, []).append((path, i+1, body, i+1, p+1))
                i = p + 1
                continue
        i += 1

for cf in cfiles:
    parse_file(cf)
print("functions:", len(functions), file=sys.stderr)

# now find lock sites per function
for name, defs in functions.items():
    for (path, startline, body, _s, _e) in defs:
        for ln_no, ln in enumerate(body.split("\n")):
            for ridx, r in enumerate(lock_res):
                m = r.search(ln)
                if m:
                    kind = ["plain","irqsave","irq","bh"][ridx]
                    lockexpr = m.group(1)
                    locksites.append((path, startline+ln_no, kind, lockexpr, name))
                    break
print("locksites:", len(locksites), file=sys.stderr)

with open(os.path.join(os.environ.get("TMPDIR","/tmp"), "i018", "functions.json"), "w") as f:
    json.dump({k: [(p,s,e1,e2) for (p,s,b,e1,e2) in v] for k,v in list(functions.items())}, f)
with open(os.path.join(os.environ.get("TMPDIR","/tmp"), "i018", "locksites.json"), "w") as f:
    json.dump(locksites, f)
