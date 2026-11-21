import os, re, json, collections
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"
T = os.environ.get("TMPDIR","/tmp")
data = json.load(open(os.path.join(T, "softirq_cbs.json")))

files = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    if "/.git" in dirpath: continue
    for fn in filenames:
        if fn.endswith((".c", ".h")):
            files.append(os.path.join(dirpath, fn))

src = {}
for f in files:
    try:
        src[f] = open(f, errors="replace").read()
    except Exception:
        pass

cache = {}
def get_text(f):
    if f not in cache:
        cache[f] = open(f, errors="replace").read()
    return cache[f]

# Better function extractor: find definition by scanning for name(, then locate '{' balancing.
def find_def(name):
    pat = re.compile(r'(?m)^[\w\s\*]*?\b' + re.escape(name) + r'\s*\(')
    out = []
    for f, txt in src.items():
        for m in pat.finditer(txt):
            start = m.start()
            # skip if in comment - approximate: check preceding text for /* without */
            seg = txt[:start]
            # find matching close paren then look for '{'
            i = txt.find('(', m.start())
            depth = 0
            j = i
            while j < len(txt):
                if txt[j] == '(': depth += 1
                elif txt[j] == ')':
                    depth -= 1
                    if depth == 0: break
                j += 1
            # look for '{' before any ';' at this level
            k = j+1
            # allow attributes and newlines
            seg2 = txt[k:k+300]
            # stop at first '{' or ';'
            brace = -1
            semi = -1
            for cidx, ch in enumerate(seg2):
                if ch == '{': brace = cidx; break
                if ch == ';': semi = cidx; break
            if brace >= 0:
                b = k + brace
                # balance braces
                d = 0
                p = b
                while p < len(txt):
                    if txt[p] == '{': d += 1
                    elif txt[p] == '}':
                        d -= 1
                        if d == 0: break
                    p += 1
                out.append((f, txt.count('\n', 0, b)+1, txt.count('\n', 0, p)+1))
    return out

defs = {}
for name in list(data["tasklet_cbs"].keys()) + list(data["napi_polls"].keys()):
    defs[name] = find_def(name)

json.dump({k: [[os.path.relpath(x[0], ROOT), x[1], x[2]] for x in v] for k, v in defs.items()},
          open(os.path.join(T, "cb_defs.json"), "w"))
missing = [n for n, v in defs.items() if not v]
print("total cbs:", len(defs), "missing:", len(missing))
print(missing[:30])
