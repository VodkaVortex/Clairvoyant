import os, re, sys

ROOT = "."
DIRS = ["net", "drivers", "include"]
RELOC_CALLS = [
    "pskb_may_pull", "pskb_pull", "__pskb_pull_tail", "skb_linearize",
    "__skb_linearize", "skb_cow", "skb_cow_head", "pskb_expand_head",
    "skb_share_check", "skb_unclone", "ip_mc_may_pull", "ipv6_mc_may_pull",
]

func_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\([A-Za-z0-9_, \t\*\/]*\)\s*(?:\n)?\{', re.M)
# simpler: find function starts by scanning lines
name_re = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\(')

def index_file(path):
    try:
        with open(path, 'r', errors='replace') as f:
            text = f.read()
    except Exception:
        return []
    lines = text.split('\n')
    funcs = []  # (name, start_line, end_line)
    # Find function definitions: line matching "name(" ... eventually "{" at depth 0
    cur = None
    depth = 0
    started = False
    for i, ln in enumerate(lines):
        if cur is None:
            m = name_re.match(ln)
            if m and not ln.strip().endswith(';') and not ln.strip().startswith('#') \
               and not re.match(r'^(if|for|while|switch|return|else|sizeof|EXPORT|MODULE|static inline|#)', ln.strip()):
                # crude: candidate function definition; need '{' within next few lines
                # search forward for '{' before ';'
                j = i
                found = False
                while j < i + 12 and j < len(lines):
                    l = lines[j]
                    if ';' in l and '{' not in l and j > i:
                        break
                    if '{' in l:
                        found = True
                        break
                    j += 1
                if found:
                    cur = [m.group(1), i, None, 0, False]
        else:
            if not started:
                if '{' in ln:
                    started = True
                    depth = ln.count('{') - ln.count('}')
                    if depth <= 0 and '}' in ln:
                        # one-liner
                        funcs.append((cur[0], cur[1], i))
                        cur = None; started = False
                continue
            depth += ln.count('{') - ln.count('}')
            if depth <= 0:
                funcs.append((cur[0], cur[1], i))
                cur = None; started = False
    out = []
    for (name, s, e) in funcs:
        body = '\n'.join(lines[s:e+1])
        calls = set()
        for c in RELOC_CALLS:
            if re.search(r'\b' + c + r'\s*\(', body):
                calls.add(c)
        if calls:
            # does the function take an skb-ish parameter?
            params = body.split('\n')[0] if False else None
            out.append((name, s+1, e+1, sorted(calls), path))
    return out

results = []
for d in DIRS:
    for dirpath, dirnames, filenames in os.walk(d):
        if '/.git' in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(('.c', '.h')):
                p = os.path.join(dirpath, fn)
                results.extend(index_file(p))

print(len(results))
import json
with open(os.environ['TMPDIR'] + '/i023/callee_index.json', 'w') as f:
    json.dump([{'name': n, 'start': s, 'end': e, 'calls': c, 'path': p} for (n, s, e, c, p) in results], f, indent=1)
