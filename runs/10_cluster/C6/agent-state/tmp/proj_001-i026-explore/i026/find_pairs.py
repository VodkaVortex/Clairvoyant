import os, re, sys

ROOT = "."

# Calee definitions that pull/cow/linearize internally
pull_re = re.compile(r'\b(pskb_may_pull|__pskb_pull_tail|skb_linearize|__skb_linearize|pskb_expand_head|skb_cow|skb_cow_head|skb_unclone)\s*\(')

files = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    if any(skip in dirpath for skip in ('/Documentation', '/tools', '/samples', '/usr/', '/scripts')):
        continue
    if not (dirpath.startswith('./net') or dirpath.startswith('./drivers')):
        if dirpath != '.':
            continue
    for fn in filenames:
        if fn.endswith(('.c', '.h')):
            files.append(os.path.join(dirpath, fn))

# Step 1: index functions containing pull calls -> candidate CALLEES with the skb parameter
callee_funcs = {}  # file -> list of (name, sig_skb_param, start_line)
func_def_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\(')

# We'll use a simple approach: find function definitions via ctags-like heuristic with brace tracking
def parse_functions(path):
    """Return list of (name, start_line, end_line, header) for functions in a C file."""
    funcs = []
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return funcs
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = re.match(r'^(\w[\w \t\*]*?)\s*\(', line)
        if m and not line.lstrip().startswith(('#', '//', '*', '/*')) and not re.match(r'^(if|for|while|switch|return|else|sizeof)\b', m.group(1)):
            # look for the opening brace within the next few lines and closing paren before it
            j = i
            header = ''
            while j < n and j <= i + 6:
                header += lines[j]
                if '{' in lines[j]:
                    break
                if lines[j].rstrip().endswith(';'):
                    break
                j += 1
            if j < n and '{' in lines[j]:
                # must have closing paren of the parameter list in header
                if header.count('(') >= 1 and header.rstrip().split('{')[0].count(')') >= 1:
                    name = m.group(1).split()[-1]
                    # find matching close brace
                    depth = 0
                    k = j
                    started = False
                    while k < n:
                        for ch in lines[k]:
                            if ch == '{':
                                depth += 1
                                started = True
                            elif ch == '}':
                                depth -= 1
                        if started and depth == 0:
                            break
                        k += 1
                    funcs.append((name, i + 1, k + 1, header))
                    i = k + 1
                    continue
        i += 1
    return funcs

callers_of = {}  # callee_name -> set of (file, funcname, start, end)

all_funcs = {}  # (file, name) -> (start,end)

for path in files:
    funcs = parse_functions(path)
    for (name, s, e, hdr) in funcs:
        all_funcs[(path, name)] = (s, e)
        with open(path, 'r', errors='replace') as f:
            flines = f.readlines()
        body = ''.join(flines[s-1:e])
        if pull_re.search(body):
            # does the header take a struct sk_buff * parameter?
            if 'sk_buff' in hdr or 'skb' in hdr:
                callee_funcs.setdefault(path, []).append((name, s, e))

# Step 2: find callers of these callee names elsewhere and check if the caller has a captured pointer used after the call
print("### CALLEES WITH INTERIOR PULL/COW/LINEARIZE (taking skb): %d" % sum(len(v) for v in callee_funcs.values()))
for path, lst in sorted(callee_funcs.items()):
    for (name, s, e) in lst:
        print(f"CALLEE {path}:{s} {name}")

# index: name -> definitions
name_to_defs = {}
for (path, name), (s, e) in all_funcs.items():
    name_to_defs.setdefault(name, []).append((path, s, e))

# Step 3: for each file, find call sites to callee names; check enclosing function for pointer captures
capture_re = re.compile(r'^\s*(?:const\s+)?(?:struct\s+)?[\w]+(?:\s+|\s*\*)\s*(\w+)\s*(?:=[^=].*)?;\s*$')

# We want functions that call a pull-capable callee AND declare a pointer into skb head before it AND use it after
results = []
for path in files:
    try:
        with open(path, 'r', errors='replace') as f:
            flines = f.readlines()
    except Exception:
        continue
    funcs = parse_functions(path)
    for (name, s, e, hdr) in funcs:
        body_lines = flines[s-1:e]
        body = ''.join(body_lines)
        if 'skb' not in body:
            continue
        # find call to a pull-capable callee
        for (callee_name, defs) in name_to_defs.items():
            if callee_name in ('pskb_may_pull',):
                continue
            if not any(d in callee_funcs_items for d in defs):
                continue
        # simpler: check calls to any known pull-callee names
        called = []
        for m in re.finditer(r'\b(\w+)\s*\(\s*(?:skb|\w*skb\w*)\b', body):
            cn = m.group(1)
            if cn in pull_callee_names:
                called.append(cn)
        if called:
            results.append((path, name, s, e, set(called)))

print("### CALLER FUNCTIONS CALLING PULL-CAPABLE CALLEES: %d" % len(results))
