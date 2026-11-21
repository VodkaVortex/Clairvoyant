import os, re, sys, json

ROOT = "."
pull_re = re.compile(r'\b(pskb_may_pull|__pskb_pull_tail|skb_linearize|__skb_linearize|pskb_expand_head|skb_cow|skb_cow_head|skb_unclone)\s*\(')
pull_call_re = re.compile(r'\b(pskb_may_pull|__pskb_pull_tail|skb_linearize|__skb_linearize|pskb_expand_head|skb_cow|skb_cow_head|skb_unclone)\s*\(\s*([A-Za-z_]\w*)')

skip_dirs = ('/Documentation', '/tools', '/samples', '/usr/', '/scripts', '/.git')

def walk_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        if dirpath == '.':
            continue
        if any(sk in dirpath + '/' for sk in skip_dirs):
            continue
        # only net/ drivers/ include/
        parts = dirpath.split(os.sep)
        if len(parts) < 2 or parts[1] not in ('net', 'drivers', 'include'):
            continue
        for fn in filenames:
            if fn.endswith(('.c', '.h')):
                yield os.path.join(dirpath, fn)

def parse_functions(path, flines):
    funcs = []
    i, n = 0, len(flines)
    kw = re.compile(r'^(if|for|while|switch|return|else|sizeof|do|case)\b')
    while i < n:
        line = flines[i]
        ls = line.strip()
        if ls and not ls.startswith(('#', '//', '*', '/*', '*', '*/')):
            m = re.match(r'^([A-Za-z_][\w \t\*]*?)\s*\(', ls)
            if m and not kw.match(m.group(1)):
                j, header = i, ''
                ok = False
                while j < n and j <= i + 8:
                    header += flines[j]
                    if '{' in flines[j]:
                        ok = True
                        break
                    if flines[j].rstrip().endswith(';'):
                        break
                    j += 1
                if ok:
                    pre = header.split('{')[0]
                    if pre.count(')') >= 1:
                        name = m.group(1).split()[-1].rstrip('*')
                        depth, started, k = 0, False, j
                        while k < n:
                            for ch in flines[k]:
                                if ch == '{': depth += 1; started = True
                                elif ch == '}': depth -= 1
                            if started and depth == 0:
                                break
                            k += 1
                        if started and depth == 0:
                            funcs.append((name, i + 1, k + 1, pre))
                            i = k + 1
                            continue
        i += 1
    return funcs

# Pass 1: collect callee functions (functions containing an interior pull on an skb-ish arg)
callees = {}   # name -> list of (path, line)
callee_paths = set()
for path in walk_files():
    try:
        with open(path, 'r', errors='replace') as f:
            flines = f.readlines()
    except Exception:
        continue
    for (name, s, e, hdr) in parse_functions(path, flines):
        body = ''.join(flines[s-1:e])
        m = pull_call_re.search(body)
        if m and 'struct sk_buff' in hdr:
            arg = m.group(2)
            if 'skb' in arg or arg in ('skb',):
                callees.setdefault(name, []).append((path, s))
                callee_paths.add(path)

pull_callee_names = set(callees.keys())
# static inline wrappers in headers count too (already covered by parse on .h)

# Pass 2: find CALLER functions that call a pull-callee AND capture a raw pointer before the call AND use it after
decl_ptr_re = re.compile(r'^\s*(?:const\s+)?(?:unsigned\s+char|u8|void|char|struct\s+\w+|__be16\s*\*|__be32\s*\*|const\s+struct\s+\w+)\s*\*?\s*(\w+)\s*(?:=[^=;]*)?;')
call_callee_re = re.compile(r'\b(\w+)\s*\(')

findings = []
for path in walk_files():
    try:
        with open(path, 'r', errors='replace') as f:
            flines = f.readlines()
    except Exception:
        continue
    for (name, s, e, hdr) in parse_functions(path, flines):
        body_lines = flines[s-1:e]
        body = ''.join(body_lines)
        if 'skb' not in body:
            continue
        # call sites of pull-callees within this function
        call_sites = []
        for m in re.finditer(r'\b(' + '|'.join(re.escape(c) for c in pull_callee_names) + r')\s*\(', body):
            call_sites.append(m.start())
        if not call_sites:
            continue
        # candidate captured pointer vars: declared as pointers assigned from skb-ish expressions
        ptr_vars = {}
        for li, line in enumerate(body_lines):
            dm = re.match(r'^\s*(?:const\s+)?[\w\s]+?\*\s*(\w+)\s*=\s*(.+?);\s*$', line)
            if dm:
                var, rhs = dm.group(1), dm.group(2)
                if re.search(r'skb->data|skb_header_pointer|_hdr\(skb\)|skb_network_header|skb_transport_header|skb_mac_header|skb_tail_pointer|skb->head', rhs):
                    ptr_vars[var] = (li, rhs)
        if not ptr_vars:
            continue
        # for each call site, check if any ptr var is used after the call
        for cs in call_sites:
            for var, (decl_li, rhs) in ptr_vars.items():
                if decl_li >= cs:
                    continue
                # uses after the call
                for li in range(cs + 1, len(body_lines)):
                    if re.search(r'\b' + re.escape(var) + r'\b', body_lines[li]) and not body_lines[li].strip().startswith(('*')):
                        findings.append((path, name, s, e, var, decl_li + s, cs, li + s, body_lines[li].strip()[:100]))
                        break

print("### PULL-CAPABLE CALLEES (name -> defs):")
for cname in sorted(callees):
    for (p, l) in callees[cname]:
        print(f"  {cname}  {p}:{l}")
print()
print("### CALLER HOLDS CAPTURED PTR ACROSS CALLEE CALL: %d" % len(findings))
for f in findings:
    print("  %s:%s %s var=%s decl@%d call@%d use@%d: %s" % (f[0], f[2], f[1], f[4], f[5], f[6], f[7], f[8]))
