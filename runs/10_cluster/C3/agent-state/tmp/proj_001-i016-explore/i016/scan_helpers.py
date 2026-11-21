import os, re, sys
root = "."
pat_par = re.compile(r'^\s*(?:static\s+)?(?:const\s+)?[A-Za-z_][A-Za-z0-9_ \*]*\s+\**([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;{]*$', re.S)
results = []
for dirpath, dirnames, filenames in os.walk(root):
    for fn in filenames:
        if not (fn.endswith('.c') or fn.endswith('.h')):
            continue
        p = os.path.join(dirpath, fn)
        try:
            with open(p, 'r', errors='replace') as f:
                lines = f.readlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            if re.search(r'\bnla_(get_\w+|data|len|parse_nested|parse_nested_deprecated|parse_nested_compat|validate_nested|validate_nested_deprecated)\s*\(', line):
                # find identifiers used as args
                pass
# phase 2: find function definitions whose params look like nlattr
func_def = re.compile(r'^([A-Za-z_][A-Za-z0-9_ \t\*]*)\(\s*([A-Za-z0-9_, \t\*]+)\)\s*$')
param_nlattr = re.compile(r'\bstruct\s+nlattr\s*\*+\s*([A-Za-z_][A-Za-z0-9_]*)')
deref = re.compile(r'\b(nla_(?:get_\w+|data|len|parse_nested\w*|validate_nested\w*)|nla_for_each_nested)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)')
func_start = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\([^;]*$|^[A-Za-z_][A-Za-z0-9_ \t\*]*\([^;]*\)\s*$')
out = []
for dirpath, dirnames, filenames in os.walk(root):
    if '/.git' in dirpath: continue
    for fn in filenames:
        if not (fn.endswith('.c')): continue
        p = os.path.join(dirpath, fn)
        try:
            src = open(p, 'r', errors='replace').read()
        except OSError:
            continue
        lines = src.split('\n')
        # crude function splitter: find lines with 'struct nlattr *' in params followed by '{'
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            if 'struct nlattr' in line and not line.strip().startswith('*') and 'typedef' not in line:
                # gather until '{' or ';' at depth 0
                j = i
                hdr = ''
                while j < n and j < i+12:
                    hdr += lines[j] + '\n'
                    if re.search(r'\)\s*\{', lines[j]) or re.search(r'\)\s*$', lines[j]) and j+1 < n and lines[j+1].strip() == '{':
                        break
                    if lines[j].rstrip().endswith(';'):
                        break
                    j += 1
                m = param_nlattr.search(hdr)
                if m:
                    pname = m.group(1)
                    # find function body boundaries: from hdr start to matching close brace
                    # locate '{' line index
                    k = j
                    while k < n and '{' not in lines[k] and k < j+3: k += 1
                    if k < n and '{' in lines[k]:
                        depth = 0; started = False; e = k
                        while e < n:
                            depth += lines[e].count('{') - lines[e].count('}')
                            if depth <= 0 and started: break
                            if '{' in lines[e]: started = True
                            if depth == 0 and started: break
                            e += 1
                        body = '\n'.join(lines[k:e+1])
                        # does it check pname for NULL?
                        guarded = re.search(r'(!\s*' + pname + r'\b|' + pname + r'\s*==\s*NULL|if\s*\(\s*' + pname + r'\s*\))', body)
                        # does it deref pname?
                        dm = deref.search(body)
                        if dm and dm.group(2) == pname and not guarded:
                            out.append((p, k+1, hdr.strip().split('\n')[0], pname, lines[k-1] if k>0 else ''))
                i = j + 1
            else:
                i += 1
for o in out:
    print("\t".join(str(x) for x in o[:4]))
