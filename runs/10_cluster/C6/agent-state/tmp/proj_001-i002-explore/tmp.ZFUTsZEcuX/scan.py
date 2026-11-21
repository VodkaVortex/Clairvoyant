import re, os, sys, subprocess

# Precompile patterns
pull_pat = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|pskb_may_pull_fraglist|__pskb_pull)\s*\(')
hdrptr_pat = re.compile(r'(\w+)\s*=\s*skb_header_pointer\s*\(')

def find_function_boundaries(lines):
    """Return list of (start_line, end_line, header_line) for top-level functions."""
    funcs = []
    cur_start = None
    cur_header = None
    depth = 0
    for i, line in enumerate(lines):
        if re.match(r'^\w.*\(', line) and cur_start is None and not line.strip().startswith(('#', '//', '*', '/*')):
            # possible function header start; check if this line or following has '{'
            j = i
            found_brace = False
            while j < len(lines) and j < i + 8:
                if '{' in lines[j]:
                    found_brace = True
                    break
                if lines[j].strip().endswith(';'):
                    break
                j += 1
            if found_brace:
                cur_start = i
                cur_header = i
                depth = 0
                for k in range(i, j+1):
                    depth += lines[k].count('{') - lines[k].count('}')
                if depth == 0:
                    funcs.append((i, j, i))
                    cur_start = None
        elif cur_start is not None:
            depth += line.count('{') - line.count('}')
            if depth <= 0:
                funcs.append((cur_start, i, cur_header))
                cur_start = None
    return funcs

results = []
files = sys.argv[1:]
for f in files:
    try:
        with open(f, errors='replace') as fh:
            lines = fh.readlines()
    except Exception:
        continue
    funcs = find_function_boundaries(lines)
    for (fs, fe, fh_line) in funcs:
        body = lines[fs:fe+1]
        bodytext = ''.join(body)
        # Find header pointer captures
        captures = []
        for m in hdrptr_pat.finditer(bodytext):
            captures.append(m.group(1))
        if not captures:
            continue
        # Find pull calls
        pulls = [m for m in pull_pat.finditer(bodytext)]
        if not pulls:
            continue
        # For each pull, check if any captured var is dereferenced AFTER the pull
        for pm in pulls:
            pull_linenum = fs + bodytext[:pm.start()].count('\n')
            for var in set(captures):
                # dereference patterns after pull: var->field, *var, var[...], var .field
                deref_pat = re.compile(re.escape(var) + r'\s*(->|\[)|\*\s*' + re.escape(var) + r'\b')
                # search text after pull position
                after = bodytext[pm.end():]
                dm = deref_pat.search(after)
                if dm:
                    deref_linenum = fs + bodytext[:pm.end() + dm.start()].count('\n')
                    results.append((f, fs+1, fe+1, pull_linenum+1, var, deref_linenum+1, (fh_line+1, lines[fh_line].strip()[:100])))

for r in results:
    print(f"{r[0]}\tfunc@{r[1]}-{r[2]}\tpull@{r[3]}\tvar={r[4]}\tderef@{r[5]}\theader={r[6][1]}")
