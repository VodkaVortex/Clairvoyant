import re, sys

pull_pat = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|pskb_may_pull_fraglist|__pskb_pull)\s*\(')
hdrptr_pat = re.compile(r'(\w+)\s*=\s*skb_header_pointer\s*\(')

def functions(lines):
    funcs = []
    cur_start = None
    depth = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('{') and depth == 0 and cur_start is None:
            j = i - 1
            while j > 0 and lines[j].strip() != '' and not lines[j].strip().endswith(('}', ';')):
                j -= 1
            cur_start = j + 1
            depth = line.count('{') - line.count('}')
            if depth == 0:
                funcs.append((cur_start, i))
                cur_start = None
        elif cur_start is not None:
            depth += line.count('{') - line.count('}')
            if depth <= 0:
                funcs.append((cur_start, i))
                cur_start = None
    return funcs

def off2line(bodytext, off, fs):
    return fs + bodytext[:off].count('\n') + 1

out = []
files = sys.argv[1:]
for f in files:
    try:
        lines = open(f, errors='replace').readlines()
    except Exception:
        continue
    for (fs, fe) in functions(lines):
        body = lines[fs:fe+1]
        bodytext = ''.join(body)
        pulls = list(pull_pat.finditer(bodytext))
        if not pulls:
            continue
        for var_m in hdrptr_pat.finditer(bodytext):
            var = var_m.group(1)
            cap_line = off2line(bodytext, var_m.start(), fs)
            for pm in pulls:
                pull_line = off2line(bodytext, pm.start(), fs)
                if pull_line < cap_line:
                    continue
                after = bodytext[pm.end():]
                # deref of captured var after the pull, with optional refetch check:
                # find first re-assignment of var (var = ...) after pull; if re-assign occurs BEFORE deref, it's a refetch (safe)
                reassign = re.compile(r'\b' + re.escape(var) + r'\s*=(?!=)')
                ra = reassign.search(after)
                deref_pat = re.compile(r'\b' + re.escape(var) + r'\s*->|\*\s*' + re.escape(var) + r'\b|\b' + re.escape(var) + r'\s*\[')
                dm = deref_pat.search(after)
                if dm and not (ra and ra.start() < dm.start()):
                    deref_line = off2line(bodytext, pm.end() + dm.start(), fs)
                    out.append((f, fs+1, fe+1, cap_line, pull_line, var, deref_line, pm.group(1)))
for o in out:
    print('\t'.join(str(x) for x in o))
