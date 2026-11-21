import re, sys

pull_pat = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|pskb_may_pull_fraglist|__pskb_pull|skb_pull)\s*\(')
# capture pointer via skb_header_pointer assignment
hp_pat = re.compile(r'(\w+)\s*=\s*skb_header_pointer\s*\(')
# capture pointer via direct cast of skb->data or skb_transport_header etc.
cast_pat = re.compile(r'=\s*\(\s*struct\s+\w+\s*\*+\s*\)\s*(skb->data|skb_transport_header\s*\([^)]*\)|skb_network_header\s*\([^)]*\)|skb_mac_header\s*\([^)]*\))')

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
        captures = {}
        for m in hp_pat.finditer(bodytext):
            captures.setdefault(m.group(1), 'skb_header_pointer')
        for m in cast_pat.finditer(bodytext):
            captures.setdefault('__cast_hdr', None)  # too noisy; skip direct cast analysis here
        for pm in pulls:
            pname = pm.group(1)
            pull_line = off2line(bodytext, pm.start(), fs)
            for var in list(captures):
                deref_pat = re.compile(r'\b' + re.escape(var) + r'\s*->|\(\s*' + re.escape(var) + r'\s*\)|\*\s*' + re.escape(var) + r'\b|\b' + re.escape(var) + r'\s*\[')
                # text between capture and pull should contain the pull; search after pull
                after = bodytext[pm.end():]
                dm = deref_pat.search(after)
                if dm:
                    deref_line = off2line(bodytext, pm.end() + dm.start(), fs)
                    # make sure capture happened BEFORE the pull (approximation)
                    cm = re.search(r'\b' + re.escape(var) + r'\s*=\s*skb_header_pointer', bodytext[:pm.start()])
                    if cm:
                        out.append((f, fs+1, fe+1, lines[fs].strip()[:90], pname, pull_line, var, deref_line))
for o in out:
    print('\t'.join(str(x) for x in o))
