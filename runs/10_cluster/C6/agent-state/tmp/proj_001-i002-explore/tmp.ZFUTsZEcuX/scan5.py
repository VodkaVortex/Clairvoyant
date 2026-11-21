import re, sys

pull_pat = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|pskb_may_pull_fraglist|__pskb_pull)\s*\(')
# capture patterns: var = skb_header_pointer(...) OR typed var = (struct X *)(skb->data + off) etc.
hp_pat = re.compile(r'(\w+)\s*=\s*skb_header_pointer\s*\(')
cast_pat = re.compile(r'(\w+)\s*=\s*\(\s*(?:const\s+)?(?:struct|union|unsigned|u\d+|__\w+)\s+\w+\s*\*+\s*\)\s*\(?\s*(?:skb->data|skb->head|skb_transport_header|skb_network_header|skb_mac_header)')

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
        caps = []
        for m in hp_pat.finditer(bodytext):
            caps.append((m.group(1), m.start()))
        for m in cast_pat.finditer(bodytext):
            caps.append((m.group(1), m.start()))
        for (var, cstart) in caps:
            cap_line = off2line(bodytext, cstart, fs)
            for pm in pulls:
                if pm.start() < cstart:
                    continue
                after = bodytext[pm.end():]
                reassign = re.compile(r'\b' + re.escape(var) + r'\s*=(?!=)')
                ra = reassign.search(after)
                deref_pat = re.compile(r'\b' + re.escape(var) + r'\s*->|\*\s*' + re.escape(var) + r'\b|\b' + re.escape(var) + r'\s*\[')
                dm = deref_pat.search(after)
                if dm and not (ra and ra.start() < dm.start()):
                    pre = bodytext[cstart:pm.start()]
                    if reassign.search(pre):
                        continue
                    pull_line = off2line(bodytext, pm.start(), fs)
                    deref_line = off2line(bodytext, pm.end() + dm.start(), fs)
                    out.append((f, fs+1, fe+1, cap_line, pull_line, var, deref_line, pm.group(1)))
for o in out:
    print('\t'.join(str(x) for x in o))
