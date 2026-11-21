import re, sys

pull_pat = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|pskb_may_pull_fraglist|__pskb_pull)\s*\(\s*(\w+)')
hp_pat   = re.compile(r'(\w+)\s*=\s*skb_header_pointer\s*\(\s*(\w+)')
cast_pat = re.compile(r'(\w+)\s*=\s*\(\s*(?:const\s+)?(?:struct|union|unsigned|u\d+|__\w+|void)\s+\w*\s*\*+\s*\)\s*\(?\s*skb->data')
hdr_pat  = re.compile(r'(\w+)\s*=\s*\w+_hdr\s*\(\s*(\w+)\s*\)')
nhdr_pat = re.compile(r'(\w+)\s*=\s*(?:skb_network_header|skb_transport_header|skb_mac_header)\s*\(\s*(\w+)\s*\)')

def functions(lines):
    funcs, cur_start, depth = [], None, 0
    for i, line in enumerate(lines):
        if line.strip().startswith('{') and depth == 0 and cur_start is None:
            j = i - 1
            while j > 0 and lines[j].strip() != '' and not lines[j].strip().endswith(('}', ';')):
                j -= 1
            cur_start = j + 1
            depth = line.count('{') - line.count('}')
            if depth == 0:
                funcs.append((cur_start, i)); cur_start = None
        elif cur_start is not None:
            depth += line.count('{') - line.count('}')
            if depth <= 0:
                funcs.append((cur_start, i)); cur_start = None
    return funcs

def l2n(bt, off, fs): return fs + bt[:off].count('\n') + 1

def argtext(bt, off):
    depth, k = 0, off
    while k < len(bt):
        if bt[k] == '(': depth += 1
        elif bt[k] == ')':
            depth -= 1
            if depth == 0: return bt[off:k+1]
        k += 1
    return bt[off:off+120]

out = []
for f in sys.argv[1:]:
    try: lines = open(f, errors='replace').readlines()
    except Exception: continue
    for (fs, fe) in functions(lines):
        body = ''.join(lines[fs:fe+1])
        pulls = list(pull_pat.finditer(body))
        if not pulls: continue
        caps = []
        for m in hp_pat.finditer(body):   caps.append((m.group(1), m.group(2), m.start(), m.end()))
        for m in cast_pat.finditer(body): caps.append((m.group(1), 'skb', m.start(), m.end()))
        for m in hdr_pat.finditer(body):  caps.append((m.group(1), m.group(2), m.start(), m.end()))
        for m in nhdr_pat.finditer(body): caps.append((m.group(1), m.group(2), m.start(), m.end()))
        for (var, sv, cs, ce) in caps:
            for pm in pulls:
                if pm.group(2) != sv or pm.start() < ce: continue
                reassign = re.compile(r'\b' + re.escape(var) + r'\s*=(?!=)')
                if reassign.search(body[ce:pm.start()]): continue
                after = body[pm.end():]
                dm = re.search(r'\b' + re.escape(var) + r'\s*->|\*\s*' + re.escape(var) + r'\b|\b' + re.escape(var) + r'\s*\[', after)
                if not dm: continue
                ra = reassign.search(after)
                if ra and ra.start() < dm.start(): continue
                pa = argtext(body, pm.end()-1)
                prio = 'PULLLEN_FROM_HDR' if re.search(re.escape(var) + r'\s*->', pa) else ''
                out.append((prio, f, fs+1, fe+1, l2n(body, cs, fs), l2n(body, pm.start(), fs), var, pm.group(1), l2n(body, pm.end()+dm.start(), fs)))
out.sort(key=lambda o: (o[0] == '', o[0], o[1], o[5]))
for o in out: print('\t'.join(str(x) for x in o))
print("TOTAL", len(out))
