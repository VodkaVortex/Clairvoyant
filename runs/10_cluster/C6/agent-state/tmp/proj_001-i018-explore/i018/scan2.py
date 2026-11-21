import re, os

targets = []
for base, dirs, files in os.walk("."):
    if "/.git" in base: continue
    for f in files:
        if f.endswith(".c"):
            targets.append(os.path.join(base, f))

RELOC = r'(?:skb_gro_header_slow|skb_gro_pull|pskb_may_pull|pskb_pull|__pskb_pull|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|gso_pskb_expand_head|skb_gro_receive|skb_segment|gro_pull_from_frag0|skb_gro_frag0_invalidate)'
RELOC_RE = re.compile(r'\b' + RELOC + r'\s*\(')
CAP_RE = re.compile(r'^\s*(?:const\s+)?(?:struct\s+\w+|u8|u16|u32|__be16|__be32|__wsum|unsigned char|char|void)\s*\*+\s*(\w+)\s*=')

def split_functions(lines):
    out = []
    fn_start = 0; fn_name = None; depth = 0; started = False
    sig_re = re.compile(r'^[A-Za-z_].*\(')
    for idx, ln in enumerate(lines):
        if not started and sig_re.match(ln) and not ln.startswith('#') and ';' not in ln:
            fn_start = idx; started = True; depth = 0
            m = re.search(r'(\w+)\s*\(', ln)
            fn_name = m.group(1) if m else None
        if started:
            depth += ln.count('{') - ln.count('}')
            if depth <= 0 and ('{' in ln or '}' in ln):
                out.append((fn_start, idx+1, fn_name, lines[fn_start:idx+1]))
                started = False
    return out

interesting = []
for path in targets:
    try: text = open(path, errors='ignore').read()
    except: continue
    if not re.search(r'\b(?:gro_receive|gro_complete|gso_segment|napi_gro|frag_list|GRO)\b', text):
        continue
    lines = text.split('\n')
    for fs, fe, fname, ftext in split_functions(lines):
        joined = '\n'.join(ftext)
        if not re.search(r'\b(?:gro_|napi_gro|gso_|_gro_|GRO_|frag_list|segment)', joined):
            continue
        caps = {}
        for i, ln in enumerate(ftext):
            m = CAP_RE.match(ln)
            if m:
                v = m.group(1)
                rhs = ln.split('=',1)[1]
                if re.search(r'skb|hdr|data|frag|shinfo|gro|p->|p\b|\*head', rhs):
                    caps.setdefault(v, i)
        relocs = [(i, RELOC_RE.search(ln).group(0).strip()) for i, ln in enumerate(ftext) if RELOC_RE.search(ln)]
        if not relocs or not caps: continue
        for ri, rcall in relocs:
            for v, ci in caps.items():
                if ci >= ri: continue
                uses = []
                for j in range(ri+1, len(ftext)):
                    if re.match(r'^\s*(?:const\s+)?(?:struct\s+\w+|u8|void)\s*\*+\s*%s\s*=' % re.escape(v), ftext[j]):
                        continue
                    if re.search(r'\b%s\s*(?:->|\.)|\(.*\*\s*%s|->\s*%s|\b%s\b' % (re.escape(v), re.escape(v), re.escape(v), re.escape(v)), ftext[j]):
                        uses.append(j+1)
                if uses:
                    interesting.append((path, fs+1, fname, v, ci+1, rcall, ri+1, uses[:10]))

for t in sorted(interesting):
    print("%s:%d %s | var=%s cap@%d | %s @%d | uses_after=%s" % t)
