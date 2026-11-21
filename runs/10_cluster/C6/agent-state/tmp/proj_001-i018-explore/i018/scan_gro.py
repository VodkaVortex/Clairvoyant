import re, os, sys

ROOT = "."
targets = []
for base, dirs, files in os.walk(ROOT):
    for f in files:
        if f.endswith(".c"):
            targets.append(os.path.join(base, f))

cap_pat = re.compile(r'^\s*(?:const\s+)?struct\s+(\w+)\s*\*\s*(\w+)\s*=')
ptr_pat = re.compile(r'\b\d|\b(?:%s)\b')
# find functions containing gro_receive/gro_complete/gso_segment/frag-list walking
RELOC = re.compile(r'\b(?:skb_gro_header_slow|skb_gro_pull|pskb_may_pull|pskb_pull|__pskb_pull|__pskb_pull_tail|skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|gso_pskb_expand_head|skb_gro_receive|skb_segment|gro_pull_from_frag0|skb_gro_frag0_invalidate)\s*\(')
CAP = re.compile(r'^\s*(?:const\s+)?(?:struct\s+\w+|u8|u16|u32|__be16|__be32|unsigned char|char|void)\s*\*\s*(\w+)\s*=')

interesting = []
for path in targets:
    try:
        text = open(path, errors='ignore').read()
    except Exception:
        continue
    if not re.search(r'\b(?:gro_receive|gro_complete|gso_segment|gro_finish|gro_flush|napi_gro)\b', text):
        continue
    lines = text.split('\n')
    # function start heuristic: line starting at col 0 with '{' or function signature
    # simpler: iterate lines; track current function boundaries by lines that begin with non-space and contain '('
    fn_start = 0
    fn_name = None
    fn_text = []
    def flush(fs, fname, ftext):
        if not fname or not ftext: return
        joined = '\n'.join(ftext)
        if 'gro' not in joined and 'gso' not in joined and 'segment' not in joined and 'frag_list' not in joined:
            return
        caps = {}  # var -> line idx of capture
        for i, ln in enumerate(ftext):
            m = CAP.match(ln)
            if m:
                v = m.group(1)
                rhs = ln.split('=',1)[1]
                # capture from skb-related rhs
                if re.search(r'skb|hdr|data|frag|shinfo|gro', rhs):
                    caps[v] = i
        relocs = [(i, ln) for i, ln in enumerate(ftext) if RELOC.search(ln)]
        if not relocs or not caps:
            return
        for ri, rln in relocs:
            rcall = RELOC.search(rln).group(0)
            for v, ci in caps.items():
                if ci >= ri: continue
                # find uses of v after ri
                uses = []
                for j in range(ri+1, len(ftext)):
                    if re.search(r'\b%s\b' % re.escape(v), ftext[j]) and not re.match(r'^\s*(?:const\s+)?(?:struct\s+\w+|u8|void)\s*\*\s*%s\s*=' % re.escape(v), ftext[j]):
                        # exclude re-assignment
                        if re.search(r'\*\s*%s\s*=' % re.escape(v), ftext[j]):
                            continue
                        uses.append(j+1)
                if uses:
                    interesting.append((path, fs+1, fname, v, ci+1, rcall.strip(), ri+1, uses[:8]))
    fn_start = 0
    fn_name = None
    for idx, ln in enumerate(lines):
        if re.match(r'^[A-Za-z_].*\)\s*$', ln) or re.match(r'^[A-Za-z_].*\)\s*\{\s*$', ln):
            flush(fn_start, fn_name, lines[fn_start:idx])
            fn_start = idx
            m = re.search(r'(\w+)\s*\(', ln)
            fn_name = m.group(1) if m else None
        elif re.match(r'^\}', ln):
            flush(fn_start, fn_name, lines[fn_start:idx+1])
            fn_name = None
    flush(fn_start, fn_name, lines[fn_start:])

for t in interesting:
    print("%s:%d %s | var=%s cap@%d | %s @%d | uses_after=%s" % t)
