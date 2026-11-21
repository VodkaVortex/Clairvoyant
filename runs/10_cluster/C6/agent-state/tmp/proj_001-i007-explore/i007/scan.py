import re, os, sys

ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s02'
REALLOC = re.compile(r'\b(skb_cow_head|skb_cow|skb_unclone|skb_share_check|pskb_expand_head|skb_linearize|__pskb_pull_tail|pskb_may_pull|pskb_pull)\s*\(')
# pointer captures: TYPE *name = <expr involving hdr/data>
CAPTURE = re.compile(r'^\s*(?:const\s+)?(?:struct\s+)?[A-Za-z_][\w]*(?:\s+struct\s+[A-Za-z_]\w*)?\s*\*\s*([A-Za-z_]\w*)\s*=\s*([^;]+);')

def functions(text):
    """Yield (name, start_line, end_line, body) for each top-level function."""
    lines = text.split('\n')
    i = 0
    n = len(lines)
    while i < n:
        m = re.match(r'^([A-Za-z_][\w\s\*]*?)([A-Za-z_]\w*)\s*\(', lines[i])
        # find function signature end and opening brace
        if m and not lines[i].strip().startswith(('#', '//', '*', '/*')) and '=' not in lines[i].split('(')[0]:
            # accumulate until '{' at depth 0 of parens
            j = i
            depth = 0
            sig = ''
            found_open = False
            while j < n and j - i < 12:
                sig += lines[j] + '\n'
                depth += lines[j].count('(') - lines[j].count(')')
                if depth <= 0 and '{' in lines[j]:
                    found_open = True
                    break
                if depth <= 0 and ';' in lines[j]:
                    break  # prototype
                j += 1
            if found_open:
                # find matching close brace
                k = j
                bdepth = 0
                started = False
                while k < n:
                    bdepth += lines[k].count('{') - lines[k].count('}')
                    if '{' in lines[k]:
                        started = True
                    if started and bdepth <= 0:
                        break
                    k += 1
                fname = m.group(2)
                yield fname, i+1, k+1, '\n'.join(lines[i:k+1])
                i = k + 1
                continue
        i += 1

results = []
for dirpath, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in ('.git',)]
    for f in files:
        if not (f.endswith('.c') or f.endswith('.h')):
            continue
        p = os.path.join(dirpath, f)
        try:
            text = open(p, errors='ignore').read()
        except:
            continue
        if not REALLOC.search(text):
            continue
        for fname, sl, el, body in functions(text):
            rls = [m.start() for m in REALLOC.finditer(body)]
            if not rls:
                continue
            # find captures before first realloc call and uses after last realloc call
            blines = body.split('\n')
            # compute line offsets
            rel = {}
            pos = 0
            for idx, l in enumerate(blines):
                rel[pos] = idx
                pos += len(l) + 1
            caps = []  # (varname, line_in_body)
            for idx, l in enumerate(blines):
                cm = CAPTURE.match(l)
                if cm:
                    caps.append((cm.group(1), idx, l.strip()))
            for rlp in rls:
                rline = rel[max(k for k in rel if k <= rlp)]
                callname = REALLOC.search(body[rlp:]).group(1)
                for (v, cidx, csrc) in caps:
                    if cidx < rline:
                        # check uses after the realloc call line
                        pat = re.compile(r'\b' + re.escape(v) + r'\b\s*(->|\.|;|\)|\[)')
                        for uidx in range(rline+1, len(blines)):
                            um = pat.search(blines[uidx])
                            if um:
                                # skip if the var is reassigned on that line before use
                                line = blines[uidx]
                                reass = re.search(r'\b' + re.escape(v) + r'\s*=', line)
                                if reass and reass.start() < um.start():
                                    continue
                                # skip pure address-of or sizeof
                                if re.search(r'\bsizeof\b[^;]*\b' + re.escape(v) + r'\b', line):
                                    continue
                                results.append((p.replace(ROOT+'/',''), fname, sl+cidx, sl+rline, sl+uidx, v, callname, csrc[:80], line.strip()[:100]))
                                break
for r in results:
    print('\t'.join(map(str, r)))
