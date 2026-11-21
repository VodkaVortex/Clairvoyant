import os, re, sys

ROOT = '/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s04'

PULL_RE = re.compile(r'\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|__skb_linearize)\s*\(')

# capture: any declaration-and-init where expr references skb->data, skb_header_pointer, _hdr(skb)
CAPTURE_RE = re.compile(
    r'^(?P<indent>\s*)(?P<type>(?:const\s+)?(?:struct\s+)?\w+)\s*\*?\s*\*?\s*(?P<var>\w+)\s*=\s*(?P<expr>[^;]+);'
)

def hdr_expr(e):
    return ('skb->data' in e or 'skb_header_pointer' in e or
            re.search(r'\w+_hdr\(\s*\w+\s*\)', e) is not None or
            'skb_network_header' in e or 'skb_transport_header' in e or
            'skb_mac_header' in e or 'skb_tail_pointer' in e or
            'skb_shinfo' in e)

out=[]
for dirpath, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in ('.git','Documentation','tools','scripts','samples')]
    if not (dirpath.startswith(os.path.join(ROOT,'net')) or dirpath.startswith(os.path.join(ROOT,'drivers/net')) or dirpath.startswith(os.path.join(ROOT,'drivers/wireless'))):
        continue
    for f in files:
        if not f.endswith('.c'): continue
        p = os.path.join(dirpath, f)
        rel = os.path.relpath(p, ROOT)
        src = open(p, errors='replace').read()
        lines = src.split('\n')
        n = len(lines)
        # function detection: braces at col 0
        spans=[]; start=None; fname=None
        for i,l in enumerate(lines):
            if l.startswith('{') and start is None:
                start=i
                for j in range(i-1, max(-1,i-15), -1):
                    m = re.search(r'(\w+)\s*\(', lines[j])
                    if m and '=' not in lines[j].split('(')[0] and not lines[j].lstrip().startswith(('*/','*','#')):
                        fname=m.group(1); break
            if l.startswith('}') and start is not None:
                spans.append((start,i,fname)); start=None; fname=None
        if start is not None:
            spans.append((start, n-1, fname))
        for (s,e,fn) in spans:
            body=lines[s:e+1]
            caps=[]
            for i,l in enumerate(body):
                m=CAPTURE_RE.match(l)
                if not m: continue
                e_=m.group('expr')
                if hdr_expr(e_) and 'alloc' not in e_ and 'skb_gro' not in e_:
                    caps.append((m.group('var'), i, l.strip()))
            if not caps: continue
            pulls=[i for i,l in enumerate(body) if PULL_RE.search(l)]
            if not pulls: continue
            for (var,ci,cl) in caps:
                for pi in pulls:
                    if pi<=ci: continue
                    # any refetch of var between capture and pull?
                    refetch=False
                    for k in range(ci+1,pi):
                        if re.search(r'\b'+re.escape(var)+r'\s*=[^=]', body[k]): refetch=True;break
                    if refetch: continue
                    for k in range(pi+1,len(body)):
                        l=body[k]
                        if re.search(r'\b'+re.escape(var)+r'\s*=[^=]', l): break
                        if re.search(r'\b'+re.escape(var)+r'\s*(->|\[)', l) or re.search(r'[,(]\s*&?'+re.escape(var)+r'\s*[,)]', l):
                            out.append(f"{rel}:{fn} cap@{s+ci+1}: {cl[:100]} || pull@{s+pi+1}: {body[pi].strip()[:70]} || use@{s+k+1}: {l.strip()[:100]}")
                            break
for o in out: print(o)
print("TOTAL", len(out), file=sys.stderr)
