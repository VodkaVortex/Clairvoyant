import os, re, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s05"

REALLOC_CALLS = re.compile(r'\b(skb_cow_head|skb_cow|skb_unclone|__skb_unclone|skb_share_check|pskb_expand_head|skb_linearize|__skb_linearize)\s*\(')

CAPTURE = re.compile(
    r'^\s*(?:const\s+)?(?:struct\s+)?(?:[A-Za-z_][A-Za-z0-9_]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
    r'([^;]+)\s*;')
REASSIGN = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+)\s*;')

CAP_EXPRS = ('skb->data', 'skb_network_header', 'skb_transport_header', 'skb_mac_header',
             'ip_hdr(', 'ipv6_hdr(', 'tcp_hdr(', 'udp_hdr(', 'icmp_hdr(', 'eth_hdr(',
             'icmp6_hdr(', 'skb_header_pointer', 'skb_tail_pointer', 'inner_',
             'mpls_hdr(', 'gre_hdr(', 'arp_hdr(', 'skb_push(', 'skb_put(', 'nsh_hdr(')

def files():
    for base in ('net', 'drivers'):
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, base)):
            for fn in filenames:
                if fn.endswith('.c'):
                    yield os.path.join(dirpath, fn)

def find_func_bounds(lines):
    funcs = []
    depth = 0
    start = None
    for i, l in enumerate(lines):
        if depth == 0:
            m = re.match(r'^[A-Za-z_].*\(.*$', l)
            if m and not l.strip().startswith(('#', '//', '*', '/*')) and not re.match(r'^\s', l):
                start = i
        d = l.count('{') - l.count('}')
        if d != 0 or depth > 0:
            depth += d
            if depth == 0 and start is not None:
                funcs.append((start, i))
                start = None
    return funcs

results = []
for path in files():
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.readlines()
    except OSError:
        continue
    funcs = find_func_bounds(lines)
    for (fs, fe) in funcs:
        body = lines[fs:fe+1]
        for ri, l in enumerate(body):
            m = REALLOC_CALLS.search(l)
            if not m:
                continue
            call = m.group(1)
            for ci, cl in enumerate(body[:ri]):
                cm = CAPTURE.match(cl)
                if not cm:
                    continue
                var, expr = cm.group(1), cm.group(2).strip()
                if var in ('skb', 'p', 'nskb', 'sk', 'dev', 'net', 'local', 'dst', 'head', 'data'):
                    continue
                if not any(e in expr for e in CAP_EXPRS):
                    continue
                reassigned = False
                for ui, ul in enumerate(body[ri+1:]):
                    rm = REASSIGN.match(ul)
                    if rm and rm.group(1) == var:
                        reassigned = True
                        break
                if reassigned:
                    continue
                uses = []
                for ui, ul in enumerate(body[ri+1:]):
                    if re.search(r'\b' + re.escape(var) + r'\s*(->|\[|\.|\))', ul):
                        uses.append((fs + ri + 1 + ui + 1, ul.rstrip()))
                if uses:
                    results.append((path.replace(ROOT + '/', ''), fs + ri + 1, call, var, expr,
                                    [(u[0]) for u in uses][:8], uses[0][1][:100] if uses else ''))

for r in sorted(results, key=lambda x: -len(x[5])):
    print(f"{r[0]}:{r[1]} call={r[2]} var={r[3]} capture='{r[4][:60]}' uses@{r[5]} firstuse='{r[6]}'")
