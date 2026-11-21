import re, os, sys, subprocess

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s03"
REALLOC_CALL = re.compile(r'\b(skb_cow_head|skb_cow|skb_unclone|skb_share_check|pskb_expand_head|skb_linearize|skb_ensure_writable|skb_cow_data)\s*\(')
# pointer capture into skb head/data areas
CAPTURE = re.compile(r'^\s*(?:const\s+)?(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);')
CAP_FROM = re.compile(r'\b(skb_header_pointer|ip_hdr|ipv6_hdr|tcp_hdr|udp_hdr|sctp_hdr|icmp_hdr|icmp6hdr|eth_hdr|nsh_hdr|mpls_hdr|gre_hdr|skb_network_header|skb_mac_header|skb_transport_header|skb_tail_pointer|skb_push|skb_put|skb->data|skb->head|skb->tail)\b')
DEREF = re.compile(r'->|\[[^\]]+\]|\*')
FUNCS = ["skb_cow_head","skb_cow","skb_unclone","skb_share_check","pskb_expand_head","skb_linearize"]

def func_name(lines, idx):
    # search upward for a line at col 0 that looks like a function definition
    for j in range(idx, max(-1, idx-300), -1):
        l = lines[j]
        if re.match(r'^[A-Za-z_].*\)\s*$', l) or re.match(r'^[A-Za-z_].*\)\s*\{\s*$', l):
            m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
            if m: return m.group(1)
        if re.match(r'^\}', l):
            m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
            return None
    return None

results = []
for dirpath, dirs, files in os.walk(os.path.join(ROOT, "net")):
    if "/selftests" in dirpath: continue
    for f in files:
        if not f.endswith(('.c','.h')): continue
        p = os.path.join(dirpath, f)
        try:
            src = open(p, errors='replace').read()
        except: continue
        lines = src.split('\n')
        for i, line in enumerate(lines):
            m = REALLOC_CALL.search(line)
            if not m: continue
            call = m.group(1)
            # find function start: scan up for line matching 'name(' at col 0 followed eventually by '{'
            fstart = None
            for j in range(i, max(-1, i-400), -1):
                if re.match(r'^\}', lines[j]): break
                fm = re.match(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*([A-Za-z_][A-Za-z0-9_]*)\s*\(', lines[j])
                if fm and '{' in ''.join(lines[j:j+3]):
                    fstart = j; break
            if fstart is None: continue
            # function end
            fend = fstart
            depth = 0; started = False
            for j in range(fstart, min(len(lines), fstart+800)):
                depth += lines[j].count('{') - lines[j].count('}')
                if '{' in lines[j]: started = True
                if started and depth <= 0:
                    fend = j; break
            # capture pointer vars before call line within function
            ptrvars = {}
            for j in range(fstart, i):
                cm = CAPTURE.match(lines[j])
                if cm and CAP_FROM.search(cm.group(3)):
                    ptrvars[cm.group(2)] = (j+1, cm.group(3))
            if not ptrvars: continue
            # uses after call
            uses = []
            for j in range(i+1, fend+1):
                for v,(cl,expr) in ptrvars.items():
                    if re.search(r'\b'+re.escape(v)+r'\b', lines[j]):
                        uses.append((v, cl, j+1, lines[j].strip()))
            if uses:
                results.append((os.path.relpath(p, ROOT), fstart+1, fend+1, i+1, call, func_name(lines, i), ptrvars, uses))

out = open(os.path.join(os.environ.get('TMPDIR','/tmp'), 'audit_out.txt'), 'w')
for r in results:
    rel, fs, fe, cl, call, fname, ptrvars, uses = r
    out.write(f"=== {rel}:{fname} (lines {fs}-{fe}) call@{cl} {call}\n")
    for v,(ce,expr) in ptrvars.items():
        out.write(f"    capture {v} @ {ce}: {expr}\n")
    for v,ce,ul,uline in uses[:12]:
        out.write(f"    USE {v} @ {ul}: {uline}\n")
    out.write("\n")
out.close()
print(f"total candidate functions with pre-call captured pointers used post-call: {len(results)}")
