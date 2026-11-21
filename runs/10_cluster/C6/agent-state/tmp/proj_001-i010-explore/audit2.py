import re, os

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s03"
REALLOC_CALL = re.compile(r'\b(skb_cow_head|skb_cow|skb_unclone|skb_share_check|pskb_expand_head|skb_linearize)\s*\(')
HDRSRC = re.compile(r'\b(skb_header_pointer|ip_hdr|ipv6_hdr|tcp_hdr|udp_hdr|sctp_hdr|icmp_hdr|icmp6_hdr|eth_hdr|nsh_hdr|mpls_hdr|gre_hdr|ipv6_hopopt_hdr|ipv6_exthdr|skb_network_header|skb_mac_header|skb_transport_header|skb_tail_pointer|skb_push|skb_put|skb->data|skb->head)\b')
STMT_SPLIT = re.compile(r';')

def split_stmts(line):
    return [s for s in STMT_SPLIT.split(line) if s.strip()]

results = []
targets = []
for sub in ["net", "drivers/net", "drivers/usb/gadget", "drivers/staging"]:
    d = os.path.join(ROOT, sub)
    if os.path.isdir(d): targets.append(d)

for dirpath, dirs, files in os.walk(os.path.join(ROOT, "net")):
    if "/selftests" in dirpath or "/testing" in dirpath: continue
    dirs[:] = [x for x in dirs if x not in ("selftests","testing")]
    for f in files:
        if not f.endswith('.c'): continue
        targets.append(os.path.join(dirpath, f))

for dirpath, dirs, files in os.walk(os.path.join(ROOT, "drivers")):
    if "/selftests" in dirpath: continue
    dirs[:] = [x for x in dirs if x not in ("selftests")]
    for f in files:
        if not f.endswith('.c'): continue
        p = os.path.join(dirpath, f)
        try: src = open(p, errors='replace').read()
        except: continue
        if 'skb_cow' not in src and 'skb_unclone' not in src and 'skb_share_check' not in src and 'pskb_expand_head' not in src and 'skb_linearize' not in src:
            continue
        targets.append(p)

seen = set()
for p in targets:
    if p in seen or not p.endswith('.c'): continue
    seen.add(p)
    try: src = open(p, errors='replace').read()
    except: continue
    lines = src.split('\n')
    for i, line in enumerate(lines):
        m = REALLOC_CALL.search(line)
        if not m: continue
        call = m.group(1)
        # function start: scan up for col-0 identifier line with '(' and '{' soon after
        fstart = None
        for j in range(i, max(-1, i-500), -1):
            if re.match(r'^\}', lines[j]): break
            fm = re.match(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(', lines[j])
            if fm and not lines[j].lstrip().startswith(('#','/','*')) and '{' in ''.join(lines[j:j+4]):
                fstart = j; break
        if fstart is None: continue
        fend = fstart; depth = 0; started = False
        for j in range(fstart, min(len(lines), fstart+1200)):
            depth += lines[j].count('{') - lines[j].count('}')
            if '{' in lines[j]: started = True
            if started and depth <= 0: fend = j; break
        # find function name
        fname = None
        fm = re.match(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(', lines[fstart])
        if fm: fname = fm.group(1)
        # collect pointer vars assigned from hdr sources anywhere before call (assignments or decls)
        ptrvars = {}
        for j in range(fstart, i):
            for s in split_stmts(lines[j]):
                am = re.match(r'\s*(?:const\s+)?(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)', s)
                if am and HDRSRC.search(am.group(3)):
                    v = am.group(2)
                    if v not in ptrvars: ptrvars[v] = (j+1, am.group(3).strip())
        if not ptrvars: continue
        uses = []
        for j in range(i+1, fend+1):
            for v,(ce,expr) in ptrvars.items():
                if re.search(r'\b'+re.escape(v)+r'\b', lines[j]):
                    uses.append((v, ce, j+1, lines[j].strip()))
        if uses:
            results.append((os.path.relpath(p, ROOT), fstart+1, fend+1, i+1, call, fname, ptrvars, uses))

out = open(os.path.join(os.environ.get('TMPDIR','/tmp'), 'audit2_out.txt'), 'w')
for r in results:
    rel, fs, fe, cl, call, fname, ptrvars, uses = r
    out.write(f"=== {rel}:{fname} (fn {fs}-{fe}) call@{cl} {call}\n")
    for v,(ce,expr) in ptrvars.items():
        out.write(f"    capture {v} @ {ce}: {expr}\n")
    for v,ce,ul,uline in uses[:15]:
        out.write(f"    USE {v} @ {ul}: {uline}\n")
    out.write("\n")
out.close()
print("functions flagged:", len(results))
