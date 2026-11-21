import re, sys, os

COW_CALLS = re.compile(r'\b(skb_cow_head|skb_cow|skb_unclone|skb_share_check|pskb_expand_head|skb_linearize)\s*\(')

PTR_HINT = re.compile(
    r'skb_header_pointer\s*\(|skb->data|skb->head|skb_tail_pointer|skb_network_header|skb_mac_header|'
    r'skb_transport_header|skb->cb|skb_shinfo|\*\s*\)\s*skb->|'
    r'vlan_eth_hdr|eth_hdr\s*\(|ip_hdr\s*\(|ipv6_hdr\s*\(|tcp_hdr\s*\(|udp_hdr\s*\(|'
    r'sctp_hdr|dccp_hdr|icmp_hdr|igmp_hdr|arp_hdr|nsh_hdr|mpls_hdr|gre_hdr|esp_hdr|ah_hdr|'
    r'geneve_hdr|vxlan_hdr|gue_hdr|frag_hdr|tcp_hdr'
)

def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), text, flags=re.S)
    text = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group(0)), text)
    return text

def split_functions(text):
    funcs = []
    lines = text.split('\n')
    idx, n = 0, len(lines)
    while idx < n:
        line = lines[idx]
        if re.search(r'\)\s*$', line) and not re.match(r'^\s', line) and not re.match(r'^(#|else|do)', line):
            k = idx; brace_line = None
            while k < idx + 6 and k < n:
                if '{' in lines[k]:
                    brace_line = k; break
                if k > idx and (re.match(r'^\}', lines[k]) or (re.match(r'^[A-Za-z_]', lines[k]))):
                    break
                k += 1
            if brace_line is not None:
                nm = None
                for l in lines[idx:brace_line+1]:
                    m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', l)
                    if m and m.group(1) not in ('if','for','while','switch','sizeof','return','container_of'):
                        nm = m.group(1); break
                if nm:
                    depth = 0; j = brace_line
                    while j < n:
                        depth += lines[j].count('{') - lines[j].count('}')
                        if depth <= 0: break
                        j += 1
                    if j < n and depth <= 0:
                        funcs.append((idx, j, nm)); idx = j + 1; continue
        idx += 1
    return funcs

ASSIGN_RE = re.compile(r'(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*(?::[A-Za-z0-9_:]+)?=(?!=)\s*([^;]+?);')

def analyze(path):
    with open(path, 'r', errors='replace') as f:
        raw = f.read()
    text = strip_comments(raw)
    lines = text.split('\n')
    out = []
    for (fs, fe, name) in split_functions(text):
        bl = lines[fs:fe+1]
        cows = [i for i in range(len(bl)) if COW_CALLS.search(bl[i])]
        if not cows: continue
        # capture map: var -> line index of first ptr-ish assignment
        caps = {}
        for i, bline in enumerate(bl):
            for m in ASSIGN_RE.finditer(bline):
                lhs, rhs = m.group(1), m.group(2)
                if PTR_HINT.search(rhs):
                    if lhs not in caps:
                        caps[lhs] = (i, bline.strip()[:80])
        for ci in cows:
            for var, (cap_i, cap_src) in caps.items():
                if cap_i >= ci: continue
                # check no reassignment between capture and cow
                reassigned = False
                uses = []
                for i in range(cap_i+1, len(bl)):
                    if i != cap_i:
                        for m in re.finditer(r'(?<![\w.>&])' + re.escape(var) + r'\s*(?::[A-Za-z0-9_:]+)?=(?!=)', bl[i]):
                            reassigned = i < ci
                            if reassigned: break
                    if reassigned: break
                if reassigned: continue
                for i in range(ci+1, len(bl)):
                    if re.search(r'(?<![\w.])' + re.escape(var) + r'\s*(?:->|\.|\[|\+|\-|\)|,|\*|;)', bl[i]) or re.search(r'(?<![\w.])' + re.escape(var) + r'\b', bl[i]) and re.search(r'\b' + re.escape(var) + r'\b\s*(?:->|\[)', bl[i]):
                        uses.append(i)
                if uses:
                    out.append(f"{path}\t{fs+ci+1}\t{name}\t{var}\tcap@{fs+cap_i+1}\tuses@{','.join(str(fs+u+1) for u in uses)}\tCOWLINE={bl[ci].strip()[:90]}")
    return out

if __name__ == '__main__':
    base = sys.argv[1]
    for root, dirs, files in os.walk(base):
        for fn in files:
            if fn.endswith('.c'):
                p = os.path.join(root, fn)
                try:
                    for r in analyze(p): print(r)
                except Exception as e:
                    print(f"ERR {p}: {e}", file=sys.stderr)
