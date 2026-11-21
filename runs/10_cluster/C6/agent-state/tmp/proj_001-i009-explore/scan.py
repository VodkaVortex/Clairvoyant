import re, os, sys

root = "net"
pull_re = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize)\s*\(')
cap_re = re.compile(
    r'(?P<var>\w+)\s*=\s*(?:\(?:?)?\s*(?:\(\s*[\w\s\*]+\*\s*\)\s*)?'
    r'(?:skb_header_pointer\s*\(|'
    r'(?:struct\s+\w+\s*\*|u8\s*\*|void\s*\*|__be16\s*\*|__be32\s*\*|\w+\s*\*)?\s*'
    r'(?:ip_hdr|ipv6_hdr|tcp_hdr|udp_hdr|icmp_hdr|icmp6_hdr|ipipv6_hdr|inner_tcp_hdr|gre_hdr|sctp_hdr|ah_hdr|esp_hdr|ip_comp_hdr|tcp_hdr|udp_hdr)\s*\(\s*skb\s*\)|'
    r'\(\s*[\w\s\*]+\*\s*\)\s*skb->data|'
    r'\(\s*[\w\s\*]+\*\s*\)\s*skb_network_header\s*\(\s*skb\s*\)|'
    r'\(\s*[\w\s\*]+\*\s*\)\s*skb_transport_header\s*\(\s*skb\s*\)|'
    r'\(\s*[\w\s\*]+\*\s*\)\s*skb_mac_header\s*\(\s*skb\s*\))'
)
# simpler: multiple specific patterns
patterns = [
    re.compile(r'(?P<var>\w+)\s*=\s*\(\s*[\w\s\*]+?\*\s*\)\s*skb->data'),
    re.compile(r'(?P<var>\w+)\s*=\s*\(\s*[\w\s\*]+?\*\s*\)\s*(skb_network_header|skb_transport_header|skb_mac_header)\s*\(\s*skb\s*\)'),
    re.compile(r'(?P<var>\w+)\s*=\s*(ip_hdr|ipv6_hdr|tcp_hdr|udp_hdr|icmp_hdr|icmp6_hdr|tcp_hdr|sctp_hdr|inner_\w+_hdr|ipip_hdr)\s*\(\s*skb\s*\)'),
    re.compile(r'(?P<var>\w+)\s*=\s*skb_header_pointer\s*\('),
]

func_head = re.compile(r'^[A-Za-z_][\w\s\*,\(\)\[\]]*?\b(\w+)\s*\([^;]*$')

def function_spans(lines):
    starts = []
    for i, line in enumerate(lines):
        if line.startswith(('if','for','while','switch','return','}','#','else','do')):
            continue
        m = func_head.match(line)
        if not m:
            continue
        # look ahead for '{' before ';' to confirm function def
        buf = line
        for j in range(i, min(i+6, len(lines))):
            buf = lines[j]
            if ';' in buf and '{' not in buf:
                break
            if '{' in buf:
                starts.append((i, m.group(1)))
                break
    spans = []
    for idx, (s, name) in enumerate(starts):
        e = starts[idx+1][0] if idx+1 < len(starts) else len(lines)
        spans.append((s, e, name))
    return spans

out = []
for dirpath, dirs, files in os.walk(root):
    for fn in files:
        if not fn.endswith('.c'):
            continue
        path = os.path.join(dirpath, fn)
        try:
            lines = open(path, errors='replace').read().split('\n')
        except Exception:
            continue
        spans = function_spans(lines)
        for (s, e, name) in spans:
            body = lines[s:e]
            # captures in this function: var -> line idx
            caps = {}
            for k, line in enumerate(body):
                for p in patterns:
                    for m in p.finditer(line):
                        v = m.group('var')
                        caps.setdefault(v, s+k)
            if not caps:
                continue
            # pull lines
            pulls = [s+k for k, line in enumerate(body) if pull_re.search(line)]
            if not pulls:
                continue
            for var, cline in caps.items():
                for pl in pulls:
                    if pl <= cline:
                        continue
                    # look for use of var after pull until function end
                    uses = []
                    for k in range(pl, e):
                        line = lines[k]
                        if re.search(r'\b'+re.escape(var)+r'\s*(->|\.|\[|=)', line):
                            # skip reassignment (refetch)
                            m2 = re.search(r'\b'+re.escape(var)+r'\s*=\s*(?!;)', line)
                            if m2:
                                continue
                            uses.append((k+1, line.strip()[:100]))
                    if uses:
                        out.append((path, name, var, cline+1, pl+1, uses[:4]))

for o in out:
    print(o)
