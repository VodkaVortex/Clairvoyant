import os, re, sys, json

root = "."

# find files that contain both header-pointer capture and pull calls
pull_re = re.compile(r'\bpskb_may_pull\s*\(|\bpskb_pull\s*\(|\bpskb_pull_reserve\s*\(|\b__pskb_pull_tail\s*\(|\bskb_linearize\s*\(')
hdrptr_re = re.compile(r'\bskb_header_pointer\s*\(|\(struct\s+\w+\s*\*\)\s*skb->data|skb_network_header\s*\(\s*skb\s*\)|skb_transport_header\s*\(\s*skb\s*\)|ip_hdr\s*\(\s*skb\s*\)|ipv6_hdr\s*\(\s*skb\s*\)|icmp_hdr\s*\(\s*skb\s*\)|tcp_hdr\s*\(\s*skb\s*\)|udp_hdr\s*\(\s*skb\s*\)|eth_hdr\s*\(\s*skb\s*\)')

results = []
for dirpath, dirnames, filenames in os.walk(root):
    for fn in filenames:
        if not fn.endswith('.c'):
            continue
        path = os.path.join(dirpath, fn)
        try:
            with open(path, 'r', errors='replace') as f:
                text = f.read()
        except OSError:
            continue
        if 'pskb_may_pull' not in text and 'pskb_pull' not in text and '__pskb_pull_tail' not in text and 'skb_linearize' not in text:
            continue
        results.append(path)

print("\n".join(results))
