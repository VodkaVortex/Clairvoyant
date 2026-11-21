#!/usr/bin/env python3
"""Static heuristic scan for the pep_get_sb() pattern in snapshots/s01:
capture a header pointer (skb_header_pointer or skb->data cast or *_hdr(skb) accessor),
then call a head-reallocating pull (pskb_may_pull/pskb_pull/__pskb_pull_tail/
pskb_pull_reserve/skb_linearize) later in the SAME function, then dereference the
captured pointer after the pull without reassignment."""
import re, os, sys, subprocess

SNAP = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s01"

# get files with pull APIs
out = subprocess.run(["/usr/bin/rg", "-n", r"pskb_may_pull|pskb_pull\(|pskb_pull_reserve|__pskb_pull_tail|skb_linearize\(", "net/", "--type", "c", "-l"],
                     cwd=SNAP, capture_output=True, text=True)
files = [f for f in out.stdout.splitlines() if f.strip()]
print(f"#files with pull APIs: {len(files)}", file=sys.stderr)

PULL_RE = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|__skb_linearize|__pskb_pull)\s*\(')
CAPTURE_RE = re.compile(
    r'^\s*(?:const\s+)?(?:struct\s+)?(\w+)\s*\*\s*(\w+)\s*=\s*(.+?);')
HDR_ACCESSOR = re.compile(r'(skb_header_pointer|ip_hdr|ipv6_hdr|tcp_hdr|udp_hdr|icmp_hdr|icmp6_hdr|eth_hdr|\(struct \w+ \*\)\s*(?:skb|[^;]*->data)|->data\b|skb_network_header|skb_transport_header|skb_mac_header|skb_tail_pointer)')

def deref(var):
    return re.compile(r'\b' + re.escape(var) + r'\s*(->|\.)|\*\s*' + re.escape(var) + r'\b|->' + re.escape(var) + r'\b|\[' + re.escape(var) + r'\]')

def find_function_bounds(lines, idx):
    """return (start,end) line indexes (0-based) of function containing idx, by brace matching backwards"""
    # find enclosing braces: scan backward for '{' at depth0 relative... simpler: record all top-level funcs
    pass

results = []
for path in files:
    full = os.path.join(SNAP, path)
    try:
        with open(full, errors='replace') as f:
            src = f.read()
    except Exception:
        continue
    lines = src.split('\n')
    # build a function index: line -> func start/end via simple brace tracking at col0
    # Precompute mapping of each line to its enclosing top-level function
    # A top-level function starts at a line matching r'^\w.*\(' at indent 0 and its body '{...}'
    func_spans = []  # (start_line_idx, end_line_idx)
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if re.match(r'^[A-Za-z_]', line) and ('(' in line or (i+1<n and '(' in lines[i+1])):
            # candidate definition start; find first '{' after
            j = i
            depth = 0
            started = False
            while j < n:
                for ch in lines[j]:
                    if ch == '{':
                        depth += 1
                        started = True
                    elif ch == '}':
                        depth -= 1
                        if started and depth == 0:
                            func_spans.append((i, j))
                            j = n
                            break
                j += 1
            i = j if j < n else n
        else:
            i += 1
    for (fs, fe) in func_spans:
        body_lines = lines[fs:fe+1]
        # find captures
        for k, bl in enumerate(body_lines):
            m = CAPTURE_RE.match(bl)
            if not m:
                continue
            typ, var, expr = m.group(1), m.group(2), m.group(3)
            if var in ('skb','data','p','q','buf','cp','sp','dp','to','from','dst','src','s','d','start','end','pos','cur','next','hdr_end'):
                # still allow data if it's from skb->data? keep but low
                pass
            if not HDR_ACCESSOR.search(expr):
                continue
            # check any pull after this line within function
            for k2 in range(k+1, len(body_lines)):
                if PULL_RE.search(body_lines[k2]):
                    pull_line = k2
                    # check deref of var after pull without reassignment
                    reassigned = False
                    stale_uses = []
                    for k3 in range(pull_line+1, len(body_lines)):
                        b3 = body_lines[k3]
                        if re.match(r'^\s*(?:const\s+)?(?:struct\s+)?\w+\s*\*\s*' + re.escape(var) + r'\s*=', b3):
                            reassigned = True
                            break
                        if re.search(r'\b' + re.escape(var) + r'\s*=', b3) and not re.search(r'==', b3):
                            reassigned = True
                            break
                        dm = re.search(r'\b' + re.escape(var) + r'\s*(->|\.)\w', b3)
                        if dm and 'if' not in b3.split(var)[0][:20]:
                            stale_uses.append((fs+k3+1, b3.strip()[:120]))
                        elif dm:
                            stale_uses.append((fs+k3+1, b3.strip()[:120]))
                    if stale_uses and not reassigned:
                        results.append((path, fs+k+1, bl.strip()[:120], fs+pull_line+1, body_lines[pull_line].strip()[:100], stale_uses[:6]))
                    break  # only first pull after capture

print("PATH\tCAPTURE_LINE\tCAPTURE\tPULL_LINE\tPULL\tSTALE_USES")
for r in results:
    uses = "; ".join(f"{l}:{t}" for l, t in r[5])
    print(f"{r[0]}\t{r[1]}\t{r[2][:80]}\t{r[3]}\t{r[4][:60]}\t{uses[:300]}")
