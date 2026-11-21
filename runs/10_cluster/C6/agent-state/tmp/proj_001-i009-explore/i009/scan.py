import re, os, sys, json

PULL_RE = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize)\s*\(')
CAPTURE_TYPES = r'(?:const\s+)?(?:struct\s+\w+|unsigned\s+char|u8|u16|u32|__be16|__be32|__wsum|void|char)'
CAPTURE_RE = re.compile(r'^(?P<indent>\s*)' + CAPTURE_TYPES + r'\s*\**\s*(?P<var>\w+)\s*=\s*(?P<rhs>[^;]+);$')
RHS_HINT = re.compile(r'skb->data|skb_header_pointer|_hdr\(skb|mpls_hdr\(|skb_network_header|skb_transport_header|skb_mac_header|skb->head|skb_tail_pointer')

def find_func_bounds(lines, idx):
    start = idx
    while start > 0:
        s = lines[start]
        if s.startswith('{') or (s.rstrip().endswith('{') and not s[0].isspace()):
            break
        start -= 1
    depth = 0
    end = start
    i = start
    while i < len(lines):
        depth += lines[i].count('{') - lines[i].count('}')
        if i > start and depth <= 0:
            end = i
            break
        if i == start and depth <= 0 and '{' in lines[start]:
            end = i
            break
        i += 1
    return start, min(end, len(lines)-1)

def scan_file(path):
    results = []
    with open(path, 'r', errors='replace') as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        if not PULL_RE.search(line):
            continue
        try:
            fs, fe = find_func_bounds(lines, i)
        except Exception:
            continue
        if fs >= fe:
            continue
        captures = []
        for j in range(fs, i+1):
            cm = CAPTURE_RE.match(lines[j])
            if cm:
                var = cm.group('var')
                rhs = cm.group('rhs')
                if RHS_HINT.search(rhs):
                    captures.append((j, var, rhs.strip()))
        if not captures:
            continue
        for (cj, var, rhs) in captures:
            uses = []
            refetch = False
            for j in range(i+1, fe+1):
                l = lines[j]
                if re.match(r'^\s*' + re.escape(var) + r'\s*=[^=]', l):
                    refetch = True
                    break
                if re.search(r'\b' + re.escape(var) + r'\b', l):
                    uses.append((j+1, l.strip()[:120]))
            if uses and not refetch:
                results.append({
                    'file': path,
                    'func_start': fs+1,
                    'pull_line': i+1,
                    'pull': line.strip()[:120],
                    'capture_line': cj+1,
                    'capture': '%s = %s' % (var, rhs)[:150],
                    'uses': uses[:8],
                })
    return results

base = os.getcwd()
allres = []
with open(sys.argv[1]) as f:
    for rel in f.read().split():
        path = rel if rel.startswith('/') else os.path.join(base, rel)
        if not os.path.exists(path):
            continue
        try:
            allres.extend(scan_file(path))
        except Exception:
            pass
print(json.dumps(allres, indent=1))
