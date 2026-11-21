import os, re, sys, json

ROOT = "."

# restrict to net/ and drivers/ .c/.h files
files = []
for base in ["net", "drivers"]:
    for dirpath, dirs, fnames in os.walk(os.path.join(ROOT, base)):
        for f in fnames:
            if f.endswith((".c", ".h")):
                files.append(os.path.join(dirpath, f))

# relocating call regexes
RELOC = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|skb_unclone|pskb_expand_head|skb_share_check|skb_linearize_cow|skb_cow_data|ip_mc_may_pull|ipv6_mc_may_pull)\s*\(')

# capture regex: pointer into skb head/data. Broad forms:
#  type *var = skb->data; / (cast)skb->data
#  type *var = <something>_hdr(skb);
#  type *var = skb_header_pointer(...);
CAPTURE = re.compile(r'^\s*(?:const\s+)?struct\s+\w+\s*\*\s*(\w+)\s*=\s*([^;]+);')
CAPTURE2 = re.compile(r'^\s*(?:const\s+)?\w+\s*\*\s*(\w+)\s*=\s*(?:\([^)]*\)\s*)?(skb->data|skb_network_header\s*\(\s*\w+\s*\)|skb_mac_header\s*\(\s*\w+\s*\)|skb_transport_header\s*\(\s*\w+\s*\)|skb_tail_pointer\s*\(\s*\w+\s*\)|skb_header_pointer\s*\([^;]*)\s*;')
HDRASSIGN = re.compile(r'^\s*(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:skb|[^;]*->skb|[^;]*skb)\s*->\s*data\s*;')

FUNC_RE = re.compile(r'^(\w[\w\s\*]*?)\b(\w+)\s*\([^;]*\)\s*$')

def func_spans(text):
    """yield (startline, endline, name) for top-level function bodies"""
    lines = text.split("\n")
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        m = re.match(r'^(\w[\w \t\*]*?)\b(\w+)\s*\(', line)
        if m and not line.strip().endswith(";") and "=" not in line.split("(")[0]:
            # find opening brace
            j = i
            depth = 0
            started = False
            while j < n:
                for ch in lines[j]:
                    if ch == "{":
                        depth += 1
                        started = True
                    elif ch == "}":
                        depth -= 1
                        if started and depth == 0:
                            yield (i, j, m.group(2))
                            i = j + 1
                            break
                if started and depth <= 0:
                    break
                j += 1
            i = j + 1
            continue
        i += 1

pairs = []
callers_with_capture = []
for path in files:
    try:
        text = open(path, errors="ignore").read()
    except Exception:
        continue
    for (s, e, fname) in func_spans(text):
        body = "\n".join(text.split("\n")[s:e+1])
        if not RELOC.search(body):
            continue
        # this function is a "callee" that relocates
        pairs.append((path, fname, s+1, e+1))

print("### CALLEES-THAT-RELOCATE:", len(pairs))
json.dump(pairs, open(sys.argv[1] if len(sys.argv)>1 else "callees.json", "w"))
