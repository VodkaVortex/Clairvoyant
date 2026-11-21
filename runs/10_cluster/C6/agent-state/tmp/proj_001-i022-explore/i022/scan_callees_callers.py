import os, re, sys, json, pickle

ROOT = "."
files = []
for base in ["net", "drivers"]:
    for dirpath, dirs, fnames in os.walk(os.path.join(ROOT, base)):
        for f in fnames:
            if f.endswith((".c", ".h")):
                files.append(os.path.join(dirpath, f))

RELOC = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|skb_unclone|pskb_expand_head|skb_share_check|skb_cow_data)\s*\(')

def func_spans(text):
    lines = text.split("\n")
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        m = re.match(r'^(\w[\w \t\*]*?)\b(\w+)\s*\(', line)
        if m and not line.strip().endswith(";") and "=" not in line.split("(")[0]:
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

# Build: relocating function names -> set of files where defined
reloc_funcs = {}   # name -> list of (path, startline, endline)
callers = {}       # (path, callername) -> list of callsites
texts = {}
for path in files:
    try:
        txt = open(path, errors="ignore").read()
        texts[path] = txt
    except Exception:
        continue
    for (s, e, fname) in func_spans(txt):
        body = "\n".join(txt.split("\n")[s:e+1])
        if RELOC.search(body):
            reloc_funcs.setdefault(fname, []).append((path, s+1, e+1))

print("relocating functions:", sum(len(v) for v in reloc_funcs.values()), "unique names:", len(reloc_funcs))

# Now find callers: functions that call any relocating function name AND capture a header pointer before the call and use it after
CAPTURE_RE = re.compile(r'^\s*(?:const\s+)?(?:struct\s+)?\w[\w\s]*?\s*\*\s*(\w+)\s*=\s*(?:\([^)]*\)\s*)?((?:\w*->)?skb\s*->\s*data|\w+->data|ip_hdr\s*\(|ipv6_hdr\s*\(|tcp_hdr\s*\(|udp_hdr\s*\(|icmp_hdr\s*\(|icmp6_hdr\s*\(|eth_hdr\s*\(|mpls_hdr\s*\(|gre_hdr\s*\(|skb_network_header\s*\(|skb_transport_header\s*\(|skb_mac_header\s*\(|skb_header_pointer\s*\(|noffi_hdr)')

chains = []
for path, txt in texts.items():
    for (s, e, fname) in func_spans(txt):
        lines = txt.split("\n")[s:e+1]
        captures = []
        for idx, line in enumerate(lines):
            m = CAPTURE_RE.match(line)
            if m:
                captures.append((idx, s+idx+1, m.group(1)))
        if not captures:
            continue
        for idx, line in enumerate(lines):
            for cn in reloc_funcs:
                if re.search(r'(?<![\w.>])' + re.escape(cn) + r'\s*\(', line):
                    # skip if this is the relocating function definition itself
                    if fname == cn:
                        continue
                    for (cidx, clineno, var) in captures:
                        if cidx < idx:
                            after = "\n".join(lines[idx+1:])
                            if re.search(r'\b' + re.escape(var) + r'\b', after):
                                chains.append({
                                    "path": path, "caller": fname, "caller_start": s+1,
                                    "capture_line": clineno, "var": var,
                                    "callee": cn, "call_line": s+idx+1
                                })
        if len(chains) > 3000: break
    if len(chains) > 3000: break

print("chains:", len(chains))
json.dump(chains, open(sys.argv[1], "w"))
