import os, re, sys, json

ROOT = "."
base_files = []
for base in ["net", "drivers"]:
    for dirpath, dirs, fnames in os.walk(os.path.join(ROOT, base)):
        for f in fnames:
            if f.endswith((".c", ".h")):
                base_files.append(os.path.join(dirpath, f))

callees = json.load(open(sys.argv[1]))
# map function name -> whether it relocates
callee_names = set(c[1] for c in callees)

# we need per-file text
texts = {}
for p in set(base_files):
    try:
        texts[p] = open(p, errors="ignore").read()
    except Exception:
        pass

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

CAPTURE_RE = re.compile(r'^\s*(?:const\s+)?(?:struct\s+)?\w[\w\s]*?\s*\*\s*(\w+)\s*=\s*(?:\([^)]*\)\s*)?((?:skb|[^;=\s]*skb[^;=\s]*)\s*->\s*data|ip_hdr\s*\(|ipv6_hdr\s*\(|tcp_hdr\s*\(|udp_hdr\s*\(|icmp_hdr\s*\(|icmp6_hdr\s*\(|eth_hdr\s*\(|mpls_hdr\s*\(|skb_network_header\s*\(|skb_transport_header\s*\(|skb_mac_header\s*\(|skb_header_pointer\s*\()')

results = []
for path, txt in texts.items():
    for (s, e, fname) in func_spans(txt):
        lines = txt.split("\n")[s:e+1]
        # find capture vars
        captures = []  # (lineno_abs, varname)
        for idx, line in enumerate(lines):
            m = CAPTURE_RE.match(line)
            if m:
                captures.append((s + idx + 1, m.group(1)))
        if not captures:
            continue
        # find calls to relocating callees
        for idx, line in enumerate(lines):
            for cn in callee_names:
                # match direct call callee( or ->callee( — skip if it's the definition line
                if re.search(r'(?<![\w.>])' + re.escape(cn) + r'\s*\(', line):
                    # not a definition (would be at function start)
                    if s + idx + 1 == s + 1 and re.match(r'^\s*\w', line) and "{" not in "".join(lines[:2]):
                        pass
                    for (clineno, var) in captures:
                        if clineno < s + idx + 1:
                            # check var used after the call line
                            after = "\n".join(lines[idx+1:])
                            if re.search(r'\b' + re.escape(var) + r'\b', after):
                                results.append((path, fname, s+1, clineno, var, cn, s+idx+1))
    if len(results) > 4000:
        break

print("### CAPTURE->CALLEE(RELOC)->USE chains:", len(results))
json.dump(results, open(sys.argv[2], "w"))
