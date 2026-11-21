import re, sys, json

path = sys.argv[1]
with open(path, 'r', errors='replace') as f:
    lines = f.readlines()

pull_re = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize)\s*\(')
# pointer capture: ident = <something>(skb...) or ident = (struct X *)skb->data etc.
assign_ptr_re = re.compile(r'^\s*(?:const\s+)?(?:struct\s+)?(\w+)\s*\*\s*(\w+)\s*=')
skbpull_count = 0

# Track function boundaries (crude: lines starting with '{' at col0 -> function body start)
func_start = 0
findings = []
for i, line in enumerate(lines):
    if line.startswith('{'):
        func_start = i
    if pull_re.search(line):
        skbpull_count += 1
        # look back up to 60 lines for pointer captures from skb
        for j in range(max(func_start, i-60), i):
            m = assign_ptr_re.match(lines[j])
            if m:
                typ, var = m.group(1), m.group(2)
                rhs = lines[j][lines[j].find('=')+1:]
                # capture must come from skb
                if 'skb' in rhs and ('header_pointer' in rhs or 'skb->data' in rhs or '_hdr(skb' in rhs or 'skb_network_header' in rhs or 'skb_transport_header' in rhs or 'pskb_may_pull' in rhs):
                    # look after pull for uses of var (max 80 lines, stop at next function)
                    for k in range(i+1, min(len(lines), i+80)):
                        if lines[k].startswith('}'):
                            pass
                        # dereference or reassignment?
                        if re.search(r'\b'+re.escape(var)+r'\b', lines[k]):
                            if re.search(r'\b'+re.escape(var)+r'\s*=\s*', lines[k]) and '==' not in lines[k]:
                                break  # reassigned -> refetch, stop
                            if var + ' ==' in lines[k] or var + '!=' in lines[k] or var + ' == NULL' in lines[k]:
                                continue
                            findings.append((path, j+1, i+1, k+1, lines[j].strip(), lines[i].strip(), lines[k].strip()))
                            break
for f in findings:
    print(json.dumps({"file": f[0], "capture_line": f[1], "pull_line": f[2], "use_line": f[3],
                      "capture": f[4], "pull": f[5], "use": f[6]}))
