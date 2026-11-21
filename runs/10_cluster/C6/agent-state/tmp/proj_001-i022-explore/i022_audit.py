import subprocess, re, os, sys, json

S = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s01"

RELOC = re.compile(r'\b(pskb_may_pull|__pskb_pull_tail|pskb_pull|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|skb_maybe_pull_tail|skb_copy_and_csum_datagram|skb_header_pointer|ip_mc_check|ipv6_mc_check)\s*\(')

def bash(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def readfile(path):
    with open(os.path.join(S, path), errors='replace') as f:
        return f.read().splitlines()

def func_spans(lines):
    spans = []
    cur = None; depth = 0; started = False
    for i, l in enumerate(lines):
        if cur is None:
            m = re.match(r'^[A-Za-z_].*\)\s*$', l) and ('(' in l) and not l.rstrip().endswith(';')
            if m and not l.startswith(('#','//','*','/*')) and not re.match(r'^(if|for|while|switch|return|else|do)\b', l):
                # heuristic start: previous line ends with '{' or this line does; find the '{'
                j = i
                # look ahead for '{' within this line or following lines before ';'
                k = i
                while k < len(lines) and k <= i + 6:
                    if '{' in lines[k]:
                        cur = (i, k)
                        depth = lines[k].count('{') - lines[k].count('}')
                        started = True
                        break
                    if ';' in lines[k] and k > i:
                        break
                    k += 1
        else:
            depth += l.count('{') - l.count('}')
            if depth <= 0:
                spans.append((cur[0], i))
                cur = None; started = False
    return spans

def is_ptr_into_skb(name, lines, fstart, fend):
    """check that variable name was captured as a pointer into skb head/data"""
    for i in range(fstart, min(fend, fstart+200)):
        l = lines[i]
        m = re.search(r'\b(?:struct\s+\S+|unsigned char|u8\s*\*|__be\d+\s*\*|void)\s*\*\s*' + re.escape(name) + r'\s*=', l)
        if m:
            rhs = l.split('=', 1)[1]
            if re.search(r'skb.*->(data|head|network_header)|skb_header_pointer|skb->data|_hdr\(|hdr\(skb\)|skb_network_header|skb_transport_header|skb_mac_header|skb_tail_pointer', rhs):
                return True, i+1, l.strip()
    return False, None, None

def caller_analysis(callees, dirs=('net', 'drivers')):
    # callees: dict name -> definition file
    results = []
    names = list(callees.keys())
    namepat = '|'.join(re.escape(n) for n in names)
    pat = re.compile(r'(?<![\w.>])(' + namepat + r')\s*\(\s*[&]?\s*(\w+)\s*[,)]')
    for d in dirs:
        out = bash(f"cd {S} && rg -l --no-messages '{namepat}' {d} --type c")
        for f in out.split():
            lines = readfile(f)
            spans = func_spans(lines)
            for i, l in enumerate(lines):
                m = pat.search(l)
                if m:
                    cname, skbarg = m.group(1), m.group(2)
                    fs = next(((a,b) for a,b in spans if a <= i <= b), None)
                    if not fs: continue
                    fstart, fend = fs
                    # capture in caller of a pointer into the same skb
                    body = '\n'.join(lines[fstart:fend+1])
                    # find candidate pointer vars captured into skb head via this skb
                    ptrvars = set(re.findall(r'(?:struct\s+\S+|unsigned char|u8|void|__be\d+)\s*\*\s*(\w+)\s*=\s*[^;]*' + re.escape(skbarg) + r'[^;]*(?:->data|_hdr\(|header|skb_header_pointer)', body))
                    ptrvars |= set(re.findall(r'(?:struct\s+\S+)\s*\*\s*(\w+)\s*=\s*(?:' + re.escape(skbarg) + r'->data|\(void \*\)' + re.escape(skbarg) + r'->data)', body))
                    ptrvars |= set(re.findall(r'(\w+)\s*=\s*skb_header_pointer\(\s*' + re.escape(skbarg), body))
                    ptrvars |= set(re.findall(r'(\w+)\s*=\s*\w+_hdr\(\s*' + re.escape(skbarg), body))
                    ptrvars |= set(re.findall(r'(\w+)\s*=\s*\w*network_header\(\s*' + re.escape(skbarg), body))
                    if not ptrvars: continue
                    # does the call appear after some capture, and is the ptr used after?
                    callpos = i
                    for pv in ptrvars:
                        capm = [j for j in range(fstart, fend+1) if re.search(r'\b'+re.escape(pv)+r'\s*=', lines[j]) and j < callpos]
                        usem = [j for j in range(callpos+1, fend+1) if re.search(r'\b'+re.escape(pv)+r'\s*(->|\[|\.|\))', lines[j])]
                        if capm and usem:
                            results.append((f, i+1, cname, skbarg, pv, capm[0]+1, usem[0]+1))
    return results

print(json.dumps({"status": "script ready"}))
