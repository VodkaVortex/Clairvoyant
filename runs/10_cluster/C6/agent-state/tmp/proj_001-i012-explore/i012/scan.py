import os, re, sys
root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s04"
pull_re = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|__skb_linearize|pskb_expand_head|skb_cow|skb_cow_head|skb_unclone|skb_share_check)\s*\(')
cap_re = re.compile(
    r'^\s*(?:const\s+)?(?:struct\s+|unsigned\s+char\s*|u8\s*|u16\s*|char\s*)?[\w:]*\s*\*+\s*([A-Za-z_]\w*)\s*=\s*(skb_header_pointer\s*\(|\(.*?\s*\*\s*\)\s*(skb|skb->data|skb_network_header|skb_transport_header|skb_mac_header)|[a-z_]+_hdr\s*\(\s*skb)'  )
results=[]
for dirpath, dirs, files in os.walk(root):
    if '/.git' in dirpath: continue
    for fn in files:
        if not fn.endswith('.c'): continue
        p=os.path.join(dirpath,fn)
        rel=os.path.relpath(p,root)
        if not (rel.startswith('net/') or rel.startswith('drivers/')): continue
        try: lines=open(p,encoding='utf-8',errors='replace').read().splitlines()
        except: continue
        # collect function boundaries roughly: lines that start at col0 with type then name(
        func_starts=[i for i,l in enumerate(lines) if re.match(r'^[A-Za-z_].*\(.*\)\s*$', l) or re.match(r'^[A-Za-z_].*\(', l)]
        for i,l in enumerate(lines):
            m=pull_re.search(l)
            if not m: continue
            # find enclosing function start: search backwards for a line matching function def heuristic
            fs=None
            for j in range(i-1,max(-1,i-400),-1):
                lj=lines[j]
                if re.match(r'^[A-Za-z_].*\)\s*$', lj) or re.match(r'^(static\s+)?[A-Za-z_][\w\s\*]*\(', lj) and not lj.startswith(('if','for','while','switch','return')):
                    # crude: function def lines start at col 0 and contain '(' ; not control keywords
                    if re.match(r'^[A-Za-z_][\w\s\*\(\)]*\(', lj) and not re.match(r'^(if|for|while|switch|return|else|goto)\b', lj):
                        fs=j; break
            if fs is None: continue
            # function end: next line at col0 that is '}' 
            fe=i
            for j in range(i+1,min(len(lines),i+600)):
                if lines[j].startswith('}'): fe=j; break
            body=[(k,lines[k]) for k in range(fs,fe+1)]
            caps=[]
            for k,bl in body:
                cm=cap_re.search(bl)
                if cm and k<=i:
                    caps.append((k,cm.group(1),bl.strip()))
            if not caps: continue
            # check any cap var used after the pull line
            for (ck,cv,cexpr) in caps:
                uses=[]
                for k in range(i+1,fe+1):
                    if re.search(r'\b'+re.escape(cv)+r'\s*(->|\[|\.|\))', lines[k]) or re.search(r'\b'+re.escape(cv)+r'\b\s*[,);]', lines[k]):
                        uses.append((k,lines[k].strip()))
                # refetch check: is var reassigned between pull and use?
                reassigned=any(re.match(r'.*\b'+re.escape(cv)+r'\s*=', lines[k]) for k in range(i+1,fe+1))
                if uses and not reassigned:
                    results.append((rel,fs+1,i+1,cv,ck+1,cexpr,uses[:6]))
for r in results:
    print(f"{r[0]} func@{r[1]} pull@{r[2]} var={r[3]} cap@{r[4]} | {r[5][:90]}")
    for (uk,ul) in r[6]:
        print(f"     use@{uk}: {ul[:100]}")
    print()
