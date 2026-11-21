import re, os, sys, subprocess

root = "snapshots/s05"
# files with gro handlers in s05
files = subprocess.run(["grep","-rl","_gro_receive\\|_gro_complete\\|gso_segment","net","drivers","--include=*.c"],
                       capture_output=True, text=True).stdout.split()

realloc = re.compile(r'\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|skb_gro_header_slow|skb_gro_remcsum_process|skb_gro_receive|skb_share_check|skb_unclone|__pskb_pull|skb_segment|skb_vlan_untag|__skb_vlan_pop|skb_checksum_help|pskb_trim)\s*\(')
decl = re.compile(r'^\t(?:const\s+)?(?:struct\s+\w+|unsigned char|char|void|__be\d+|u\d+|u8|u16|u32)\s*\*?\s*(\w+)\s*(?:=|;|,|\))')

interesting = []
for f in files:
    try:
        lines = open(os.path.join(root,f), errors="ignore").read().splitlines()
    except: continue
    # find function boundaries crudely: lines starting non-tab at col0 with '{' style
    funcs = []  # (start,end)
    start=None; fname=None
    for i,l in enumerate(lines):
        m = re.match(r'^(\w[\w\s\*,\(\)]*?)\)\s*$', l)
        if re.match(r'^[A-Za-z_].*\)\s*$', l) and not l.startswith(('if','for','while','switch','return','}')):
            pass
        if re.match(r'^\{', l) and fname is None:
            fname = lines[i-1].strip()
            start = i
        if start is not None and re.match(r'^\}', l):
            funcs.append((fname,start,i))
            fname=None; start=None
    for (fn,s,e) in funcs:
        body = lines[s:e+1]
        pulls = [j+s for j,l in enumerate(body) if realloc.search(l)]
        if not pulls: continue
        for j,l in enumerate(body):
            dm = re.match(r'^\t(?:const\s+)?(?:struct\s+\w+|unsigned char|char|void)\s*\*\s*(\w+)\s*=\s*(.+);', l)
            if not dm: continue
            var, rhs = dm.group(1), dm.group(2)
            if not re.search(r'skb|hdr|data|frag|p->|gro', rhs): continue
            cap = j+s
            # find deref of var after first pull
            for pu in pulls:
                if pu > cap:
                    for k in range(pu+1, e+1):
                        if re.search(r'\b'+re.escape(var)+r'\b\s*(->|\[|\.)|->\s*'+re.escape(var)+r'\b', lines[k]):
                            interesting.append((f,fn,cap+1,pu+1,k+1,var,lines[cap].strip(),lines[k].strip()))
                            break
                    break
for t in interesting:
    print(f"{t[0]}:{t[2]} fn={t[1]!r} cap[{t[5]}] pull@{t[3]} use@{t[4]} :: {t[6]}  ==> {t[7]}")
