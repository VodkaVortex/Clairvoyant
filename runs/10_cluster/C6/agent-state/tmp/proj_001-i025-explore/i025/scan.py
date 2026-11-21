import re, os, sys
root="."
pulls=re.compile(r'\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|skb_cow|skb_cow_head|pskb_expand_head)\s*\(')
func_def=re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\(')
capt=re.compile(r'(?:const\s+)?struct\s+\w+\s*\*\s*(\w+)\s*=\s*(?:\(.*?\*\)\s*)?(?:skb(?:->skb)?\s*->\s*data|(\w+)\s*=\s*skb_header_pointer|\w+_hdr\(skb|skb_network_header\(skb|skb_transport_header\(skb|ipv6_hdr\(skb|ip_hdr\(skb|tcp_hdr\(skb|udp_hdr\(skb|icmp6_hdr\(skb|icmp_hdr\(skb|mpls_hdr\(skb|eth_hdr\(skb|gre_hdr\(skb|sctp_hdr\(skb)')
callre=re.compile(r'\b([a-z_][a-z0-9_]*)\s*\(\s*(?:[^();]*,\s*)?skb\b')
skbcallee={}
# collect files
files=[]
for d in ("net","drivers"):
    for dp,_,fns in os.walk(os.path.join(root,d)):
        for fn in fns:
            if fn.endswith((".c",".h")): files.append(os.path.join(dp,fn))
# build per-function index: name -> (file, start, end, has_pull, has_skb_param)
funcs={}
for f in files:
    try: lines=open(f,errors='ignore').read().split('\n')
    except: continue
    cur=None
    for i,l in enumerate(lines):
        m=func_def.match(l)
        if m and not l.strip().startswith(('if','for','while','switch','return','}')) and ('(' in l):
            cur={'name':m.group(1),'file':f,'start':i+1,'pull':False,'skbparam':('sk_buff' in l),'body':[]}
            if cur['name'] not in funcs: funcs[cur['name']]=[]
            funcs[cur['name']].append(cur)
        if cur is not None:
            cur['body'].append((i+1,l))
            if pulls.search(l): cur['pull']=True
            if l.startswith('}') and len(l)==1: cur=None
# candidate callees: functions with skb param (or unknown) that pull
cands=[]
for name,lst in funcs.items():
    for fn in lst:
        if fn['pull'] and len(fn['body'])<200:
            cands.append(fn)
callees=set(f['name'] for f in cands)
# now scan callers: capture pointer, call a pulling callee with skb, deref after
results=[]
for name,lst in funcs.items():
    for fn in lst:
        body=fn['body']
        captures=[]  # (line, var)
        calls=[]     # (line, callee)
        for ln,l in body:
            m=capt.search(l)
            if m: captures.append((ln,m.group(1),l.strip()))
            for cm in callre.finditer(l):
                cn=cm.group(1)
                if cn in callees and cn!=fn['name']: calls.append((ln,cn))
        if not captures or not calls: continue
        for (cl,var,src) in captures:
            for (dl,cn) in calls:
                if dl<=cl: continue
                # deref of var after call
                for ln,l in body:
                    if ln>dl and re.search(r'\b'+re.escape(var)+r'\s*(->|\[|\)|\+|;|\.|,)', l) and not re.search(r'\b'+re.escape(var)+r'\s*=', l):
                        results.append((fn['file'],fn['name'],cn,cl,src,dl,ln,l.strip()))
                        break
                else: continue
                break
seen=set(); out=[]
for r in results:
    k=(r[0],r[1],r[2],r[3])
    if k in seen: continue
    seen.add(k); out.append(r)
out.sort(key=lambda r:(r[0],r[3]))
for r in out[:80]:
    print(f"{r[0]}::{r[1]}() calls {r[2]}() | cap@{r[3]}: {r[4][:70]} | call@{r[5]} | use@{r[6]}: {r[7][:70]}")
print("TOTAL",len(out))
