import re, os
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s14"

def find_functions(lines):
    """kernel-style: '{' at col 0 opens a function body; '}' at col 0 closes it.
    returns name -> list of (body_start_line, body_end_line) 1-based inclusive."""
    funcs={}
    n=len(lines)
    i=0
    while i<n:
        if lines[i].startswith("{"):
            # find closing '}' at col 0, with comment/string awareness
            j=i; depth=0; in_block=False; in_str=None; closed=None
            while j<n:
                raw=lines[j]; p=0
                if j==i: p=1  # skip the opening brace char itself? count it below via depth init
                # simpler: handle col-0 braces separately
                if j==i: depth=1
                while p<len(raw):
                    ch=raw[p]
                    if in_block:
                        if ch=="*" and p+1<len(raw) and raw[p+1]=="/": in_block=False; p+=1
                        p+=1; continue
                    if in_str:
                        if ch=="\\": p+=2; continue
                        if ch==in_str: in_str=None
                        p+=1; continue
                    if ch=="/" and p+1<len(raw) and raw[p+1]=="*": in_block=True; p+=2; continue
                    if ch=="/" and p+1<len(raw) and raw[p+1]=="/": break
                    if ch=='"': in_str='"'; p+=1; continue
                    if ch=="'": in_str="'"; p+=1; continue
                    if ch=="{": depth+=1
                    elif ch=="}":
                        depth-=1
                        if depth<=0 and lines[j].startswith("}"):
                            closed=j; break
                    p+=1
                if closed is not None: break
                j+=1
            if closed is None:
                i+=1; continue
            # identify name: walk back from i-1 to find identifier before first '('
            name=None
            k=i-1
            while k>=0 and k>=i-12:
                t=lines[k]
                if "/*" in t:  # may be inside decl comment; still try
                    pass
                m=re.match(r'^\s*(?:[A-Za-z_][\w\s\*,\(\)]*?)?\b([A-Za-z_]\w*)\s*\(', t)
                if m:
                    cand=m.group(1)
                    if cand not in ("if","for","while","switch","return","sizeof","defined","do","else"):
                        name=cand; break
                if t.strip()=="" or t.strip().endswith(";"):
                    # keep walking a bit: signature may span lines
                    pass
                if t.strip().endswith(";"):
                    break
                k-=1
            if name:
                funcs.setdefault(name,[]).append((i+1, closed+1))
            i=closed+1
        else:
            i+=1
    return funcs

if __name__=="__main__":
    import sys
    rel=sys.argv[1]
    with open(os.path.join(ROOT,rel),errors="replace") as fh: lines=fh.read().split("\n")
    f=find_functions(lines)
    print(len(f), "functions")
    for k,v in list(f.items())[:10]: print(k,v)
