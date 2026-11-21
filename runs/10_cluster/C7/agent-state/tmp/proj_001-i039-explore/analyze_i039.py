import re, os, json, sys, collections

ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s10"

TASK_RE=re.compile(r"tasklet(?:_init)?\s*\(\s*[^,]+,\s*(?:\(void\s*\*\s*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)")
NAPI_RE=re.compile(r"netif_napi_add\s*\(([^;]*)\);")

def find_files():
    for dp,dn,fn in os.walk(ROOT):
        if "/.git" in dp: dn[:]=[]; continue
        for f in fn:
            if f.endswith((".c",".h")):
                yield os.path.join(dp,f)

def extract_functions(txt):
    """Return list of (name, start_line, body_string, body_start_line)."""
    funcs=[]
    lines=txt.split("\n")
    i=0
    n=len(lines)
    func_hdr=re.compile(r"^([A-Za-z_][A-Za-z0-9_ \t\*]*)\(([;{])")
    while i<n:
        line=lines[i]
        m=re.match(r"^[A-Za-z_][A-Za-z0-9_ \t\*]*\*?\s*\*?([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
        if m and not line.strip().startswith("#") and not re.match(r"^\s*(if|for|while|switch|return|else)", line):
            # find the opening brace at col 0 on a subsequent line within 15 lines
            j=i
            depth_paren=0; seen_open=False
            hdr=""
            while j<n and j-i<30:
                hdr+=lines[j]+"\n"
                depth_paren+=lines[j].count("(")-lines[j].count(")")
                if depth_paren==0 and "{" in lines[j]:
                    # body starts
                    bstart=hdr.index("{")
                    # brace match over full txt
                    char_off=sum(len(x)+1 for x in lines[:j])+bstart
                    depth=0; k=char_off
                    while k<len(txt):
                        c=txt[k]
                        if c=="{": depth+=1
                        elif c=="}":
                            depth-=1
                            if depth==0:
                                body=txt[char_off+1:k]
                                start_ln=i+1
                                body_start=txt.count("\n",0,char_off)+1
                                funcs.append((m.group(1), start_ln, body, body_start))
                                i=txt.count("\n",0,k)
                                break
                        k+=1
                    break
                if depth_paren==0 and ";" in lines[j]:
                    break
                j+=1
        i+=1
    return funcs

LOCK_RE=re.compile(r"spin_(?:try_)?lock(?:_irqsave|_irqsave_nested|_irq|_irqrestore|_bh|_nested)?\s*\(\s*([^;{]*?)\s*\)")
# context hint regexes
PROC_HINTS=re.compile(r"\b(mutex_lock|mutex_unlock|msleep|usleep_range|schedule_timeout|wait_for_completion|copy_(from|to)_user|request_firmware|kzalloc\([^)]*GFP_KERNEL|kmalloc\([^)]*GFP_KERNEL|dev_err|napi_disable|napi_enable|netif_tx_disable)\b")

def lock_flavor(call):
    if call.startswith("spin_try_lock"): return "try"
    for suf in ("_irqsave","_irq","_irqrestore","_bh","_nested"):
        if call.startswith("spin_lock"+suf): return suf
    return "plain"

def base_lock(expr):
    expr=expr.strip()
    expr=re.sub(r"^&","",expr)
    # take last member/name token
    m=re.search(r"([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?)$", expr)
    return m.group(1) if m else expr

results={}  # file -> {lockbase: {"sites":[(flavor,line,func)], ...}}

for p in find_files():
    try: txt=open(p,errors="ignore").read()
    except: continue
    rel=os.path.relpath(p,ROOT)
    task_cbs=set()
    for m in TASK_RE.finditer(txt):
        task_cbs.add(m.group(1))
    napi_cbs=set()
    for m in NAPI_RE.finditer(txt):
        args=m.group(1)
        parts=[]
        depth=0; cur=""
        for ch in args:
            if ch=="(" : depth+=1; cur+=ch
            elif ch==")": depth-=1; cur+=ch
            elif ch=="," and depth==0:
                parts.append(cur); cur=""
            else: cur+=ch
        parts.append(cur)
        if len(parts)>=3:
            poll=parts[2].strip()
            nm=re.match(r"([A-Za-z_][A-Za-z0-9_]*)",poll)
            if nm: napi_cbs.add(nm.group(1))
    if not task_cbs and not napi_cbs:
        continue
    funcs=extract_functions(txt)
    for (name, sl, body, body_start) in funcs:
        soft = name in task_cbs or name in napi_cbs
        if not soft: continue
        for lm in LOCK_RE.finditer(body):
            call=lm.group(0)
            flavor=lock_flavor(call.split("(")[0])
            expr=lm.group(1)
            lb=base_lock(expr)
            ln=body_start+body.count("\n",0,lm.start())
            results.setdefault(rel,{}).setdefault(lb,[]).append((flavor,ln,name,"SOFTIRQ", "tasklet" if name in task_cbs else "napi"))
    # also record non-softirq functions' acquisitions for shared locks (2nd pass per file)
    softlocks={lb for lb,d in results.get(rel,{}).items()}
    for (name, sl, body, body_start) in funcs:
        if name in task_cbs or name in napi_cbs: continue
        found=[(m.group(0),m.group(1)) for m in LOCK_RE.finditer(body)]
        locks_here={base_lock(e) for _,e in found}
        shared=locks_here & softlocks
        if not shared: continue
        for (call,expr) in found:
            lb=base_lock(expr)
            if lb not in softlocks: continue
            flavor=lock_flavor(call.split("(")[0])
            ln=body_start+body.count("\n",0,call and found and 0 or 0) if False else None
            # recompute line
            pass
        for lm in LOCK_RE.finditer(body):
            call=lm.group(0)
            flavor=lock_flavor(call.split("(")[0])
            lb=base_lock(lm.group(1))
            if lb not in softlocks: continue
            ln=body_start+body.count("\n",0,lm.start())
            proc_hint = bool(PROC_HINTS.search(body))
            results[rel][lb].append((flavor,ln,name,"OTHER"+(" proc-hint" if proc_hint else ""), ""))

# Report: groups where softirq side has plain AND other side has plain
report=[]
for rel in sorted(results):
    for lb, sites in results[rel].items():
        soft_plain=[s for s in sites if s[3]=="SOFTIRQ" and s[0]=="plain"]
        if not soft_plain: continue
        others=[s for s in sites if s[3]!="SOFTIRQ"]
        other_plain=[s for s in others if s[0]=="plain"]
        bh_uses=[s for s in others if s[0]=="_bh"]
        report.append({"file":rel,"lock":lb,
            "soft_plain":soft_plain,"other_plain":other_plain,"other_bh":bh_uses,
            "other_all":others})
print(json.dumps([{"file":r["file"],"lock":r["lock"],
   "soft_plain":[f"{x[2]}:{x[1]}({x[4]})" for x in r["soft_plain"]],
   "other_plain":[f"{x[2]}:{x[1]}{'*P' if 'proc-hint' in x[3] else ''}" for x in r["other_plain"]],
   "other_bh":[f"{x[2]}:{x[1]}" for x in r["other_bh"]],
   } for r in report], indent=1))
