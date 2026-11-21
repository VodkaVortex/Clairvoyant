import os, re, sys, json, subprocess

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s14"

# 1. find irq registration sites
rg = subprocess.run(["rg","-n","--no-heading","-e",r"\b(request_irq|devm_request_irq|request_threaded_irq|devm_request_threaded_irq)\s*\(",
                     ROOT+"/drivers",ROOT+"/net",ROOT+"/sound",ROOT+"/arch",ROOT+"/fs"],
                    capture_output=True,text=True)
lines = rg.stdout.splitlines()
regs = []
rx_irq = re.compile(r"\b(request_irq|devm_request_irq|request_threaded_irq|devm_request_threaded_irq)\s*\(")
for ln in lines:
    m = rx_irq.search(ln)
    if not m: continue
    path, lineno, text = ln.split(":",2)
    # arg extraction
    i = ln.find(m.group(0))
    # arg splitting respecting parens
    args, depth, cur, instr = [], 0, "", False
    j = i + len(m.group(0)) - 1
    k = j
    while k < len(ln):
        c = ln[k]
        if instr:
            if c == '"' and ln[k-1] != '\\': instr=False
            cur += c; k+=1; continue
        if c == '"': instr=True; cur+=c; k+=1; continue
        if c == '(' or c=='[': depth+=1
        if c == ')' or c==']':
            depth-=1
            if depth==0:
                args.append(cur); break
        if c==',' and depth==1:
            args.append(cur); cur=""; k+=1; continue
        cur+=c; k+=1
    args=[a.strip() for a in args]
    fn = m.group(1)
    if fn in ("request_irq",):
        handler = args[1] if len(args)>1 else None
    elif fn=="devm_request_irq":
        handler = args[2] if len(args)>2 else None
    elif fn in ("request_threaded_irq",):
        handler = args[1] if len(args)>1 else None
    else: # devm_request_threaded_irq
        handler = args[2] if len(args)>2 else None
    regs.append((path,int(lineno),fn,handler))

print("registrations:",len(regs))
json.dump(regs, open("regs.json","w"))
