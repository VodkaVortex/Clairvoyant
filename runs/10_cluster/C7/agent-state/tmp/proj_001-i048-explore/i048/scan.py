import os, re, sys, json, subprocess
ROOT="."
out=open(os.path.join(os.environ["TMPDIR"],"i048","irq_regs.txt"),"w")
reg_re=re.compile(r'\b(request_irq|devm_request_irq|request_threaded_irq|devm_request_threaded_irq)\s*\(')
files=subprocess.run(["/usr/bin/grep","-rl","request_irq","--include=*.c","--include=*.h","."],capture_output=True,text=True).stdout.split()
files+=[f for f in subprocess.run(["/usr/bin/grep","-rl","devm_request","--include=*.c","--include=*.h","."],capture_output=True,text=True).stdout.split() if f not in files]
nreg=0
for f in files:
    try:
        lines=open(f,errors="ignore").read().split("\n")
    except: continue
    for i,l in enumerate(lines):
        m=reg_re.search(l)
        if m:
            out.write(f"{f}\t{i+1}\t{m.group(1)}\t{l.strip()[:200]}\n")
            nreg+=1
out.close()
print("regs",nreg)
