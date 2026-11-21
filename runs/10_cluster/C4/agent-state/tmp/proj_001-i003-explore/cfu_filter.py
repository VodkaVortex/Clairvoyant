import re, subprocess, json, os
SNAP='/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C4/public/snapshots/s01'
dirs=[d for d in os.listdir(SNAP) if os.path.isdir(os.path.join(SNAP,d)) and d not in ('Documentation','tools','samples','usr','arch','sound')]
CFU = re.compile(r'copy_from_user\s*\(')
ASSIGN = re.compile(r'=\s*(?:__\s*)?copy_from_user\s*\(')
results=[]
for d in dirs:
    p = subprocess.run(['/usr/bin/rg','-l','copy_from_user',os.path.join(SNAP,d),'-g','*.c'],capture_output=True,text=True)
    for f in p.stdout.splitlines():
        try:
            lines=open(f,errors='replace').read().split('\n')
        except Exception: continue
        for idx,l in enumerate(lines):
            if CFU.search(l):
                if ASSIGN.search(l):
                    continue
                in_if = re.search(r'\bif\s*\(', l) or (idx>0 and re.search(r'\bif\s*\([^;]*$', lines[idx-1]))
                if not in_if:
                    results.append((f.replace(SNAP+'/',''), idx+1, l.strip(), 'NO-IF-NO-ASSIGN'))
                    continue
                k=idx; depth=0; started=False
                while k < len(lines):
                    for ch in lines[k]:
                        if ch=='(': depth+=1; started=True
                        elif ch==')': depth-=1
                    if started and depth<=0: break
                    k+=1
                ok=False
                for m in range(k+1, min(len(lines), k+5)):
                    s=lines[m].strip()
                    if not s: continue
                    if re.match(r'(return|goto|break|continue)\b', s) or re.search(r'=\s*-?\s*E\w+\s*;', s) or s.startswith('}'):
                        ok=True
                    break
                if not ok:
                    nxt = lines[k+1].strip() if k+1 < len(lines) else ''
                    results.append((f.replace(SNAP+'/',''), idx+1, l.strip()[:140], nxt[:140]))
print(json.dumps(results, indent=1))
print("TOTAL", len(results))
