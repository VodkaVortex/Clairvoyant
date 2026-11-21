import os, re
from collections import defaultdict
ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
TMP="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i016-explore"
OUT=os.path.join(TMP,"timer_scan_results.txt")
DIRS=["drivers","net","sound"]
sig_res=[re.compile(r'\btimer_setup\s*\([^,()]+,\s*(\w+)\s*[,)]'),
 re.compile(r'\bsetup_timer\s*\([^,()]+,\s*(\w+)\s*[,)]'),
 re.compile(r'\bDEFINE_TIMER\s*\(\s*\w+\s*,\s*(\w+)\s*[,)]'),
 re.compile(r'\bhrtimer_setup\s*\(\s*[^,()]+,\s*(\w+)\s*[,)]'),
 re.compile(r'\btasklet_hrtimer_init\s*\([^,()]+,\s*(\w+)\s*,')]
func_assign_re=re.compile(r'\.\s*function\s*=\s*(\w+)\s*[,;]')
spin_re=re.compile(r'\bspin_(lock|lock_bh|lock_irq|lock_irqsave|lock_nested|lock_irqrestore)\s*\(\s*([^,;]+?)\s*\)')
def find_defs(src,name):
    out=[];pat=re.compile(r'(?<![\w\.>&])\b'+re.escape(name)+r'\s*\(')
    for m in pat.finditer(src):
        i=m.end()-1;depth=0;j=i
        while j<len(src):
            if src[j]=='(':depth+=1
            elif src[j]==')':
                depth-=1
                if depth==0:break
            j+=1
        k=src.find('{',j)
        if k==-1 or k-j>150:continue
        if ';' in src[j:k]:continue
        depth=0;e=k
        while e<len(src):
            if src[e]=='{':depth+=1
            elif src[e]=='}':
                depth-=1
                if depth==0:break
            e+=1
        out.append((k,e+1))
    return out
def guess_func(src,pos):
    lines=src[:pos].splitlines()
    for line in reversed(lines[-200:]):
        ls=line.strip()
        if not ls or ls.startswith(('#','/','*','}','{','return','if(','if (','for(','for (','while','switch','else','do ')):continue
        m=re.match(r'^[A-Za-z_][\w\s\*]*?\b(\w+)\s*\([^;]*$',ls)
        if m and not ls.startswith(('if','for','while','switch','return')):
            return m.group(1)
    return '?'
groups=defaultdict(list);nfiles=0;ncb=0
for d in DIRS:
    for dirpath,dirnames,filenames in os.walk(os.path.join(ROOT,d)):
        for fn in filenames:
            if not(fn.endswith('.c') or fn.endswith('.h')):continue
            p=os.path.join(dirpath,fn)
            try:src=open(p,encoding='utf-8',errors='replace').read()
            except Exception:continue
            nfiles+=1
            if 'spin_lock' not in src and 'hrtimer' not in src and 'timer' not in src.lower():continue
            cb_names=set()
            for r in sig_res:
                for m in r.finditer(src):cb_names.add(m.group(1))
            for m in func_assign_re.finditer(src):cb_names.add(m.group(1))
            cbranges=[]
            for n in cb_names:
                for (s,e) in find_defs(src,n):cbranges.append((s,e,n))
            if cbranges:ncb+=1
            for m in spin_re.finditer(src):
                variant=m.group(1);expr=m.group(2).strip();norm=expr.lstrip('&').strip()
                if not variant.startswith('lock'):continue
                pos=m.start();cb=None
                for (s,e,n) in cbranges:
                    if s<=pos<=e:cb=n;break
                rel=os.path.relpath(p,ROOT)
                lineno=src.count('\n',0,pos)+1
                groups[(os.path.dirname(rel),norm)].append({'file':rel,'line':lineno,'variant':variant,'cb':cb,'func':guess_func(src,pos),'text':src.splitlines()[lineno-1].strip()})
cands=[]
for (dn,expr),hits in groups.items():
    th=[h for h in hits if h['cb']];oth=[h for h in hits if not h['cb']]
    oth_plain=[h for h in oth if h['variant']=='lock']
    if not th or not oth_plain:continue
    cands.append((dn,expr,th,oth_plain,set(h['variant'] for h in hits)))
def score(c):
    dn,e,t,o,v=c;s=0
    if 'lock_bh' in v:s-=6
    s+=min(len(o),4)+min(len(t),2)
    return s
cands.sort(key=score,reverse=True)
with open(OUT,'w') as f:
    f.write("files_scanned=%d files_with_timer_cb_defs=%d groups_total=%d candidate_groups=%d\n"%(nfiles,ncb,len(groups),len(cands)))
    for i,(dn,e,t,o,v) in enumerate(cands):
        f.write("\n=== #%d dir=%s lock=%s variants=%s ===\n"%(i+1,dn,e,sorted(v)))
        f.write("  TIMER-SIDE (inside timer/hrtimer callback):\n")
        for h in t[:5]:f.write("    %s:%d [%s via cb=%s] %s\n"%(h['file'],h['line'],h['variant'],h['cb'],h['text']))
        f.write("  OTHER-SIDE plain spin_lock (candidate process ctx):\n")
        for h in o[:10]:f.write("    %s:%d [func~%s] %s\n"%(h['file'],h['line'],h['func'],h['text']))
print(open(OUT).read()[:14000])
