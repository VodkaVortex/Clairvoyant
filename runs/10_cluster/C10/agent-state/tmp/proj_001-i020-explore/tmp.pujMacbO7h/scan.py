import re, os
root='/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s03'
pat_copy = re.compile(r'(copy_from_user|memdup_user\(|vmemdup_user\(|simple_write_to_buffer)')
pat_term = re.compile(r'(\w+)\s*\[\s*([A-Za-z_]\w*)\s*\]\s*=\s*(\'\\0\'|"\\0"|0)\s*;')
pat_clamp = re.compile(r'(\w+)\s*=\s*min(?:_t\(\s*\w+\s*,\s*)?\(\s*([^,()]+),\s*sizeof\(([^)]+)\)\s*\)')
out=[]
for dirpath,dirs,files in os.walk(root):
    for f in files:
        if not f.endswith(('.c','.h')): continue
        p=os.path.join(dirpath,f)
        try: lines=open(p,encoding='utf-8',errors='ignore').read().splitlines()
        except Exception: continue
        for i,l in enumerate(lines):
            m=pat_term.search(l)
            if not m: continue
            var,idx=m.group(1),m.group(2)
            ctx='\n'.join(lines[max(0,i-25):i+1])
            if not pat_copy.search(ctx): continue
            clamped=False
            for mm in pat_clamp.finditer(ctx):
                if mm.group(1)==idx: clamped=True
            decl=None
            for j in range(max(0,i-40),i):
                dm=re.search(r'\b(?:char|u8|unsigned char|__u8|uint8_t)\s+'+re.escape(var)+r'\s*\[\s*([^\]]+)\]', lines[j])
                if dm: decl=(j+1,dm.group(1).strip())
            out.append(f"{p[len(root)+1:]}:{i+1} {var}[{idx}]=0 clamped={clamped} decl={decl} :: {l.strip()}")
print('\n'.join(out))
