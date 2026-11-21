import os, re
root='.'
cb_re = re.compile(r'(?:timer_setup|setup_timer)\s*\(\s*[^,]+,\s*&?(\w+)\s*,')
dt_re = re.compile(r'DEFINE_TIMER\s*\(\s*\w+\s*,\s*&?(\w+)\s*,')
hrt_re = re.compile(r'->function\s*=\s*(\w+)')
def_re = re.compile(r'^(?:static\s+|inline\s+|noinline\s+)*(?:void|unsigned long|int|enum hrtimer_restart)\s+\**(\w+)\s*\(')
out=[]
for dirpath, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in ('tools','Documentation','scripts','samples','usr','.git')]
    for f in files:
        if not f.endswith('.c'): continue
        p=os.path.join(dirpath,f)
        try: src=open(p,encoding='utf-8',errors='ignore').read()
        except Exception: continue
        cbs=set(m.group(1) for m in cb_re.finditer(src)) | set(m.group(1) for m in dt_re.finditer(src)) | set(m.group(1) for m in hrt_re.finditer(src))
        if not cbs: continue
        lines=src.split('\n')
        for i,l in enumerate(lines):
            m=def_re.match(l)
            if not m or m.group(1) not in cbs: continue
            depth=0; started=False
            for j in range(i, min(i+250, len(lines))):
                depth += lines[j].count('{') - lines[j].count('}')
                if '{' in lines[j]: started=True
                if re.search(r'\bspin_lock\s*\(', lines[j]):
                    out.append(f"{p}:{j+1}: [{m.group(1)}] {lines[j].strip()}")
                if started and depth<=0 and j>i: break
print('\n'.join(out))
