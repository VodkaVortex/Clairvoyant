import re, subprocess, os

root = '.'
out = subprocess.run(['find','drivers','net','-name','*.c'],capture_output=True,text=True).stdout.split()
napi_hits = []
tasklet_hits = []
for path in out:
    try:
        txt = open(path, errors='ignore').read()
    except Exception:
        continue
    if 'netif_napi_add' in txt or 'napi_schedule' in txt:
        # find NAPI poll function names
        polls = set(re.findall(r'netif_napi_add(?:_weight)?\s*\([^;]*?,\s*&?[\w\-]+,\s*(\w+)\s*,', txt))
        polls |= set(re.findall(r'netif_napi_add(?:_weight)?\s*\([^;]*?,\s*(\w+)\s*,', txt))
        for fn in polls:
            m = re.search(r'\b(?:static\s+)?\w[\w\s\*]*?\b'+re.escape(fn)+r'\s*\([^)]*\)\s*\{', txt)
            if not m: continue
            start = m.start()
            # extract body approx: until matching close brace
            depth = 0; i = txt.find('{', m.start())
            j = i
            while j < len(txt):
                if txt[j]=='{': depth+=1
                elif txt[j]=='}':
                    depth-=1
                    if depth==0: break
                j+=1
            body = txt[i:j]
            if re.search(r'spin_lock\(', body) and 'spin_lock_bh' not in body and 'local_bh_disable' not in body:
                lines = txt[:m.start()].count('\n')+1
                plain = re.findall(r'spin_lock(?:_nested)?\(&?[\w\->\.]+(?:\[[^\]]*\])?(?:,\s*\w+)?\)', body)
                napi_hits.append((path, lines, fn, plain[:4]))
    if 'tasklet_schedule' in txt or 'tasklet_init' in txt or 'tasklet_setup' in txt:
        fns = set(re.findall(r'tasklet_(?:init|setup)\s*\([^;]*?,\s*(\w+)\s*,', txt))
        for fn in fns:
            m = re.search(r'\b(?:static\s+)?\w[\w\s\*]*?\b'+re.escape(fn)+r'\s*\([^)]*\)\s*\{', txt)
            if not m: continue
            i = txt.find('{', m.start()); depth=0; j=i
            while j < len(txt):
                if txt[j]=='{': depth+=1
                elif txt[j]=='}':
                    depth-=1
                    if depth==0: break
                j+=1
            body = txt[i:j]
            if re.search(r'spin_lock\(', body):
                lines = txt[:m.start()].count('\n')+1
                plain = re.findall(r'spin_lock(?:_nested)?\(&?[\w\->\.]+(?:\[[^\]]*\])?(?:,\s*\w+)?\)', body)
                tasklet_hits.append((path, lines, fn, plain[:4]))

print("=== NAPI polls with plain spin_lock (no bh in body) ===")
for h in sorted(napi_hits):
    print(h)
print()
print("=== Tasklet callbacks containing spin_lock (any) ===")
for h in sorted(tasklet_hits):
    print(h)
