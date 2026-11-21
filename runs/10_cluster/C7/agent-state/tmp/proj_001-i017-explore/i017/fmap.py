import re, sys
def mapfile(path, targets):
    lines = open(path, encoding='utf-8', errors='ignore').read().split('\n')
    # find function start lines (col-0 identifier + '(' ... ') {')
    starts = []
    for i,l in enumerate(lines):
        m = re.match(r'^(\w[\w\s\*]*?)\s+\**(\w+)\s*\(', l)
        if m and not l.strip().endswith(';') and not re.match(r'^(if|for|while|switch|return|else|EXPORT)', l):
            starts.append((i, m.group(2)))
    def func_of(ln):
        best = None
        for i,n in starts:
            if i < ln-1: best = (i,n)
            else: break
        return best
    for t in targets:
        fi = func_of(t)
        if fi:
            i,n = fi
            # find end of function (next line col0 '}')
            end = i
            for j in range(i, min(i+400, len(lines))):
                if lines[j].startswith('}'): end = j; break
            print(f"{path}:{t}: in {n} (def at {i+1}, ends ~{end+1})")
        else:
            print(f"{path}:{t}: <top-level>")
base='.'
mapfile('net/bridge/br_multicast.c', [654,865,1321,1568,1656,1702,1735,1901,1942,2846,2984,3436,3519,3603,3787,3800,3871,3982])
print('---')
mapfile('net/bridge/br_multicast_eht.c', [213,230])
print('---')
import subprocess
src = open('drivers/scsi/libiscsi.c', encoding='utf-8', errors='ignore').read().split('\n')
fl = [i+1 for i,l in enumerate(src) if re.search(r'spin_lock(_bh)?\(&session->frwd_lock', l) or 'spin_unlock_bh(&session->frwd_lock' in l or ('frwd_lock' in l and 'spin_' in l)]
print('libiscsi frwd_lock sites:', fl)
mapfile('drivers/scsi/libiscsi.c', fl)
