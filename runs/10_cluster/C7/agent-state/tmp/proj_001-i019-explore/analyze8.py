import re, os

root = os.getcwd()
entries = []
for l in open(os.environ['TMPDIR'] + '/timer_cb_with_locks.txt'):
    parts = l.rstrip('\n').split('\t')
    if len(parts) < 6:
        continue
    f, cb, reg, defspan, locks = parts[0], parts[1], parts[2], parts[3], parts[4]
    entries.append((f, cb, defspan, locks.split(',')))

print(len(entries))
# per file: what lock forms does the timer callback itself use?
for f, cb, defspan, locks in entries[:5]:
    path = os.path.join(root, f)
    lines = open(path, errors='replace').read().splitlines()
    s, e = defspan.replace('def ', '').split('-')
    s, e = int(s), int(e)
    print('==', f, cb, defspan)
    for i in range(s-1, min(e, len(lines))):
        if 'spin_lock' in lines[i]:
            print('   ', i+1, lines[i].strip())
