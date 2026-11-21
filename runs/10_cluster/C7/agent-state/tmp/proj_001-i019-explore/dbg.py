import re, os
root = os.getcwd()
# sanity check: pick a known case: drivers/net/wireless/cw1200/queue.c cw1200_queue_gc queue->lock
f = 'drivers/net/wireless/cw1200/queue.c'
text = open(os.path.join(root, f), errors='replace').read()
print('spin_lock(&queue->lock):', len(re.findall(r'spin_lock\s*\(\s*&queue->lock\s*\)', text)))
print('spin_lock_bh(&queue->lock):', len(re.findall(r'spin_lock_bh\s*\(\s*&queue->lock\s*\)', text)))
for i, ln in enumerate(text.splitlines(), 1):
    if 'queue->lock' in ln and 'spin' in ln:
        print(i, ln.strip())
