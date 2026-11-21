import json, os, re
W = os.environ["W"]
with open(os.path.join(W, 'candidates.json')) as fh:
    cands = json.load(fh)

out = []
for c in cands:
    call = c['call_line']
    assigns_before = [a for a in c['assign'] if a < call]
    if not assigns_before: continue
    # deref-style uses after call (-> [ or *) not mere reassignment
    uses = []
    for (ln, txt) in c['uses_after']:
        if re.search(r'\b'+c['ptr']+r'\s*(->|\[)', txt):
            uses.append((ln, txt))
    if not uses: continue
    # check refetch: reassignment after call? treat as still candidate but note
    refetch = [a for a in c['assign'] if a > call]
    out.append({**c, 'deref_after': uses, 'refetch_after': refetch})

with open(os.path.join(W, 'filtered.json'), 'w') as fh:
    json.dump(out, fh, indent=1)
print(len(out))
for c in out:
    ref = 'REFETCH' if c['refetch_after'] else 'STALE'
    print(f"{c['file']}:{c['call_line']} {c['func']} ptr={c['ptr']} {ref} firstuse={c['deref_after'][0][0]}")
