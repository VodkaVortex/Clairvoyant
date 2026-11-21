import json, re, os, collections

TMP = os.environ['TMPDIR']+'/i022'
census = json.load(open(TMP+'/census_net.json'))
funcs = collections.defaultdict(list)
for p, name, start, op, ln in census:
    funcs[(p, name, start)].append((op, ln))

# Candidate callees: functions whose body contains a relocating op on a parameter skb.
# Extract callee signatures to see if they take struct sk_buff *skb (not const).
callees = {}
for (p, name, start), ops in funcs.items():
    try:
        text = open(p, encoding='utf-8', errors='replace').read()
    except Exception:
        continue
    lines = text.split('\n')
    # signature: up to 5 lines from start-1
    sig = '\n'.join(lines[start-1:start+4])
    # find param list
    m = re.search(r'\(([^;{}]*?)\)\s*$', sig, re.S)
    if not m:
        m = re.search(r'\((.*)\)', sig, re.S)
    params = m.group(1) if m else ''
    has_skb_param = re.search(r'struct\s+sk_buff\s*\*', params)
    const_skb = re.search(r'const\s+struct\s+sk_buff\s*\*', params)
    if has_skb_param:
        callees[(p, name)] = {'start': start, 'ops': ops, 'params': ' '.join(params.split())[:180], 'const': bool(const_skb)}

print('callees with skb param:', len(callees))
# Now scan net/ and drivers/net for call sites of these callee names where
# the caller also has a live local pointer-into-skb captured before the call.
# Strategy: for each callee name (unique), find call sites in net/ and drivers/,
# then check the enclosing function for pointer captures before the call line.
cal_by_name = collections.defaultdict(list)
for (p, name), info in callees.items():
    cal_by_name[name].append((p, info))

# Priority: callee names that look like validators/helpers (contain check/validate/ensure/may_pull etc.) OR are called with skb first arg from a different file
interesting = []
for name, lst in cal_by_name.items():
    if len(lst) == 0: continue
    # skip very common core helpers that are the relocating ops themselves handled by same-function intents? No - keep all; interprocedural is the point.
    interesting.append((name, len(lst)))
interesting.sort(key=lambda x: -x[1])
json.dump({name: [(p, i['start'], i['ops'], i['params']) for p, i in lst] for name, lst in cal_by_name.items()}, open(TMP+'/callees.json','w'))
print('unique callee names:', len(cal_by_name))
for name, cnt in interesting[:40]:
    print(cnt, name)
