import json, re, os, collections
census = json.load(open(os.environ['TMPDIR']+'/i022/census_net.json'))
# Group by file+function: function-level set of relocating ops
funcs = collections.defaultdict(list)
for p, name, start, op, ln in census:
    funcs[(p, name, start)].append((op, ln))

# We need the callee's params. Extract from s01 source on demand.
print('total functions with relocating ops:', len(funcs))
# Distribution of ops
ops = collections.Counter(op for v in funcs.values() for op, ln in v)
print(ops)
