import re, os, sys, json
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import read_fns, lock_uses, base_name, has_bh_disable, uses_flags_arg

TASKLET_INIT = re.compile(r'tasklet_init\s*\(\s*&?\s*([A-Za-z0-9_>\.\-]+)\s*,\s*([A-Za-z0-9_]+)\s*,')
TASKLET_SETUP = re.compile(r'tasklet_setup\s*\(\s*&?\s*([A-Za-z0-9_>\.\-]+)\s*,\s*([A-Za-z0-9_]+)\s*,')
DECLARE_TASKLET = re.compile(r'DECLARE_TASKLET(?:_OLD)?\s*\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*[,)]')
TASKLET_SCHED = re.compile(r'tasklet_(?:hi_)?schedule\s*\(\s*&?\s*([A-Za-z0-9_>\.\-]+)\s*\)')
NAPI_ADD = re.compile(r'netif_napi_add(?:_weight|_dev)?\s*\(([^;]{0,300}?)\)\s*;')
NAPI_SCHED = re.compile(r'napi_schedule(?:_prep|d)?\s*\(\s*&?\s*([A-Za-z0-9_>\.\-]+)\s*\)')

def load(files_list):
    data = {}
    for f in files_list:
        if not os.path.exists(f): continue
        fns = read_fns(f)
        txt = open(f, encoding='utf-8', errors='replace').read()
        data[f] = (fns, txt)
    return data

def tasklet_callbacks(data):
    """map callback fn name -> list of (file, tasklet_var, sched_context)"""
    cbs = defaultdict(list)
    for f, (fns, txt) in data.items():
        for m in TASKLET_INIT.finditer(txt):
            cbs[m.group(2)].append((f, m.group(1), 'tasklet_init', txt[:m.start()].count('\n')+1))
        for m in TASKLET_SETUP.finditer(txt):
            cbs[m.group(2)].append((f, m.group(1), 'tasklet_setup', txt[:m.start()].count('\n')+1))
        for m in DECLARE_TASKLET.finditer(txt):
            cbs[m.group(2)].append((f, m.group(1), 'DECLARE_TASKLET', txt[:m.start()].count('\n')+1))
    return cbs

def napi_polls(data):
    """poll fn names registered via netif_napi_add; positional: first arg dev, second napi struct, third poll fn (classic) — but newer API: netif_napi_add(dev, &napi, poll) still 3rd. For weight variants: (dev, &napi, poll, weight)."""
    polls = defaultdict(list)
    for f, (fns, txt) in data.items():
        for m in NAPI_ADD.finditer(txt):
            args = [a.strip() for a in m.group(1).split(',')]
            if len(args) >= 3:
                poll = args[2].strip()
                mm = re.match(r'^([A-Za-z0-9_]+)$', poll)
                if mm:
                    polls[poll].append((f, args[1], txt[:m.start()].count('\n')+1))
    return polls

def fn_lock_map(data, files_scope=None):
    """fn name -> {file: [(variant, lockexpr)]} across the corpus (name may repeat across files)."""
    fl = defaultdict(lambda: defaultdict(list))
    for f, (fns, txt) in data.items():
        if files_scope and f not in files_scope: continue
        for name,(s,e,body) in fns.items():
            fl[name][f].extend(lock_uses(body))
    return fl

if __name__ == '__main__':
    base = sys.argv[1]  # snapshot root
    task_files = [os.path.join(base, l.strip()) for l in open(sys.argv[2]) if l.strip()]
    napi_files = [os.path.join(base, l.strip()) for l in open(sys.argv[3]) if l.strip()]
    # data keyed by absolute path
    allfiles = sorted(set(task_files + napi_files))
    data = {}
    for f in allfiles:
        if os.path.exists(f):
            data[f] = (read_fns(f), open(f, encoding='utf-8', errors='replace').read())
    cbs = tasklet_callbacks(data)
    polls = napi_polls(data)
    print(json.dumps({
        "tasklet_callbacks": {k: [ {"file": os.path.relpath(p[0], base), "tasklet": p[1], "how": p[2], "line": p[3]} for p in v] for k,v in cbs.items()},
        "napi_polls": {k: [ {"file": os.path.relpath(p[0], base), "napi": p[1], "line": p[2]} for p in v] for k,v in polls.items()},
    }, indent=1))
