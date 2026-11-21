import re, json, sys, os
sys.path.insert(0,'.')
exec(open('locks.py').read().split("regs = json.load")[0])  # reuse parse helpers

regs = json.load(open("regs.json"))
by_file = {}
for path, line, fn, handler in regs:
    by_file.setdefault(path, []).append((line, fn, handler))

results = {}
for path in sorted(by_file.keys()):
    try:
        fdict = parse_file(path)
    except Exception:
        continue
    # handler idents
    handlers = {}
    for (line, fn, handler) in by_file[path]:
        if not handler: continue
        h=handler.strip()
        mm = re.match(r"^([A-Za-z_]\w*)$", h)
        ident = h if mm else (re.findall(r"[A-Za-z_]\w*", h) or [None])[-1]
        if ident and ident in fdict:
            handlers[ident] = fdict[ident]
    if not handlers: continue
    # all plain spin_lock sites in file, mapped to enclosing function
    try:
        mask = strip_comments_keep_len(open(path,encoding='utf8',errors='replace').read())
    except Exception:
        continue
    plain = []
    for m in re.finditer(r"spin_lock\s*\(\s*(.+?)\s*\)\s*;", mask):
        expr = canonical(m.group(1))
        line = mask.count('\n',0,m.start())+1
        # find enclosing function
        enc=None
        for nm,(start,body) in fdict.items():
            i = body
            # body starts at brace; we have start line and body text; compute absolute positions? 
            pass
        plain.append((line, expr))
    if not plain: continue
    results[path] = {
        "handlers": {k:[v[0]] for k,v in handlers.items()},
        "plain": plain,
    }

json.dump(results, open("plain_sites.json","w"))
# filter: files where handler takes plain spin_lock of same expr as some plain site
hits={}
for path, d in results.items():
    hs = d["handlers"]
    # handler plain locks
    hlocks={}
    for path2, hl in json.load(open("handler_locks.json")).items(): pass
    hits[path]=d
print("files w/ handlers+plain:", len(results))
