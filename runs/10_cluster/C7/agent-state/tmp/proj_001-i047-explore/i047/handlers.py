import re, json, os, sys, collections

sites = json.load(open(sys.argv[1]))
# build map file -> list of lines
filecache = {}
def get_lines(path):
    if path not in filecache:
        try:
            filecache[path] = open(path, errors='replace').read().splitlines()
        except Exception:
            filecache[path] = None
    return filecache[path]

skip = {"request_irq","devm_request_irq","request_threaded_irq","devm_request_threaded_irq",
        "IRQF_SHARED","IRQF_TRIGGER","irq","int","void","unsigned","long","static","devm",
        "platform_get_resource","pci_irq_vector","platform_get_irq","gpio_to_irq","spin_lock","dev"}

resolved = []
unresolved = []
for s in sites:
    lines = get_lines(s["path"])
    if lines is None:
        unresolved.append(s); continue
    # join the call statement: from s.line-1 forward until ';' balance parens
    start = s["line"]-1
    text = []
    depth = 0
    i = start
    stmt = ""
    while i < len(lines) and i < start + 30:
        stmt += lines[i] + " "
        if stmt.count("(") >= 1 and stmt.count(")") >= stmt.count("(") and ";" in stmt:
            break
        i += 1
    # extract args at top level
    # find the opening paren after the api name
    m = re.search(r'\b(request_irq|devm_request_irq|request_threaded_irq)\s*\(', stmt)
    if not m:
        unresolved.append(s); continue
    api = m.group(1)
    rest = stmt[m.end():]
    # top-level split
    args = []
    depth = 0; cur = ""
    for ch in rest:
        if ch == '(' or ch == '[': depth += 1
        if ch == ')' or ch == ']':
            if depth == 0:
                if cur.strip(): args.append(cur.strip())
                break
            depth -= 1
        if ch == ',' and depth == 0:
            args.append(cur.strip()); cur = ""
        else:
            cur += ch
    handler = None
    if api == "request_threaded_irq":
        if len(args) >= 2:
            handler = args[1]  # primary hardirq handler (arg index 1: irq, handler, thread_fn...)
            thread_fn = args[2] if len(args) > 2 else None
        else:
            thread_fn = None
    else:
        # request_irq(irq, handler, ...)
        if len(args) >= 2:
            handler = args[1]
        thread_fn = None
    s2 = dict(s); s2["api"] = api; s2["handler_expr"] = handler; s2["thread_fn"] = thread_fn
    resolved.append(s2)

json.dump(resolved, open(sys.argv[2],"w"), indent=1)
print("resolved", len(resolved), "unresolved", len(unresolved))
