import re, json, os, collections, sys

root = os.environ.get("S04", ".")
sites = []
line_re = re.compile(r'^(.*?\.c):(\d+):(.*)$')
call_re = re.compile(r'\b(request_irq|devm_request_irq|request_threaded_irq)\s*\(')

for line in open(sys.argv[1]):
    m = line_re.match(line.rstrip("\n"))
    if not m: continue
    path, ln, code = m.group(1), int(m.group(2)), m.group(3)
    if not call_re.search(code): continue
    # handler is typically the 2nd arg (irq, handler, ...) or first for some
    # try to grab identifier-ish tokens in the call line
    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', code)
    # candidate handler names: skip the api name, numbers
    cands = []
    skip = {"request_irq","devm_request_irq","request_threaded_irq","devm_request_threaded_irq"}
    for t in tokens:
        if t in skip: continue
        cands.append(t)
    sites.append({"path":path,"line":ln,"tokens":cands,"code":code.strip()})

json.dump(sites, open(sys.argv[2],"w"), indent=1)
print(len(sites))
