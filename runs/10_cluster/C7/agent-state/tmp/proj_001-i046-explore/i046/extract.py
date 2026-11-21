import os, re, sys, json, collections

ROOT = "."
reg_re = re.compile(r'\b(request_irq|devm_request_irq|devm_request_any_context_irq|request_any_context_irq|request_threaded_irq|request_percpu_irq)\s*\(')

# map of file -> list of (funcname) defined in that file
funcdef_re = re.compile(r'^\s*(?:static\s+)?(?:inline\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s+)+\**\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(')

handler_name_re = re.compile(r'\b(?:request_irq|devm_request_irq|devm_request_any_context_irq|request_any_context_irq)\s*\(\s*([^,]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')
threaded_re = re.compile(r'\brequest_threaded_irq\s*\(\s*([^,]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*|NULL)\s*,\s*([A-Za-z_][A-Za-z0-9_]*|NULL)\s*,')

results = []
nfiles = 0
for dirpath, dirnames, filenames in os.walk(ROOT):
    # skip non-source
    dirnames[:] = [d for d in dirnames if d not in ('.git',)]
    for fn in filenames:
        if not fn.endswith(('.c', '.h')):
            continue
        path = os.path.join(dirpath, fn)
        try:
            with open(path, 'r', errors='ignore') as f:
                text = f.read()
        except Exception:
            continue
        if not reg_re.search(text):
            continue
        nfiles += 1
        lines = text.split('\n')
        handlers = []
        for m in handler_name_re.finditer(text):
            handlers.append((m.group(2), m.start()))
        for m in threaded_re.finditer(text):
            if m.group(2) != 'NULL':
                handlers.append((m.group(2), m.start()))
        if handlers:
            results.append((path, sorted(set(h[0] for h in handlers))))

print(json.dumps({"nfiles_with_reg": nfiles, "n_results": len(results)}))
with open(os.path.join(os.environ['TMPDIR'], 'i046', 'handlers.json'), 'w') as f:
    json.dump({p: hs for p, hs in results}, f, indent=1)
