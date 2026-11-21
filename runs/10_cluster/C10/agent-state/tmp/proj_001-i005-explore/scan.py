import os, re, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s01"
EXCLUDE = ("tools/", "Documentation/", "samples/", "rust/", "scripts/")

COPY_RE = re.compile(r'\b(memdup_user|vmemdup_user|memdup_user_nul|strndup_user|copy_from_user)\s*\(')
STROP_RE = re.compile(r'\b(sscanf|simple_strtol|simple_strtoul|simple_strtoull|kstrtol|kstrtoul|strcmp|strncmp|strlen|strchr|strrchr|strscpy|strcpy|strstrip|strsep|strstr|strnchr|strncasecmp|strcasecmp)\s*\(')
SAFE_RE = re.compile(r'\b(memdup_user_nul|strndup_user)\s*\(')
TERM_RE = re.compile(r'(\w+)\s*\[\s*[^]]*\]\s*=\s*[\'"]\\0[\'"]|\bmemset\s*\(\s*(\w+)\s*,\s*0\s*,|\bmemchr\s*\(')

def funcs(text):
    # crude top-level function splitter: finds "name(...) {" at top level
    n = len(text)
    i = 0
    out = []
    while i < n:
        m = re.search(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\(', text[i:], re.M)
        if not m: break
        start = i + m.start()
        # find matching close paren
        j = i + m.end() - 1
        depth = 0
        while j < n:
            if text[j] == '(': depth += 1
            elif text[j] == ')':
                depth -= 1
                if depth == 0: break
            j += 1
        if j >= n: break
        # find '{' after
        k = text.find('{', j)
        # ensure only whitespace/annotations between
        between = text[j+1:k]
        if k == -1 or re.search(r'[;{}=]', between):
            i = j + 1
            continue
        # match braces
        d = 0
        p = k
        while p < n:
            c = text[p]
            if c == '{': d += 1
            elif c == '}':
                d -= 1
                if d == 0: break
            p += 1
        fname_m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\($', text[start:i+m.end()-1] + '(')
        fname = fname_m.group(1) if fname_m else '?'
        # line numbers
        ls = text.count('\n', 0, start) + 1
        le = text.count('\n', 0, p) + 1
        out.append((fname, ls, le, text[start:p+1]))
        i = p + 1
    return out

results = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    rel = os.path.relpath(dirpath, ROOT)
    if any(rel.startswith(e) or rel + '/' == e for e in EXCLUDE):
        continue
    for fn in filenames:
        if not fn.endswith('.c'): continue
        path = os.path.join(dirpath, fn)
        try:
            with open(path, 'r', errors='replace') as f:
                text = f.read()
        except OSError:
            continue
        for fname, ls, le, body in funcs(text):
            copies = COPY_RE.findall(body)
            if not copies: continue
            strops = STROP_RE.findall(body)
            if not strops: continue
            safe = bool(SAFE_RE.search(body))
            term = bool(TERM_RE.search(body))
            results.append({
                "file": os.path.relpath(path, ROOT),
                "func": fname, "start": ls, "end": le,
                "copy": sorted(set(copies)),
                "strops": sorted(set(strops)),
                "safe_helper": safe, "term_hint": term,
            })

with open(sys.argv[1], 'w') as f:
    json.dump(results, f, indent=1)
print(len(results), "functions with usercopy + string ops")
