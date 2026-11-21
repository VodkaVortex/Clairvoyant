import os, re, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s04"
copy_re = re.compile(r'\b(memdup_user|vmemdup_user|copy_from_user)\s*\(')
nul_safe_re = re.compile(r'\b(memdup_user_nul|strndup_user|memdup_user_nul)\s*\(')
str_re = re.compile(r'\b(sscanf|simple_strtou?ll?|simple_strtol|kstrto[ul]*|strlen|strcmp|strchr|strscpy|strcpy|strstr)\s*\(')
debugfs_re = re.compile(r'debugfs_create|debugfs')

func_start_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\(')

results = []
for dirpath, dirs, files in os.walk(ROOT):
    for fn in files:
        if not fn.endswith('.c') and not fn.endswith('.h'):
            continue
        p = os.path.join(dirpath, fn)
        try:
            with open(p, 'r', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            continue
        # quick prefilter
        text = ''.join(lines)
        if 'debugfs' not in text:
            continue
        if not copy_re.search(text) or not str_re.search(text):
            continue
        rel = os.path.relpath(p, ROOT)
        # split into functions roughly by brace tracking
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            if ('__user' in line and ('write' in line.lower() or 'store' in line.lower())) or re.match(r'^static\s+(ssize_t|int|void)', line):
                # find function body: from this line, track braces
                depth = 0
                started = False
                j = i
                body = []
                while j < n and j < i + 400:
                    l = lines[j]
                    body.append(l)
                    depth += l.count('{') - l.count('}')
                    if '{' in l:
                        started = True
                    if started and depth <= 0:
                        break
                    if not started and ';' in l and '(' in l and ')' in l and '{' not in l and j > i:
                        break  # prototype or var decl
                    j += 1
                bodytext = ''.join(body)
                if copy_re.search(bodytext) and str_re.search(bodytext) and '__user' in bodytext:
                    has_nul_safe = nul_safe_re.search(bodytext)
                    # memdup_user( must not be memdup_user_nul
                    copies = copy_re.findall(bodytext)
                    if has_nul_safe:
                        # check if there's also a non-nul copy
                        if re.search(r'\bmemdup_user\s*\(', bodytext.replace('memdup_user_nul','X')):
                            pass
                        else:
                            i = j + 1
                            continue
                    m2 = str_re.findall(bodytext)
                    results.append((rel, i+1, j+1, copies, sorted(set(m2))))
                    i = j + 1
                    continue
            i += 1

seen = set()
for rel, s, e, copies, strs in results:
    key = (rel, s)
    if key in seen: continue
    seen.add(key)
    print(f"{rel}:{s}-{e} copies={copies} strs={strs}")
