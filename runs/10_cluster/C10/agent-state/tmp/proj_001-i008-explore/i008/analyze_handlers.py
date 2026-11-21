import re, os, json

S02 = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s02"
data = json.load(open('proc_writers.json'))
handlers = data['procops_writers']

COPY = re.compile(r'(memdup_user|vmemdup_user|copy_from_user|memcpy\s*\(\s*[^,]+,\s*page|simple_write_to_buffer)')
STRINGOPS = re.compile(r'\b(sscanf|simple_strtoul|simple_strtol|simple_strtoull|simple_strtoll|kstrtoul|kstrtol|kstrtouint|kstrtoint|strcmp|strncmp|strlen|strnlen|strchr|strscpy|strsep|strim|strstrip|strcpy|strstr|strpbrk|strlcpy|match_string|sysfs_match_string|strreplace|memparse)\s*\(')
TERM = re.compile(r"(\w+)\s*\[\s*(len|count|size|n|length|cnt|size_t|data_size|op_size|written)\s*\]\s*=\s*('\\\\0'|0)|memset\s*\(\s*(\w+)\s*,\s*0\s*,|memdup_user_nul|strndup_user|kmemdup_nul|kmalloc\s*\(\s*\w+\s*\+\s*1|kzalloc\s*\(\s*\w+\s*\+\s*1|kvmalloc\s*\(\s*\w+\s*\+\s*1")

out = []
for f, fns in sorted(handlers.items()):
    src = open(os.path.join(S02, f), errors='replace').read()
    lines = src.split('\n')
    for fn in fns:
        # locate function definition
        pat = re.compile(r'^\s*(?:static\s+)?(?:ssize_t|int|void)\s+' + re.escape(fn) + r'\s*\(', re.M)
        m = pat.search(src)
        if not m:
            continue
        start = src[:m.start()].count('\n') + 1
        # find end via brace matching
        i = src.find('{', m.start())
        depth = 0; end = i
        for j in range(i, len(src)):
            if src[j] == '{': depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0:
                    end = j; break
        body = src[i:end]
        bodylines = body.count('\n') + 1
        copies = COPY.findall(body)
        strops = set(m.group(1) for m in STRINGOPS.finditer(body))
        term = bool(TERM.search(body))
        if copies and strops:
            out.append((f, fn, start, bodylines, sorted(strops), term))

print("Handlers with BOTH usercopy/copy and string ops:", len(out))
for f, fn, start, n, ops, term in out:
    print(f"{f}:{start} {fn} ({n} lines) strops={ops} terminator={term}")
