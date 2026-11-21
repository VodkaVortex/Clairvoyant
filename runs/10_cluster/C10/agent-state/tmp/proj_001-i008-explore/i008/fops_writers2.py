import re, os

S02 = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s02"
files = [l.strip().lstrip('./') for l in open('proc_files_all.txt') if l.strip()]
COPY = re.compile(r'(copy_from_user|memdup_user|simple_write_to_buffer)')
STRINGOPS = re.compile(r'\b(sscanf|simple_strtoul|simple_strtol|simple_strtoull|simple_strtoll|kstrtoul|kstrtol|kstrtouint|kstrtoint|kstrtou16|kstrtou8|strcmp|strncmp|strlen|strnlen|strchr|strscpy|strcpy|strsep|strim|strstrip|strpbrk|strreplace)\s*\(')
TERM = re.compile(r"(\w+)\[\s*(len|count|size|n|length|cnt|tmp_len)\s*\]\s*=\s*('\\0'|0)|memset\s*\(\s*\w+\s*,\s*0|memdup_user_nul|strndup_user|kmemdup_nul|__get_free_page")

for f in files:
    p = os.path.join(S02, f)
    src = open(p, errors='replace').read()
    # find all functions that are used as .write = in file, or any _write(struct file*
    fnames = set(re.findall(r'\.write\s*=\s*(\w+)', src))
    for fn in fnames:
        m = re.search(r'^\s*(?:static\s+)?(?:inline\s+)?(?:ssize_t|int|void)\s+' + re.escape(fn) + r'\s*\(', src, re.M)
        if not m: continue
        i = src.find('{', m.start())
        depth = 0; end = i
        for j in range(i, len(src)):
            if src[j] == '{': depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0: end = j; break
        body = src[i:end]
        has_copy = bool(COPY.search(body))
        strops = set(x.group(1) for x in STRINGOPS.finditer(body))
        if has_copy and strops:
            term = bool(TERM.search(body))
            ln = src[:m.start()].count('\n')+1
            print(f"{f}:{ln} {fn} strops={sorted(strops)} terminator-evidence={term}")
