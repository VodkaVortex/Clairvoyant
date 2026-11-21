import os, re, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s02"
copy_re = re.compile(r'\b(memdup_user|vmemdup_user|copy_from_user)\s*\(')
strfuncs = ['sscanf', 'simple_strtoul', 'simple_strtol', 'simple_strtoull', 'simple_strtoll',
            'strlen', 'strcmp', 'strncmp', 'strchr', 'strrchr', 'strscpy', 'strcpy', 'strsep',
            'strstr', 'strstrip', 'strreplace', 'strreplace', 'match_string', 'sysfs_match_string',
            'kstrtol', 'kstrtoul', 'kstrtoint', 'kstrtouint', 'kstrtox', 'strcat']
str_re = re.compile(r'\b(' + '|'.join(strfuncs) + r')\s*\(')

results = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        if not fn.endswith('.c'):
            continue
        p = os.path.join(dirpath, fn)
        try:
            lines = open(p, encoding='utf-8', errors='replace').read().splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines):
            m = copy_re.search(line)
            if not m:
                continue
            # skip nul variants for copy_re since regex doesn't match memdup_user_nul anyway
            # look ahead 12 lines for a string function
            for j in range(i, min(i + 13, len(lines))):
                if str_re.search(lines[j]):
                    results.append((p, i + 1, j + 1, line.strip(), lines[j].strip()))
                    break

for p, i, j, cl, sl in results:
    rel = os.path.relpath(p, ROOT)
    print(f"{rel}:{i} -> {j}")
    print(f"    COPY: {cl}")
    print(f"    STR : {sl}")
print(f"TOTAL {len(results)}", file=sys.stderr)
