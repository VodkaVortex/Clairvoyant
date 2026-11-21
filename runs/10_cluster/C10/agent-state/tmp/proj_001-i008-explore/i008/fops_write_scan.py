import re, os

S02 = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s02"
# directories to exclude from this tracefs/securityfs/misc-control sweep
EXCLUDE_DIRS = ('/Documentation', '/tools', '/samples', '/scripts', '/usr')

targets = [
    'kernel/trace/trace.c',
    'kernel/trace/trace_events_user.c',
    'kernel/trace/trace_hwlat.c',
    'kernel/trace/trace_osnoise.c',
    'kernel/trace/trace_events_synth.c',
    'security/integrity/evm/evm_secfs.c',
    'security/integrity/ima/ima_fs.c',
    'security/tomoyo/securityfs_if.c',
    'security/apparmor/apparmorfs.c',
    'security/inode.c',
    'security/lockdown/lockdown.c',
    'security/safesetid/securityfs.c',
    'drivers/char/tpm/eventlog/common.c',
    'drivers/virt/coco/efi_secret/efi_secret.c',
    'security/loadpin/loadpin.c',
]

COPY = re.compile(r'(copy_from_user|memdup_user|simple_write_to_buffer|memcpy\s*\()')
STRINGOPS = re.compile(r'\b(sscanf|simple_strtoul|simple_strtol|simple_strtoull|kstrtoul|kstrtou64|kstrtouint|strcmp|strncmp|strlen|strnlen|strchr|strscpy|strcpy|strsep|strim|strstrip)\s*\(')
TERM = re.compile(r"(\w+)\[\s*(len|count|size|n|length|cnt)\s*\]\s*=\s*('\\0'|0)|memset\s*\(\s*\w+\s*,\s*0|memdup_user_nul|strndup_user|kmemdup_nul|\w+\s*\+\s*1\s*\)")

for f in targets:
    p = os.path.join(S02, f)
    if not os.path.exists(p): 
        print("missing:", f); continue
    src = open(p, errors='replace').read()
    for m in re.finditer(r'^\s*(?:static\s+)?(?:ssize_t|int)\s+(\w+)\s*\(\s*struct file\s*\*', src, re.M):
        fn = m.group(1)
        if not (fn.endswith('_write') or 'write' in fn): continue
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
            print(f"{f}:{ln} {fn} strops={sorted(strops)} terminator={term}")
