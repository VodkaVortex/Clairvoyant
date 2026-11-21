#!/usr/bin/env python3
import re, sys, os

root = sys.argv[1]
# pattern: an assignment of a parse/copy helper to a variable
parse_pat = re.compile(r'^\s*(?:[A-Za-z_][\w]*\s+)?(\w+)\s*=\s*(\w+)\(')
helpers = {
 'nla_parse','nla_parse_nested','nla_parse_deprecated','nla_parse_nested_deprecated',
 'nlmsg_parse','nlmsg_parse_deprecated',
 'nla_memdup','nla_strdup','nla_strscpy',
 'copy_from_user','strncpy_from_user',
 'nla_get_be32','nla_get_be64','nla_get_u32','nla_get_u64',
 'nla_len','nla_data',
 'sock_kmalloc','kmalloc','kmemdup','memdup_user',
 'kstrtoint','kstrtou32','kstrtou16','kstrtou8','kstrtobool',
 'sscanf','match_int','match_u64',
 'snd_config','sysfs_match_string',
}
results = []
for dirpath, dirs, files in os.walk(root):
    if '/.git' in dirpath: continue
    for fn in files:
        if not fn.endswith(('.c','.h')): continue
        p = os.path.join(dirpath, fn)
        try:
            with open(p, encoding='utf-8', errors='replace') as fh:
                lines = fh.readlines()
        except Exception:
            continue
        n = len(lines)
        i =  0
        while i < n:
            m = parse_pat.match(lines[i])
            if not m:
                i += 1; continue
            var, fn_ = m.group(1), m.group(2)
            if fn_ not in helpers:
                i += 1; continue
            # look ahead up to 25 lines for reads of var before a guard, and note guards
            j = i + 1
            guard_found = False
            reads_before_guard = []
            while j < n and j <= i + 25:
                l = lines[j]
                if re.search(r'\b(return|goto|break)\b', l) and re.search(r'\b' + re.escape(var) + r'\b', l):
                    guard_found = True
                    break
                if re.search(r'\b' + re.escape(var) + r'\b', l) and '=' not in l.split('//')[0][:40]:
                    reads_before_guard.append(j+1)
                    if len(reads_before_guard) >= 3: break
                if re.match(r'^\}', l):
                    break
                j += 1
            if not guard_found and reads_before_guard:
                results.append((p.replace(root+'/',''), i+1, fn_, var, reads_before_guard[:3]))
            i = j if j > i else i + 1

for r in results:
    print(f"{r[0]}:{r[1]}: {r[2]} -> {r[3]} used at {r[4]} without nearby guard")
print(f"TOTAL {len(results)}", file=sys.stderr)
