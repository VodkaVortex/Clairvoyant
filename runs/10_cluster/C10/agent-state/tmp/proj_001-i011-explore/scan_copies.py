import subprocess, re, os
files = subprocess.check_output(["/usr/bin/rg","-n","memdup_user|copy_from_user|vmemdup_user","-g","*.c","-l"]).decode().split()
results = []
for f in files:
    lines = open(f, errors="ignore").readlines()
    for i,l in enumerate(lines):
        if re.search(r'copy_from_user|memdup_user\(', l) and 'memdup_user_nul' not in l:
            ctx = "".join(lines[max(0,i-40):i+45])
            # string consumer in context?
            if re.search(r'sscanf\s*\(|simple_strto|kstrto[ulxd]*\s*\(\s*[^,]*,\s*[0-9]|strcmp|strncmp|strchr|strrchr|strscpy|strcpy|strlen|strsep|strnstr|kstrtocstring|match_token|strreplace|strim|skip_spaces|strpbrk|strstr', ctx):
                # check terminator in context after copy
                after = "".join(lines[i:i+45])
                term = bool(re.search(r"\\0|nul|\[len\]|\[count\]|\[size\]|\[cnt\]", after, re.I))
                results.append((f, i+1, l.strip()[:110], term))
for r in results:
    print(f"{r[0]}:{r[1]} term_after={r[3]} | {r[2]}")
