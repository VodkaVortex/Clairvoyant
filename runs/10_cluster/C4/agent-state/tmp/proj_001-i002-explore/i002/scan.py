import re, os, sys, subprocess

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C4/public/snapshots/s01"

# files referencing proc_do helpers
out = subprocess.run(["grep","-rl","--include=*.c","-E","proc_dointvec|proc_doulongvec|proc_dostring|proc_douintvec|proc_dou8vec", ROOT], capture_output=True, text=True)
files = out.stdout.strip().split("\n")

PARSE_CALL = re.compile(r'\b(proc_dointvec_minmax|proc_dointvec_ms_jiffies|proc_dointvec_jiffies|proc_dointvec_userhz_jiffies|proc_dointvec_minmax_sysadmin|proc_doulongvec_minmax|proc_doulongvec_ms_jiffies_minmax|proc_douintvec_minmax|proc_douintvec|proc_dou8vec_minmax|proc_dointvec|proc_dostring)\s*\(')

def extract_functions(src):
    """Yield (name, start_line, body) for top-level and static functions."""
    funcs = []
    # find function definitions: identifier ( at start of line, followed by { on same or next lines
    for m in re.finditer(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{)]*\)?\s*\n?\s*\{', src, re.M):
        name = m.group(1)
        # skip control keywords
        if name in ("if","for","while","switch","return","sizeof","else","do"):
            continue
        start = m.start()
        brace = src.find('{', m.start())
        if brace < 0: continue
        depth = 0
        i = brace
        instr = None
        while i < len(src):
            c = src[i]
            if instr:
                if c == '\\': i += 2; continue
                if c == instr: instr = None
            elif c in ('"',"'"): instr = c
            elif c == '/' and i+1 < len(src) and src[i+1] == '*':
                j = src.find('*/', i+2)
                i = (j+2) if j>=0 else len(src)
                continue
            elif c == '/' and i+1 < len(src) and src[i+1] == '/':
                j = src.find('\n', i)
                i = j if j>=0 else len(src)
                continue
            elif c == '{': depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    body = src[start:i+1]
                    funcs.append((name, src[:start].count('\n')+1, body))
                    break
            i += 1
    return funcs

results = []
for f in files:
    try:
        src = open(f, errors='replace').read()
    except Exception:
        continue
    for name, line, body in extract_functions(src):
        calls = PARSE_CALL.findall(body)
        if not calls:
            continue
        # ignore the generic implementations themselves
        if name.startswith('do_proc_') or name in ('proc_dointvec','proc_dointvec_minmax','proc_dostring','proc_doulongvec_minmax','proc_douintvec','proc_doulongvec_ms_jiffies_minmax','proc_douintvec_minmax','proc_dou8vec_minmax','proc_dointvec_jiffies','proc_dointvec_userhz_jiffies','proc_dointvec_ms_jiffies','proc_do_large_bitmap','proc_dostring_static_key','proc_treat_ro_intvec'):
            continue
        rel = os.path.relpath(f, ROOT)
        # signals
        shadow = bool(re.search(r'struct\s+ctl_table\s+\w+\s*=', body)) or bool(re.search(r'ctl_table_copy|memcpy\s*\([^,]*,\s*ctl', body))
        stackdata = bool(re.search(r'\.data\s*=\s*&\w+', body))
        ret_captured = bool(re.search(r'=\s*\w*\s*(proc_dointvec|proc_doulongvec|proc_dostring|proc_douintvec|proc_dou8vec)', body))
        ret_checked = bool(re.search(r'if\s*\(\s*(ret|rc|err|error)\s*[=!]=?|if\s*\(\s*!\s*(ret|rc|err|error)|return\s+(ret|rc|err|error)', body))
        results.append((rel, line, name, ','.join(sorted(set(calls))), shadow, stackdata, ret_captured, ret_checked))

print(f"{len(results)} handler functions calling proc_do* parsers")
print(f"{'file':60s} {'line':>5s} {'function':40s} {'parsers':45s} shadow stackdata retcap retchk")
for r in sorted(results, key=lambda x:(x[0],x[1])):
    print(f"{r[0]:60s} {r[1]:5d} {r[2]:40s} {r[3]:45s} {str(r[4])[0]}      {str(r[5])[0]}        {str(r[6])[0]}      {str(r[7])[0]}")
