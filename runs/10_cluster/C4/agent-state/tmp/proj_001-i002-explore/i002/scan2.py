import re, os, subprocess

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C4/public/snapshots/s01"

out = subprocess.run(["grep","-rl","--include=*.c","-E","proc_dointvec|proc_doulongvec|proc_dostring|proc_douintvec|proc_dou8vec", ROOT], capture_output=True, text=True)
files = [f for f in out.stdout.strip().split("\n") if f]

def strip_comments_strings(src):
    res = []
    i = 0; n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i+1 < n and src[i+1] == '*':
            j = src.find('*/', i+2)
            if j < 0: j = n-2
            res.append(' ' * (j+2-i)); i = j+2
        elif c == '/' and i+1 < n and src[i+1] == '/':
            j = src.find('\n', i)
            if j < 0: j = n
            res.append(' ' * (j-i)); i = j
        elif c == '"':
            j = i+1
            while j < n:
                if src[j] == '\\': j += 2; continue
                if src[j] == '"': break
                j += 1
            res.append('" "' * 1); i = j+1
        elif c == "'":
            j = i+1
            while j < n:
                if src[j] == '\\': j += 2; continue
                if src[j] == "'": break
                j += 1
            i = j+1
        else:
            res.append(c); i += 1
    return ''.join(res)

def extract_functions(clean):
    """Return list of (name, sig_start_offset, body) using brace depth on comment-stripped src."""
    funcs = []
    depth = 0
    i = 0; n = len(clean)
    last_boundary = 0  # offset after last ; or } at depth 0
    while i < n:
        c = clean[i]
        if c == '{':
            if depth == 0:
                sig = clean[last_boundary:i]
                # could be struct init `= {`, array init, etc. Function sig must contain '(' and ')'
                m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', sig)
                if m and '=' not in sig.split('(')[0]:
                    name = m.group(1)
                    # find function end
                    j = i; d = 0
                    while j < n:
                        if clean[j] == '{': d += 1
                        elif clean[j] == '}':
                            d -= 1
                            if d == 0: break
                        j += 1
                    body = clean[last_boundary:j+1]
                    line = clean[:last_boundary].count('\n')+1
                    funcs.append((name, line, body))
                    i = j
                    depth = 0
                    last_boundary = j+1
                    i += 1
                    continue
            depth += 1
        elif c == '}':
            depth -= 1
            if depth <= 0:
                depth = 0
                last_boundary = i+1
        elif c == ';' and depth == 0:
            last_boundary = i+1
        i += 1
    return funcs

PARSE_CALL = re.compile(r'\b(proc_dointvec_minmax_sysadmin|proc_dointvec_minmax_warn_RT_change|proc_dointvec_minmax_bpf_restricted|proc_dointvec_minmax_coredump|proc_dointvec_ms_jiffies|proc_dointvec_jiffies|proc_dointvec_userhz_jiffies|proc_dointvec_minmax|proc_doulongvec_minmax|proc_doulongvec_ms_jiffies_minmax|proc_douintvec_minmax|proc_douintvec|proc_dou8vec_minmax|proc_dointvec|proc_dostring)\s*\(')
GENERIC = {'do_proc_dointvec','do_proc_doulongvec_minmax','do_proc_douintvec','do_proc_dostring','do_proc_dointvec_minmax_conv','proc_dointvec','proc_dointvec_minmax','proc_dostring','proc_doulongvec_minmax','proc_douintvec','proc_doulongvec_ms_jiffies_minmax','proc_douintvec_minmax','proc_dou8vec_minmax','proc_dointvec_jiffies','proc_dointvec_userhz_jiffies','proc_dointvec_ms_jiffies','proc_do_large_bitmap','proc_dostring_static_key','proc_treat_ro_intvec','proc_doulongvec','proc_dolongvec'}

results = []
for f in files:
    try:
        src = open(f, errors='replace').read()
    except Exception:
        continue
    clean = strip_comments_strings(src)
    for name, line, body in extract_functions(clean):
        if name in GENERIC: continue
        calls = PARSE_CALL.findall(body)
        if not calls: continue
        rel = os.path.relpath(f, ROOT)
        results.append((rel, line, name, sorted(set(calls)), body))

print(f"TOTAL: {len(results)}")
for r in sorted(results, key=lambda x: (x[0], x[1])):
    print(f"{r[0]}:{r[1]}  {r[2]}  [{','.join(r[3])}]")
