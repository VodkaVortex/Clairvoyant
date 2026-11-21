import os, re, sys

root = "snapshots/s01"
pull_re = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|pskb_expand_head|skb_cow|skb_cow_head|skb_unclone|skb_share_check)\s*\(')
func_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
loop_re = re.compile(r'\b(for|while)\s*\(')

results = []
for dirpath, dirs, files in os.walk(root):
    for fn in files:
        if not fn.endswith('.c') and not fn.endswith('.h'):
            continue
        path = os.path.join(dirpath, fn)
        try:
            with open(path, 'r', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            continue
        # find function starts: line where func_re matches and next non-empty line ends with '{' at col 0 or same line '{'
        i = 0
        n = len(lines)
        while i < n:
            m = func_re.match(lines[i])
            if m:
                # look ahead for the opening brace at column 0
                j = i
                # allow signature spanning lines until we find '{' at start of line
                depth_open = None
                k = i
                while k < n and k < i + 8:
                    if lines[k].startswith('{'):
                        depth_open = k
                        break
                    if lines[k].rstrip().endswith(';'):
                        break
                    k += 1
                if depth_open is not None:
                    # find matching closing brace at col 0
                    e = depth_open + 1
                    while e < n and not lines[e].startswith('}'):
                        e += 1
                    body = lines[depth_open:e+1]
                    bodytext = ''.join(body)
                    pulls = [(depth_open+1+idx, l.rstrip()) for idx, l in enumerate(body) if pull_re.search(l)]
                    if pulls:
                        # determine if any pull is inside a loop: track loop headers and their brace spans
                        # naive: record line numbers of loop headers within body, and their indent
                        loop_lines = [depth_open+1+idx for idx,l in enumerate(body) if loop_re.search(l)]
                        # check loop bodies: from loop line, find opening brace, match to closing
                        inside_loops = []
                        for ll in loop_lines:
                            # find opening brace after loop line at same or greater indent
                            lidx = ll - depth_open - 1
                            # find first '{' from lidx
                            p = lidx
                            while p < len(body):
                                if '{' in body[p]:
                                    start = p
                                    break
                                if ';' in body[p] and p > lidx:
                                    # single-statement loop
                                    start = None
                                    break
                                p += 1
                            else:
                                start = None
                            if start is not None:
                                # match braces
                                d = 0
                                q = start
                                while q < len(body):
                                    d += body[q].count('{') - body[q].count('}')
                                    if d == 0:
                                        break
                                    q += 1
                                lo = depth_open+1+start
                                hi = depth_open+1+q
                                inside_loops.append((lo, hi, body[lidx].strip()[:80]))
                        for pl, txt in pulls:
                            for (lo, hi, hdr) in inside_loops:
                                if lo <= pl <= hi:
                                    results.append((path, pl, txt.strip()[:100], f"loop at {lo}: {hdr}"))
                                    break
                            else:
                                pass
                    i = e
                    continue
            i += 1

print(f"Total pull-in-loop sites: {len(results)}")
for r in results:
    print(f"{r[0]}:{r[1]}  {r[3]}")
    print(f"    {r[2]}")
