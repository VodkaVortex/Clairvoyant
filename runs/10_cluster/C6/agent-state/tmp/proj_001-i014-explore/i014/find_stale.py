#!/usr/bin/env python3
"""Find stale-skb-pointer candidates: pointer captured from skb data before a
pull/linearize call and dereferenced after it, in the same function."""
import re, sys, os, json

PULL_RE = re.compile(r'(?<![a-zA-Z0-9_])(pskb_may_pull|pskb_pull|__pskb_pull_tail|skb_linearize|pskb_pull_reserve|pskb_expand_head|skb_cow_head|skb_cow|skb_unclone)\s*\(')
# pointer capture from skb data
CAPTURE_RE = re.compile(
    r'(?<![a-zA-Z0-9_])([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?'
    r'(?:skb_header_pointer\s*\(|[a-zA-Z0-9_]*skb->data|skb_tail_pointer\s*\(|'
    r'(?:ip|ipv6|tcp|udp|sctp|icmp|icmp6|igmp|arp|eth|nfc|ieee|pn|nsh|mpls|gre|esp|ah|th|uh|iph|ip6h|greh|esph|ahh)_?hdr\s*\(|'
    r'skb_network_header\s*\(|skb_transport_header\s*\(|skb_mac_header\s*\(|'
    r'skb_get\s*\()'
)
LOOP_RE = re.compile(r'\b(while|for)\s*\(|\bdo\s*\{')
USE_RE_TMPL = r'(?<![a-zA-Z0-9_])%s\s*(->|\.|\[|\+\+|--|\)|;|\*)'  # crude use detection

def strip_comments_strings(lines):
    out = []
    in_block = False
    for ln in lines:
        s = ln
        # remove line comments
        s = re.sub(r'//.*$', '', s)
        if in_block:
            idx = s.find('*/')
            if idx == -1:
                out.append('')
                continue
            s = s[idx+2:]
            in_block = False
        s = re.sub(r'/\*.*?\*/', '', s)
        if '/*' in s:
            s = s[:s.find('/*')]
            in_block = True
        s = re.sub(r'"(\\.|[^"\\])*"', '""', s)
        s = re.sub(r"'(\\.|[^'\\])*'", "''", s)
        out.append(s)
    return out

def split_functions(lines):
    """yield (start_idx, end_idx, name, body_lines) using brace matching"""
    func_start_re = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_ \t\*]*\s+\**([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;]*$')
    i = 0
    n = len(lines)
    while i < n:
        m = func_start_re.match(lines[i])
        if m and '{' in ''.join(lines[i:i+4]):
            # find the opening brace
            j = i
            depth = 0
            started = False
            name = m.group(1)
            while j < n and j < i + 400:
                for ch in lines[j]:
                    if ch == '{':
                        depth += 1
                        started = True
                    elif ch == '}':
                        depth -= 1
                        if started and depth == 0:
                            yield (i, j, name, lines[i:j+1])
                            i = j + 1
                            break
                else:
                    j += 1
                    continue
                break
            else:
                i += 1
                continue
            if not started:
                i += 1
        else:
            i += 1

def analyze(path):
    res = []
    try:
        with open(path, 'r', errors='replace') as f:
            raw = f.readlines()
    except Exception:
        return res
    lines = strip_comments_strings(raw)
    for (fs, fe, name, body) in split_functions(lines):
        # find captures and pulls with body-relative indices
        captures = []  # (idx, var)
        pulls = []     # (idx, func)
        for bi, ln in enumerate(body):
            for m in CAPTURE_RE.finditer(ln):
                var = m.group(1)
                # skip non-pointer-ish or self-assignments
                captures.append((bi, var, m.group(0)))
            for m in PULL_RE.finditer(ln):
                pulls.append((bi, m.group(1)))
        if not pulls:
            continue
        for (pidx, pfunc) in pulls:
            for (cidx, var, cap) in captures:
                if cidx > pidx:
                    continue
                # find uses of var AFTER the pull line (or on the pull line but
                # note: on the pull line itself, args are evaluated first, so
                # only flag uses strictly after the pull line)
                stale_uses = []
                for ui in range(pidx + 1, len(body)):
                    uln = body[ui]
                    if re.search(r'(?<![a-zA-Z0-9_])' + re.escape(var) + r'(?![a-zA-Z0-9_])', uln):
                        # dereference-ish use
                        if re.search(r'(?<![a-zA-Z0-9_])' + re.escape(var) + r'\s*(->|\.)', uln) or \
                           re.search(r'->\s*' + re.escape(var), uln) or \
                           re.search(r'(?<![a-zA-Z0-9_])\*?\s*' + re.escape(var) + r'\s*\[', uln) or \
                           re.search(r'return\s+' + re.escape(var) + r'\s*;', uln) or \
                           re.search(r'(?<![a-zA-Z0-9_])' + re.escape(var) + r'\s*;', uln):
                            stale_uses.append((ui, uln.strip()[:120]))
                if stale_uses:
                    # loop context?
                    loop_before_pull = any(LOOP_RE.search(body[k]) for k in range(cidx, pidx))
                    loop_in_range = any(LOOP_RE.search(body[k]) for k in range(cidx, min(pidx+6, len(body))))
                    res.append({
                        'file': path, 'func': name,
                        'func_start_line': fs + 1, 'pull_line': fs + pidx + 1,
                        'pull_func': pfunc, 'capture_line': fs + cidx + 1,
                        'var': var, 'capture': cap.strip()[:80],
                        'loop_before_pull': loop_before_pull,
                        'loop_near': loop_in_range,
                        'uses': [{'line': fs + u + 1, 'text': t} for (u, t) in stale_uses[:6]],
                    })
    return res

def main():
    roots = sys.argv[1:]
    all_res = []
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in ('.git',)]
            for fn in files:
                if fn.endswith(('.c', '.h')):
                    all_res.extend(analyze(os.path.join(dirpath, fn)))
    # rank: loop context first
    all_res.sort(key=lambda r: (not r['loop_before_pull'], not r['loop_near'], r['file']))
    print(json.dumps(all_res, indent=1))
    sys.stderr.write(f"total candidates: {len(all_res)}, with loop_before_pull: {sum(1 for r in all_res if r['loop_before_pull'])}\n")

if __name__ == '__main__':
    main()
