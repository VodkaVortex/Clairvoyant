#!/usr/bin/env python3
"""Find candidate stale-header-pointer-after-pull patterns in receive-path parsers.

Strategy: for each call to pskb_may_pull/pskb_pull/__pskb_pull_tail/skb_linearize
in a function, collect pointer captures earlier in the same function of the form
  type *var = <expr into skb>      (skb_header_pointer, skb->data cast, *_hdr(skb), skb_network_header...)
Then check whether var is dereferenced (var->field, var[N], *var) AFTER the pull
call line without being reassigned between the pull and the use.
"""
import os, re, sys

S = sys.argv[1] if len(sys.argv) > 1 else "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s03"

PULL_RE = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|__skb_linearize)\s*\(')
CAPTURE_RE = re.compile(
    r'^\s*(?:const\s+|volatile\s+|static\s+)*'
    r'(?:struct\s+|enum\s+|union\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\**\s*'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);',
)
INTO_SKB = re.compile(
    r'(skb_header_pointer\s*\(|'
    r'->data\b|'
    r'_hdr\s*\(\s*(?:\w*[sS]kb|\w*skb|skb|\*skb)\s*\)|'
    r'_hdr\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)|'
    r'skb_network_header\s*\(|skb_transport_header\s*\(|skb_mac_header\s*\(|'
    r'skb_tail_pointer\s*\(|skb_tailroom_reserve)'
)
USE_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:->|\[|\.\s*\*|\*\s*\()|\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')

def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), text, flags=re.S)
    text = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group(0)), text)
    return text

def func_spans(lines):
    """Yield (start, end, name) for top-level-ish function definitions."""
    i = 0
    n = len(lines)
    while i < n:
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_ \t\*]*)\(', lines[i])
        if m and not lines[i].lstrip().startswith(('#', '//', '*')) and not re.match(r'^\s*(if|for|while|switch|return|else|do)\b', lines[i]):
            # find opening brace
            j = i
            hdr = ''
            while j < n and j < i + 6:
                hdr += lines[j]
                if '{' in lines[j]:
                    break
                j += 1
            if j < n and '{' in lines[j]:
                depth = 0
                k = j
                while k < n:
                    depth += lines[k].count('{') - lines[k].count('}')
                    if depth == 0 and k > j:
                        yield (i, k, m.group(1).strip()[-40:], lines)
                        i = k + 1
                        break
                    k += 1
                else:
                    i = k
            else:
                i += 1
        else:
            i += 1

def analyze(path):
    out = []
    try:
        with open(path, 'r', errors='replace') as f:
            raw = f.read()
    except OSError:
        return out
    text = strip_comments(raw)
    lines = text.split('\n')
    for (fs, fe, fname, _) in func_spans(lines):
        body = lines[fs:fe+1]
        # capture var -> (line_offset, expr)
        captures = {}
        for idx, ln in enumerate(body):
            m = CAPTURE_RE.match(ln)
            if m and INTO_SKB.search(m.group(3) or ''):
                var = m.group(2)
                captures.setdefault(var, (fs + idx, m.group(3)))
        if not captures:
            continue
        for idx, ln in enumerate(body):
            pm = PULL_RE.search(ln)
            if not pm:
                continue
            pull_line = fs + idx + 1  # 1-based
            for var, (cap_line, cap_expr) in captures.items():
                if cap_line >= pull_line - 1:
                    continue
                # check uses after pull without reassignment
                reassigned = False
                uses = []
                for idx2 in range(idx + 1, len(body)):
                    ln2 = body[idx2]
                    if re.search(r'\b' + re.escape(var) + r'\s*=[^=]', ln2):
                        reassigned = True
                        break
                    um = re.search(r'\b' + re.escape(var) + r'\s*(->|\[)', ln2)
                    if um:
                        uses.append((fs + idx2 + 1, ln2.strip()))
                if uses and not reassigned:
                    out.append((path, fname, var, cap_line + 1, pull_line, uses[:4]))
    return out

def main():
    results = []
    for root, dirs, files in os.walk(os.path.join(S, 'net')):
        dirs[:] = [d for d in dirs if d not in ('selftests',)]
        for fn in files:
            if fn.endswith('.c'):
                p = os.path.join(root, fn)
                results.extend(analyze(p))
    for r in sorted(results, key=lambda x: (x[0], x[3])):
        rel = os.path.relpath(r[0], S)
        print(f"{rel}:{r[2]}:{r[1]}: cap@{r[3]} pull@{r[4]} uses@{[u[0] for u in r[5]]}")
        for (ul, ut) in r[5]:
            print(f"    use {ul}: {ut[:110]}")
    print(f"TOTAL {len(results)}", file=sys.stderr)

main()
