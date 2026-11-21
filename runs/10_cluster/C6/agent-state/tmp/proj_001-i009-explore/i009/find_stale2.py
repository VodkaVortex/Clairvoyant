#!/usr/bin/env python3
"""v2: capture = plain assignments to declared pointer vars + declarations with initializers.
Flag: var captured into skb (hdr accessor / skb->data / skb_header_pointer) BEFORE a
pskb_may_pull/pskb_pull/__pskb_pull_tail/skb_linearize call in the same function, and
dereferenced AFTER the pull without reassignment."""
import os, re, sys

S = sys.argv[1]
SCAN_DIRS = sys.argv[2:] or [os.path.join(S, 'net')]

PULL_RE = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|__skb_linearize|pskb_expand_head|skb_cow|skb_cow_head|skb_unclone)\s*\(')
ASSIGN_RE = re.compile(r'^\s*(?:const\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);\s*$')
DECL_RE = re.compile(r'\*\s*([A-Za-z_][A-Za-z0-9_]*)\b')
INTO_SKB = re.compile(
    r'(skb_header_pointer\s*\(|'
    r'\bskb->data\b|\b\w+->data\b|'
    r'\b\w*_hdr\s*\(\s*[A-Za-z_][A-Za-z0-9_.\->]*\s*\)|'
    r'skb_network_header\s*\(|skb_transport_header\s*\(|skb_mac_header\s*\(|'
    r'skb_tail_pointer\s*\(|skb_shinfo\s*\(|skb->head\b|\w+->head\b)'
)
CAST_PTR_RE = re.compile(r'^\(\s*(?:const\s+)?(struct\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\*\s*\)\s*')

def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), text, flags=re.S)
    text = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group(0)), text)
    return text

def func_spans(lines):
    i, n = 0, len(lines)
    while i < n:
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_ \t\*]*)\(', lines[i])
        if m and not lines[i].lstrip().startswith(('#', '//', '*')) and \
           not re.match(r'^\s*(if|for|while|switch|return|else|do)\b', lines[i]) and \
           not re.search(r'=\s*$', lines[i]):
            j = i
            while j < n and j < i + 8:
                if '{' in lines[j]:
                    break
                j += 1
            if j < n and j < i + 8 and '{' in lines[j]:
                depth, k = 0, j
                while k < n:
                    depth += lines[k].count('{') - lines[k].count('}')
                    if depth == 0 and k > j:
                        yield (i, k)
                        i = k + 1
                        break
                    k += 1
                else:
                    i = n
            else:
                i += 1
        else:
            i += 1

def analyze(path):
    out = []
    try:
        with open(path, 'r', errors='replace') as f:
            text = strip_comments(f.read())
    except OSError:
        return out
    lines = text.split('\n')
    for (fs, fe) in func_spans(lines):
        body = lines[fs:fe+1]
        # declared pointer vars
        ptrvars = set()
        for ln in body:
            for dm in DECL_RE.finditer(ln):
                ptrvars.add(dm.group(1))
        captures = {}
        for idx, ln in enumerate(body):
            # declaration with initializer: struct foo *x = expr;
            dm = re.match(r'^\s*(?:const\s+|static\s+)*(?:struct\s+|enum\s+|union\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);\s*$', ln)
            if dm and INTO_SKB.search(dm.group(2)):
                captures.setdefault(dm.group(1), (fs + idx + 1, dm.group(2).strip()))
                continue
            am = ASSIGN_RE.match(ln)
            if am and am.group(1) in ptrvars:
                expr = am.group(2)
                if INTO_SKB.search(expr) or (CAST_PTR_RE.match(expr) and INTO_SKB.search(expr)):
                    captures.setdefault(am.group(1), (fs + idx + 1, expr.strip()))
        if not captures:
            continue
        for idx, ln in enumerate(body):
            if not PULL_RE.search(ln):
                continue
            pull_line = fs + idx + 1
            for var, (cap_line, cap_expr) in captures.items():
                if cap_line > pull_line:
                    continue
                reassigned_after = False
                uses = []
                for idx2 in range(idx + 1, len(body)):
                    ln2 = body[idx2]
                    if re.search(r'\b' + re.escape(var) + r'\s*=[^=]', ln2):
                        reassigned_after = True
                        break
                    um = re.search(r'\b' + re.escape(var) + r'\s*(->|\[)|\*\s*' + re.escape(var) + r'\b|\(\s*\*\s*' + re.escape(var) + r'\s*\)', ln2)
                    if um:
                        uses.append((fs + idx2 + 1, ln2.strip()))
                if uses and not reassigned_after:
                    out.append((path, fs, fe, var, cap_line, pull_line, uses[:5]))
    return out

def main():
    results = []
    for d in SCAN_DIRS:
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in ('selftests',)]
            for fn in files:
                if fn.endswith('.c'):
                    results.extend(analyze(os.path.join(root, fn)))
    for r in results:
        rel = os.path.relpath(r[0], S)
        print(f"{rel}: cap {r[3]} @line {r[4]} (func lines {r[1]+1}-{r[2]+1}); pull @line {r[5]}; stale uses: {r[6]}")
    print(f"TOTAL {len(results)}", file=sys.stderr)

main()
