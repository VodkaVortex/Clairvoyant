#!/usr/bin/env python3
"""Heuristic scanner for stale-pointer-across-pull patterns in loop parsers.

Finds functions that contain both (a) a header-pointer capture via
skb_header_pointer or a direct skb->data cast, and (b) a pull/linearize call,
then reports whether the captured variable is referenced after the pull line.
"""
import os, re, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s02"

CAPTURE_RE = re.compile(r"""
    (?P<var>\w+)\s*=\s*(?:
        skb_header_pointer\s*\( |
        (?:\([^)]*\*\)\s*)?skb_\w*->data(?:\s*\+\s*[\w.]+)? |
        skb_\w+->head\s*\+ |
        skb_tail_pointer\s*\(\s*\w+\s*\) |
        skb_network_header\s*\(\s*\w+\s*\) |
        skb_mac_header\s*\(\s*\w+\s*\) |
        skb_transport_header\s*\(\s*\w+\s*\) |
        skb_pull_data\s*\(
    )
""", re.X)

PULL_RE = re.compile(r"""\b(
    pskb_may_pull\s*\(| pskb_may_pull_reason\s*\(| pskb_pull\s*\(| pskb_pull_inline\s*\( |
    __pskb_pull\s*\(| __pskb_pull_tail\s*\(| skb_linearize\s*\(| skb_linearize_rcsum\s*\( |
    pskb_expand_head\s*\(| skb_cow\s*\(| skb_cow_head\s*\(| skb_unclone\s*\(| skb_share_check\s*\(
)\b""", re.X)

FUNC_START = re.compile(r'^(?:static\s+|inline\s+|const\s+)*[\w\s\*]+?\b(\w+)\s*\([^;]*\)\s*$|^(?:static\s+|inline\s+)*[\w\s\*]+?\b(\w+)\s*\(')

def split_functions(src):
    """Yield (name, start_line, [lines]) for each top-level function."""
    funcs = []
    lines = src.split('\n')
    i = 0
    n = len(lines)
    func_start_re = re.compile(r'^[A-Za-z_].*\)\s*$|^[A-Za-z_].*\)\s*\{')
    while i < n:
        line = lines[i]
        m = re.match(r'^((?:[A-Za-z_][\w]*\s+)*)([A-Za-z_]\w*)\s*\(', line)
        # crude function detection: line ends with '{' or next line is '{'
        if (not line.startswith(('\t', ' ', '#', '*', '/*', ' */')) and
                re.search(r'\w\s*\(', line) and
                (line.rstrip().endswith('{') or
                 (i+1 < n and lines[i+1].strip() == '{')) and
                not line.lstrip().startswith(('if','for','while','switch','return','}')) and
                '=' not in line.split('(')[0]):
            # find matching closing brace
            depth = 0
            body = []
            j = i
            started = False
            while j < n:
                l = lines[j]
                depth += l.count('{') - l.count('}')
                body.append(l)
                if '{' in l:
                    started = True
                if started and depth <= 0:
                    break
                j += 1
            name_m = re.search(r'(\w+)\s*\(', line)
            if name_m and depth <= 0:
                funcs.append((name_m.group(1), i+1, body))
            i = j + 1
        else:
            i += 1
    return funcs

def scan():
    results = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in ('.git',)]
        for fn in filenames:
            if not fn.endswith(('.c', '.h')):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, 'r', errors='replace') as f:
                    src = f.read()
            except OSError:
                continue
            if 'pskb_may_pull' not in src and 'pskb_pull' not in src and \
               '__pskb_pull' not in src and 'skb_linearize' not in src and \
               'skb_cow' not in src and 'pskb_expand_head' not in src and 'skb_unclone' not in src:
                continue
            for (fname, fline, body) in split_functions(src):
                text = '\n'.join(body)
                if not PULL_RE.search(text):
                    continue
                captures = {}
                for li, l in enumerate(body):
                    for m in CAPTURE_RE.finditer(l):
                        var = m.group('var')
                        if var and var not in ('if','while','for','return','size_t','sizeof'):
                            captures.setdefault(var, li)
                if not captures:
                    continue
                # for each capture, check use after the first pull
                first_pull = None
                for li, l in enumerate(body):
                    if PULL_RE.search(l):
                        first_pull = li
                        break
                if first_pull is None:
                    continue
                for var, cli in captures.items():
                    if cli >= first_pull:
                        continue
                    # uses after pull: var-> or var. or var[ or *var
                    uses = []
                    for li in range(first_pull+1, len(body)):
                        l = body[li]
                        if re.search(r'(?<![\w.>])' + re.escape(var) + r'\s*(->|\.\w|\[)', l):
                            uses.append(li)
                        elif re.search(r'\*\s*' + re.escape(var) + r'\b', l):
                            uses.append(li)
                    if uses:
                        results.append((os.path.relpath(path, ROOT), fname, fline,
                                        var, cli, first_pull, uses[:8]))
    return results

if __name__ == '__main__':
    res = scan()
    print(f"total candidate functions with capture-before-pull + use-after-pull: {len(res)}")
    for r in sorted(res, key=lambda x: (x[0], x[2])):
        rel, fname, fline, var, cli, fp, uses = r
        print(f"{rel}:{fline} fn={fname} var={var} cap_line_off={cli} pull_off={fp} use_offs={uses}")
