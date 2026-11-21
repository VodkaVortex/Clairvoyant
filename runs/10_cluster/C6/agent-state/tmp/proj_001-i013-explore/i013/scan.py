#!/usr/bin/env python3
"""Scan s04 net/ + drivers/ for capture -> head-reallocating-call -> stale-use chains.
Heuristic: within the function containing a skb_cow/skb_cow_head/skb_unclone/
skb_share_check/pskb_expand_head/skb_linearize call, find pointer captures that look
like pointers into skb->head (casts of skb->data / *_hdr(skb) / skb_header_pointer)
that were NOT reassigned between capture and the call, and are dereferenced after it.
"""
import re, os, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C6/public/snapshots/s04"

RELOC = re.compile(r'\b(skb_cow_head|skb_cow|skb_unclone|skb_share_check|pskb_expand_head|skb_linearize|__skb_linearize|__pskb_pull_tail|pskb_may_pull|pskb_pull)\s*\(')

# capture patterns producing a pointer into the skb
CAPTURE = re.compile(
    r'^\s*(?:const\s+)?(?:struct\s+)?[\w\*]+?\s*\*+\s*(\w+)\s*=\s*'
    r'([^;]*?)\s*;\s*(?://.*)?$'
)
CAP_SRC = re.compile(
    r'(skb_header_pointer\s*\(|->data\b|\bskb->data\b|_hdr\s*\(\s*skb\s*\)|skb_network_header|skb_transport_header|skb_mac_header|skb_tail_pointer|skb->head)'
)
IDENT_DEREF = re.compile(r'\b([A-Za-z_]\w*)\s*(?:->|\.)|\*\s*([A-Za-z_]\w*)')

def functions(text):
    """Yield (startline, endline, headerline, body) for top-level functions."""
    lines = text.split('\n')
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        # function definition heuristic: identifier(...)  {  at col 0
        m = re.match(r'^[A-Za-z_].*\)\s*\{', line)
        if m or (line.startswith('{') ):
            # find header start: walk back over continuation lines starting at col 0 or continuation
            start = i
            # take header line as i (assume single-line sig; else use previous lines)
            hdr = line
            # find matching closing brace
            depth = 0
            j = i
            started = False
            while j < n:
                for ch in lines[j]:
                    if ch == '{':
                        depth += 1; started = True
                    elif ch == '}':
                        depth -= 1
                        if started and depth == 0:
                            break
                if started and depth == 0:
                    break
                j += 1
            if started and depth == 0:
                yield (start, j, hdr, lines[start:j+1])
                i = j + 1
                continue
        i += 1

def scan_file(path):
    try:
        text = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        return []
    out = []
    for (fs, fe, hdr, body) in functions(text):
        blob = '\n'.join(body)
        if not RELOC.search(blob):
            continue
        # line numbers relative to file
        # find captures with absolute line numbers
        for idx, line in enumerate(body):
            abs_ln = fs + idx
            mc = CAPTURE.match(line)
            if not mc:
                continue
            var, src = mc.group(1), mc.group(2)
            if 'skb' not in src and 'skb' not in line:
                continue
            if not CAP_SRC.search(src):
                continue
            if var in ('skb', 'sk', 'dev', 'net', 'head', 'data'):
                continue
            # find all reallocating calls after capture in this function
            for ridx, rline in enumerate(body[idx+1:], start=idx+1):
                if not RELOC.search(rline):
                    continue
                call = RELOC.search(rline).group(1)
                # check if var reassigned between capture and call
                reassigned = False
                for k in range(idx+1, ridx):
                    if re.search(r'\b%s\s*=' % re.escape(var), body[k]):
                        reassigned = True
                        break
                if reassigned:
                    continue
                # check dereference of var after the call until end of function
                uses = []
                for u in range(ridx+1, len(body)):
                    ul = body[u]
                    # stop at function end naturally; skip comments-only
                    if re.search(r'\b%s\s*(->|\.)' % re.escape(var), ul) or re.search(r'\(\s*%s\s*\)' % re.escape(var), ul):
                        uses.append(fs + u)
                if uses:
                    out.append({
                        'file': path.replace(ROOT + '/', ''),
                        'func_start': fs + 1,
                        'capture_line': abs_ln + 1,
                        'capture_src': line.strip()[:160],
                        'call_line': fs + ridx + 1,
                        'call': call,
                        'call_src': rline.strip()[:160],
                        'use_lines': uses[:6],
                        'use_src': body[uses[0] - fs - 1].strip()[:160] if uses else '',
                    })
    return out

def main():
    targets = []
    for base in ('net', 'drivers'):
        b = os.path.join(ROOT, base)
        for dirpath, dirs, files in os.walk(b):
            if '/.git' in dirpath:
                continue
            for f in files:
                if f.endswith('.c'):
                    targets.append(os.path.join(dirpath, f))
    results = []
    for t in targets:
        results.extend(scan_file(t))
    json.dump(results, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results.json'), 'w'), indent=1)
    print(f"scanned {len(targets)} files, {len(results)} capture->realloc->use chains")

if __name__ == '__main__':
    main()
