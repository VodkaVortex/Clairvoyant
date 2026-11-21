#!/usr/bin/env python3
"""For each function containing a pskb pull, print pull lines and whether the function
contains a loop; for loop cases with pulls inside loop bodies, flag them."""
import re, sys

path = sys.argv[1]
PULL = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|pskb_expand_head|skb_cow_head|skb_cow|skb_unclone|skb_share_check)\s*\(')

lines = open(path, 'r', errors='replace').read().split('\n')
n = len(lines)
i = 0
while i < n:
    l = lines[i]
    # function start heuristic: non-indented line with '(' , not preprocessor/comment
    if l and not l[0].isspace() and '(' in l and not l.startswith(('#','/','*')):
        # scan forward to find '{' (function body) before ';'
        j = i
        found = False
        while j < n and j < i + 8:
            if ';' in lines[j] and '{' not in lines[j]:
                break
            if '{' in lines[j]:
                found = True
                break
            j += 1
        if found:
            # brace match
            depth = 0
            k = j
            end = None
            while k < n:
                depth += lines[k].count('{') - lines[k].count('}')
                if depth == 0 and k >= j:
                    end = k
                    break
                k += 1
            if end is not None:
                body = range(j, end+1)
                pull_lines = [x+1 for x in body if PULL.search(lines[x])]
                if pull_lines:
                    # loop detection within body (crude: any for/while/do at position)
                    loops = [x+1 for x in body if re.match(r'\s*(for|while|do)\b', lines[x])]
                    if loops:
                        # pull inside a loop body? check if any pull line is after a loop header and before the loop's end (approx: before next line at same-or-less indent than loop header)
                        inside = []
                        for pl in pull_lines:
                            for ll in loops:
                                if pl > ll:
                                    # find indent of loop header
                                    ind = len(lines[ll-1]) - len(lines[ll-1].lstrip())
                                    # loop ends at first subsequent line with indent <= ind that isn't blank/brace
                                    e = ll
                                    for x in range(ll, end+1):
                                        s2 = lines[x]
                                        if not s2.strip():
                                            continue
                                        ind2 = len(s2) - len(s2.lstrip())
                                        if x+1 > ll and ind2 <= ind and s2.strip() != '}' and s2.strip() != '{' and not s2.strip().startswith('}') and not s2.strip().startswith('/*') and not s2.strip().startswith('*'):
                                            e = x+1
                                            break
                                        e = x+1
                                    if pl <= e:
                                        inside.append(pl)
                                        break
                        print(f"{path}|{i+1}-{end+1}|pulls={pull_lines}|loops={loops}|pull_in_loop={inside}")
                i = end + 1 if end else i + 1
                continue
    i += 1
