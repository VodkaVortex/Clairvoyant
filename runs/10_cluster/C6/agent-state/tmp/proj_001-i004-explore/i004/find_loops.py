import os, re, sys

root = sys.argv[1]
pull_re = re.compile(r'\b(pskb_may_pull|pskb_pull|__pskb_pull_tail|pskb_pull_reserve|skb_linearize)\s*\(')
file_hits = {}
for dirpath, dirnames, filenames in os.walk(root):
    for fn in filenames:
        if not fn.endswith(('.c', '.h')):
            continue
        p = os.path.join(dirpath, fn)
        try:
            with open(p, 'r', errors='ignore') as f:
                lines = f.readlines()
        except OSError:
            continue
        pull_lines = []
        for i, l in enumerate(lines):
            if pull_re.search(l):
                pull_lines.append(i)
        if pull_lines:
            file_hits[p] = (lines, pull_lines)

def enclosing_brace_start(lines, lineno):
    depth = 0
    for i in range(lineno, -1, -1):
        for ch in lines[i]:
            if ch == '}':
                depth += 1
            elif ch == '{':
                if depth == 0:
                    return i
                depth -= 1
    return None

results = []
for p, (lines, pull_lines) in file_hits.items():
    for pl in pull_lines:
        start = enclosing_brace_start(lines, pl)
        if start is None:
            continue
        # find nearest loop header line between start and pl
        loop_line = None
        for i in range(pl, start-1, -1):
            if re.search(r'\b(for|while|do)\b', lines[i]):
                loop_line = i
                break
        if loop_line is None:
            continue
        if pl - loop_line > 150:
            continue
        rel = os.path.relpath(p, root)
        results.append((rel, pl+1, loop_line+1, lines[loop_line].strip()[:100]))

for rel, pl, ll, hdr in sorted(results):
    print(f"{rel}:{pl}\tloop@{ll}\t{hdr}")
