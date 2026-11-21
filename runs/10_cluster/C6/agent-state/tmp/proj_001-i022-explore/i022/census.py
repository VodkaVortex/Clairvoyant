import re, os, json, sys

RELOC = re.compile(r'\b(pskb_may_pull|pskb_pull|pskb_pull_reserve|__pskb_pull_tail|skb_linearize|__skb_linearize|skb_cow|skb_cow_head|pskb_expand_head|__pskb_expand_head|skb_unclone|skb_share_check)\s*\(')

def scan(tree):
    census = []
    for root, dirs, files in os.walk(tree):
        for f in files:
            if not f.endswith('.c') and not f.endswith('.h'):
                continue
            p = os.path.join(root, f)
            try:
                text = open(p, encoding='utf-8', errors='replace').read()
            except Exception:
                continue
            lines = text.split('\n')
            n = len(lines)
            i = 0
            while i < n:
                l = lines[i]
                if l and l[0] not in (' ', '\t', '#', '/', '*', '}', 'I', 'E', 'W') and re.search(r'\(', l):
                    # possible function head; check next 3 lines for '{'
                    window = '\n'.join(lines[i:i+4])
                    if re.search(r'\)\s*\{', window) or re.search(r'\)\s*\n\s*{', window):
                        nm = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', l)
                        if nm:
                            depth = 0; started = False; end = None
                            for j in range(i, min(n, i+2000)):
                                for ch in lines[j]:
                                    if ch == '{':
                                        depth += 1; started = True
                                    elif ch == '}':
                                        depth -= 1
                                        if started and depth == 0:
                                            end = j; break
                                if end is not None: break
                            if end is not None and end > i:
                                body = '\n'.join(lines[i:end+1])
                                for mm in RELOC.finditer(body):
                                    ln = i + body[:mm.start()].count('\n') + 1
                                    census.append((p, nm.group(1), i+1, mm.group(1), ln))
                                i = end + 1
                                continue
                i += 1
    return census

c1 = scan('net')
json.dump(c1, open(os.environ['TMPDIR']+'/i022/census_net.json','w'))
print('net entries:', len(c1), 'files:', len(set(x[0] for x in c1)))
