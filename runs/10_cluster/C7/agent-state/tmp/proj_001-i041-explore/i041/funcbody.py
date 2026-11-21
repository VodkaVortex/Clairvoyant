import re
def find_func(text, name):
    # match any line starting the definition: name( ... possibly multiline, then { on some line
    idx = 0
    res=[]
    while True:
        # find name followed by ( at a definition-like position
        for m in re.finditer(r'(?m)^([ \t]*)(?:static\s+|inline\s+|__devinit\s+|__init\s+|__exit\s+|EXPORT[A-Z_]*\s*\(?)?([A-Za-z_][A-Za-z0-9_]*)\s*\(', text):
            if m.group(2)!=name: continue
            # check for ';' before '{'
            rest = text[m.end():]
            # limit lookahead
            seg = rest[:6000]
            semi = seg.find(';')
            brace = seg.find('{')
            if brace!=-1 and (semi==-1 or brace<semi):
                # count braces
                depth=0; i=0; start=m.start()
                # find opening brace
                j=text.find('{', m.end())
                depth=0
                k=j
                while k < len(text):
                    c=text[k]
                    if c=='{': depth+=1
                    elif c=='}':
                        depth-=1
                        if depth==0:
                            return (text[:m.start()].count('\n')+1, text[:k].count('\n')+1)
                    k+=1
                return None
        return None
    return None
