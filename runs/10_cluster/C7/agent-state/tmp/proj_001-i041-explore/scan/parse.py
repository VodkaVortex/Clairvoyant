import re, os, sys, json, glob
from collections import defaultdict

def read_fns(path):
    """Parse top-level C functions: name -> (start_line, end_line, body)."""
    try:
        txt = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        return {}
    lines = txt.split('\n')
    fns = {}
    # find function starts: identifier ( ... ) { at col 0
    i = 0
    n = len(lines)
    fnre = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    while i < n:
        m = fnre.match(lines[i])
        if m and not lines[i].rstrip().endswith(';'):
            # could be multi-line signature; scan forward for '{' at col 0 or after ')'
            j = i
            depth = 0
            sig = lines[i]
            found_open = None
            while j < n and j < i + 12:
                if '{' in lines[j]:
                    # ensure it's the body opener
                    if lines[j].lstrip().startswith('{') or re.search(r'\)\s*\{', lines[j]):
                        found_open = j
                        break
                j += 1
            if found_open is None:
                i += 1
                continue
            # brace match
            depth = 0
            k = found_open
            while k < n:
                depth += lines[k].count('{') - lines[k].count('}')
                if depth == 0 and k >= found_open:
                    break
                k += 1
            if k < n:
                fns[m.group(1)] = (i + 1, k + 1, '\n'.join(lines[i:k+1]))
                i = k + 1
                continue
        i += 1
    return fns

LOCK_RE = re.compile(r'(spin_lock(?:_irqsave|_irq|_bh|_nested|_irqsave_nested|_bh_nested)?)\s*\(\s*(?:&?\s*)?([^),;]+?)\s*[,)]')
IRQFLAG_RE = re.compile(r'spin_lock_irqsave\s*\(')
BH_RE = re.compile(r'(spin_lock_bh\s*\(|local_bh_disable\s*\()')

def lock_uses(body):
    """Return list of (variant, lockexpr)."""
    out = []
    for m in LOCK_RE.finditer(body):
        variant, expr = m.group(1), m.group(2).strip()
        out.append((variant, expr))
    return out

def base_name(expr):
    expr = expr.strip()
    expr = re.sub(r'^&', '', expr).strip()
    # strip container_of etc already done; take last component
    expr = expr.split('.')[-1] if '.' in expr else expr
    expr = expr.split('->')[-1]
    return expr.strip()

def has_bh_disable(body):
    return bool(re.search(r'spin_lock_bh\s*\(|local_bh_disable\s*\(', body))

def uses_flags_arg(body):
    """spin_lock_irqsave used anywhere."""
    return bool(re.search(r'spin_lock_irqsave\s*\(', body))

if __name__ == '__main__':
    files = [l.strip() for l in open(sys.argv[1]) if l.strip()]
    for f in files:
        if not os.path.exists(f):
            continue
        fns = read_fns(f)
        print(json.dumps({"file": f, "fns": {k: {"start": v[0], "end": v[1]} for k, v in fns.items()}}))
