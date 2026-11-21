import re, sys

def extract_locks(path, plain_re, bh_re):
    """Return list of (line_no, lock_expr) for each acquisition."""
    out = []
    with open(path, errors="ignore") as f:
        for i, line in enumerate(f, 1):
            for m in re.finditer(plain_re, line):
                out.append((i, m.group(1).strip(), "plain"))
            for m in re.finditer(bh_re, line):
                out.append((i, m.group(1).strip(), "bh"))
    return out

if __name__ == "__main__":
    path = sys.argv[1]
    plain_re = re.compile(r"spin_lock\s*\(\s*&?([^);]+?)\s*\)")
    bh_re = re.compile(r"spin_lock_(?:bh|irqsave|irq|irqrestore|nested|nested_bh)\s*\(\s*&?([^);]+?)\s*[,)]")
    for ln, lock, kind in extract_locks(path, plain_re, bh_re):
        print(f"{ln}\t{kind}\t{lock}")
