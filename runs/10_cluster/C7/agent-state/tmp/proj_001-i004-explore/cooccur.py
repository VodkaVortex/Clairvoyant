import re, sys, os
snap = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"
results = []
for root, dirs, files in os.walk(snap):
    dirs[:] = [d for d in dirs if d not in (".git",)]
    for fn in files:
        if not fn.endswith((".c",)):
            continue
        p = os.path.join(root, fn)
        try:
            src = open(p, errors="ignore").read()
        except Exception:
            continue
        if "ndo_start_xmit" not in src and "netdev_tx_t" not in src:
            continue
        lines = src.split("\n")
        # find plain spin_lock var usage lines and their enclosing functions
        plain = []
        for i, l in enumerate(lines):
            m = re.search(r"spin_lock\((&)([A-Za-z0-9_>\.\[\]\-]+)", l)
            if m:
                plain.append((i, m.group(2)))
        if not plain:
            continue
        for i, var in plain:
            # enclosing function: search backwards for a line matching 'static ... name(' or function def at col 0
            fname = None
            for j in range(i, -1, -1):
                m2 = re.match(r"^[A-Za-z_][A-Za-z0-9_ \*\t]*\(([A-Za-z0-9_]+)\(", lines[j]) 
                if m2 and not lines[j].startswith(("if", "for", "while", "switch", "return")):
                    fname = m2.group(1)
                    fline = j
                    break
            results.append((os.path.relpath(p, snap), i+1, var, fname))
for r in results:
    print("|".join(str(x) for x in r))
