import re, os
ROOT='/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12'
def show(path, a, b, tag):
    print(f"===== {path} {a}-{b} ({tag}) =====")
    lines=open(os.path.join(ROOT,path),errors='replace').readlines()
    for i in range(a, min(b, len(lines))+1):
        print(f"{i}: {lines[i-1].rstrip()}")
show('drivers/net/wan/sbni.c', 1220, 1232, 'SIOCDEVSHWSTATE ioctl tail? check function')
show('drivers/net/wan/sbni.c', 1390, 1432, 'enslave/emancipate')
