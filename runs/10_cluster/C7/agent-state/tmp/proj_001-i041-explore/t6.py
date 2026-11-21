import re
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s12/drivers/net/ethernet/silan/sc92031.c"
def_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\**([A-Za-z_][A-Za-z0-9_]*)\s*\(')
lines = open(p, errors='replace').readlines()
m = def_re.match(lines[833])
print("match on 834:", m, m.group(1) if m else None)
# try named group
def_re2 = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\**(?P<nm>[A-Za-z_][A-Za-z0-9_]*)\s*\(')
m2 = def_re2.match(lines[833])
print("named match:", m2.group('nm') if m2 else None)
print("group(1):", m.group(1))
