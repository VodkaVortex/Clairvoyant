import re, os, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"

# tasklet candidate: (file, lock regex obj base)
napi_cands = [
 ("drivers/net/ethernet/broadcom/b44.c","tx_lock"),
 ("drivers/net/ethernet/broadcom/bcm63xx_enet.c","rx_lock"),
 ("drivers/net/ethernet/freescale/fs_enet/fs_enet-main.c","tx_lock"),
 ("drivers/net/ethernet/freescale/ucc_geth.c","lock"),
 ("drivers/net/ethernet/natsemi/natsemi.c","lock"),
 ("drivers/net/ethernet/realtek/8139too.c","rx_lock"),
 ("drivers/net/ethernet/ti/cpmac.c","rx_lock"),
 ("drivers/net/ethernet/toshiba/tc35815.c","rx_lock"),
 ("drivers/net/ethernet/via/via-rhine.c","lock"),
 ("drivers/net/fjes/fjes_main.c","rx_status_lock"),
 ("drivers/net/wan/fsl_ucc_hdlc.c","lock"),
 ("drivers/net/xen-netfront.c","rx_lock"),
]
lock_usage = re.compile(r'(spin_lock\w*)\s*\(\s*&?\s*([^);]+?)\s*\)')
def norm(l):
    l = l.strip()
    parts = re.split(r'->|\.', l)
    return parts[-1].strip()

for relf, lockname in napi_cands:
    path = os.path.join(ROOT, relf)
    with open(path, errors="replace") as fh: src = fh.read()
    lines = src.split("\n")
    print(f"\n##### {relf}  lock~{lockname}")
    for i, ln in enumerate(lines, 1):
        for m in lock_usage.finditer(ln):
            lk, obj = m.group(1), norm(m.group(2))
            if obj == lockname:
                print(f"  {i}: {lk}({m.group(2)}) | {ln.strip()[:90]}")
