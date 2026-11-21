import re, os, sys
sys.path.insert(0, "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/tmp/proj_001-i042-explore/i042")
from find_func_v2 import strip_comments_strings, find_all_funcs

root = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13"

# candidates: (file, lockexpr_base)
CANDS = [
 ("drivers/net/ethernet/marvell/sky2.c","phy_lock"),
 ("drivers/net/ethernet/atheros/atlx/atl1.c","mb_lock"),
 ("drivers/net/ethernet/ti/cpmac.c","rx_lock"),
 ("drivers/net/ethernet/broadcom/bcm63xx_enet.c","rx_lock"),
 ("drivers/net/ethernet/broadcom/bcm63xx_enet.c","tx_lock"),
 ("drivers/net/ethernet/freescale/fs_enet/fs_enet-main.c","tx_lock"),
 ("drivers/net/ethernet/freescale/ucc_geth.c","lock"),
 ("drivers/net/fjes/fjes_main.c","rx_status_lock"),
 ("drivers/net/wan/hd64572.c","lock"),
 ("drivers/net/wan/fsl_ucc_hdlc.c","lock"),
 ("drivers/net/ethernet/rdc/r6040.c","lock"),
 ("drivers/net/ethernet/natsemi/natsemi.c","lock"),
 ("drivers/net/ethernet/tehuti/tehuti.c","tx_lock"),
 ("drivers/net/ethernet/qlogic/qlcnic/qlcnic_io.c","rds_ring->lock"),
 ("drivers/net/ethernet/intel/e100.c","cb_lock"),
 ("drivers/net/ethernet/broadcom/genet/bcmgenet.c","ring->lock"),
 ("drivers/net/ethernet/realtek/8139too.c","rx_lock"),
 ("drivers/net/ethernet/via/via-rhine.c","lock"),
 ("drivers/atm/solos-pci.c","cli_queue_lock"),
 ("drivers/atm/solos-pci.c","tx_queue_lock"),
 ("drivers/net/ethernet/chelsio/cxgb4/sge.c","sendq.lock"),
 ("drivers/net/ethernet/netronome/nfp/nfp_net_common.c","r_vec->lock"),
 ("drivers/net/ethernet/silan/sc92031.c","lock"),
 ("drivers/net/ethernet/micrel/ksz884x.c","hwlock"),
]

PROCMARK = re.compile(r'\b(mutex_lock|copy_from_user|copy_to_user|kmalloc\(|kzalloc\(|dev_open|msleep|usleep|schedule_timeout|wait_event|mutex_unlock|request_firmware|queue_work|cancel_work|flush_work|napi_disable|netif_tx_disable|kthread_should_stop)\b')

for f, lock in CANDS:
    p=os.path.join(root,f)
    raw=open(p,errors="ignore").read()
    stripped=strip_comments_strings(raw)
    lines=stripped.split("\n")
    funcs=find_all_funcs(lines)
    lockesc = re.escape(lock)
    lockre = re.compile(r'spin_(?:try|un)?lock(?:_bh|_irq|_irqsave|_irqrestore)?\s*\(\s*&?\s*[^;]*' + lockesc)
    print(f"##### {f} :: {lock}")
    # map function containing each lock site
    names = sorted(funcs.items(), key=lambda kv: kv[1][0])
    sites=[]
    for i,l in enumerate(lines):
        m = re.search(r'\bspin_(try|un)?lock(_bh|_irq|_irqsave|_irqrestore)?\s*\(\s*&?\s*([A-Za-z0-9_\>\.\-\[\]\(\)-> ]+?)\s*[,)]', l)
        if m and re.search(lockesc, m.group(3)):
            kind = m.group(1) or ""
            flavor = m.group(2) or ""
            owner=None
            for name,(a,b) in names:
                if a<=i<=b: owner=name; break
            sites.append((i+1, kind, flavor, owner))
    for s in sites:
        print(f"  line {s[0]:5d} spin_{s[1]}lock{s[2]}  in {s[3]}")
