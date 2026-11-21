import re, os, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"

# targets: (file, function name holding the plain spin_lock, lock obj string)
targets = [
 ("drivers/net/wireless/ath/ath5k/base.c", "ath5k_tasklet_rx", "ah->rxbuflock"),
 ("drivers/net/wireless/ath/ath5k/base.c", "ath5k_tasklet_beacon", "ah->block"),
 ("drivers/net/ethernet/marvell/skge.c", "skge_extirq", "hw->phy_lock"),
 ("drivers/media/pci/ddbridge/ddbridge-core.c", "input_tasklet", "input->lock"),
 ("drivers/media/pci/ddbridge/ddbridge-core.c", "output_tasklet", "output->lock"),
 ("drivers/media/pci/ttpci/av7110.c", "debiirq", "av7110->debilock"),
 ("drivers/media/pci/ttpci/av7110.c", "gpioirq", "av7110->debilock"),
 ("sound/core/timer.c", "snd_timer_tasklet", "timer->lock"),
 ("drivers/atm/solos-pci.c", "solos_bh", "card->cli_queue_lock"),
 ("drivers/crypto/caam/jr.c", "caam_jr_dequeue", "jrp->outlock"),
 ("drivers/mmc/host/wbsd.c", "wbsd_tasklet_card", "host->lock"),
 ("drivers/mmc/host/atmel-mci.c", "atmci_tasklet_func", "host->lock"),
 ("drivers/mmc/host/dw_mmc.c", "dw_mci_tasklet_func", "host->lock"),
 ("drivers/net/ethernet/silan/sc92031.c", "sc92031_tasklet", "priv->lock"),
 ("drivers/net/ethernet/via/via-rhine.c", "rhine_napipoll", "rp->lock"),
 ("drivers/net/ethernet/natsemi/natsemi.c", "natsemi_poll", "np->lock"),
 ("drivers/net/ethernet/toshiba/tc35815.c", "tc35815_poll", "lp->rx_lock"),
 ("drivers/net/ethernet/realtek/8139too.c", "rtl8139_poll", "tp->rx_lock"),
 ("drivers/net/ethernet/freescale/ucc_geth.c", "ucc_geth_poll", "ugeth->lock"),
 ("drivers/net/fjes/fjes_main.c", "fjes_poll", "hw->rx_status_lock"),
 ("drivers/net/wan/fsl_ucc_hdlc.c", "ucc_hdlc_poll", "priv->lock"),
 ("drivers/net/xen-netfront.c", "xennet_poll", "queue->rx_lock"),
 ("drivers/usb/host/fhci-sched.c", "process_done_list", "fhci->lock"),
 ("drivers/usb/gadget/udc/amd5536udc.c", "udc_tasklet_disconnect", "dev->lock"),
 ("drivers/tty/serial/atmel_serial.c", "atmel_tasklet_rx_func", "port->lock"),
]

def find_body(src, name):
    pat = re.compile(r'\b' + re.escape(name) + r'\s*\([^;{]*?\)\s*\{', re.S)
    for m in pat.finditer(src):
        start = m.end(); depth = 1; i = start
        while i < len(src) and depth > 0:
            c = src[i]
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            i += 1
        line = src[:m.start()].count("\n") + 1
        return src[m.start():i], line
    return None, None

# find all lines within each target file where the plain spin_lock(<lock obj>) occurs, and report enclosing function
for relf, func, lockobj in targets:
    path = os.path.join(ROOT, relf)
    with open(path, errors="replace") as fh: src = fh.read()
    lines = src.split("\n")
    # build map of line -> enclosing function by scanning for definitions
    funcs = []  # (start, end, name)
    for m in re.finditer(r'^[A-Za-z_][A-Za-z0-9_ \*\t\n]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*?\)\s*\{', src, re.M | re.S):
        start = m.start()
        i = m.end(); depth = 1
        while i < len(src) and depth > 0:
            c = src[i]
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            i += 1
        funcs.append((start, i, m.group(1)))
    print(f"\n### {relf} lock={lockobj}")
    for i, ln in enumerate(lines):
        mm = re.search(r'spin_lock\s*\(\s*&?\s*' + re.escape(lockobj.split('.')[-1]) + r'\b', ln)
        if mm:
            pos = sum(len(x)+1 for x in lines[:i])
            owner = "?"
            for s, e, n in funcs:
                if s <= pos < e:
                    owner = n
                    break
            print(f"  line {i+1} in func={owner}: {ln.strip()[:90]}")
