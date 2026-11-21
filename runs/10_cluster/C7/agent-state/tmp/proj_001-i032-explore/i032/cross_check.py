import re, os, sys

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03"

# (file, tasklet func line, func, lock base name)
cands = [
 ("drivers/atm/solos-pci.c","cli_queue_lock"),
 ("drivers/crypto/caam/jr.c","outlock"),
 ("drivers/dma/pl330.c","lock"),
 ("drivers/dma/timb_dma.c","lock"),
 ("drivers/dma/txx9dmac.c","lock"),
 ("drivers/dma/xilinx/zynqmp_dma.c","lock"),
 ("drivers/gpu/drm/vmwgfx/vmwgfx_cmdbuf.c","lock"),
 ("drivers/media/pci/ddbridge/ddbridge-core.c","lock"),
 ("drivers/media/pci/ttpci/av7110.c","debilock"),
 ("drivers/media/pci/ttpci/av7110.c","aout.lock"),
 ("drivers/media/pci/ttpci/av7110.c","avout.lock"),
 ("drivers/mmc/host/atmel-mci.c","lock"),
 ("drivers/mmc/host/dw_mmc.c","lock"),
 ("drivers/mmc/host/wbsd.c","lock"),
 ("drivers/net/ethernet/chelsio/cxgb/sge.c","lock"),
 ("drivers/net/ethernet/chelsio/cxgb3/sge.c","lock"),
 ("drivers/net/ethernet/chelsio/cxgb4/sge.c","sendq.lock"),
 ("drivers/net/ethernet/marvell/skge.c","phy_lock"),
 ("drivers/net/ethernet/silan/sc92031.c","lock"),
 ("drivers/net/ethernet/synopsys/dwc_eth_qos.c","tx_lock"),
 ("drivers/net/wireless/ath/ath5k/base.c","rxbuflock"),
 ("drivers/net/wireless/ath/ath5k/base.c","block"),
 ("drivers/rapidio/devices/tsi721_dma.c","lock"),
 ("drivers/tty/serial/atmel_serial.c","port->lock"),
 ("drivers/tty/serial/timbuart.c","port.lock"),
 ("drivers/usb/gadget/udc/amd5536udc.c","lock"),
 ("drivers/usb/host/fhci-sched.c","lock"),
 ("sound/core/timer.c","timer->lock"),
]

lock_usage = re.compile(r'(spin_lock\w*)\s*\(\s*&?\s*([^);]+?)\s*\)')
def norm(l):
    l = l.strip()
    # base member name
    parts = re.split(r'->|\.', l)
    return parts[-1].strip()

seen_files = {}
for relf, lockname in cands:
    path = os.path.join(ROOT, relf)
    with open(path, errors="replace") as fh:
        src = fh.read()
    lines = src.split("\n")
    print(f"\n##### {relf}  lock~{lockname}")
    for i, ln in enumerate(lines, 1):
        for m in lock_usage.finditer(ln):
            lk, obj = m.group(1), norm(m.group(2))
            if lockname in obj or obj in lockname or obj == lockname:
                print(f"  {i}: {lk}({m.group(2)}) | {ln.strip()[:100]}")
