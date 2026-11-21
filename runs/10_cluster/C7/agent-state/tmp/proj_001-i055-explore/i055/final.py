import json, os
CK="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i055.json"
FA="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i055.json"

ckpt={"intent_id":"i055","branch":"hardirq-shared-lock","snapshot":"s11","status":"finalizing",
 "note":"Scan of 40945 files: 4011 irq-request sites, 2112 handlers resolved to in-file defs, 584 handler lock sites, 358 plain handler locks, 288 (file,lock) pairs with handler-plain + other-plain in same file. Deep-read top rows; 4 confirmed mixed-discipline pairs reported (korg1212, synclink_gt, ens1370, sbni); 8 next-tier rows left unresolved.",
 "candidates":[
  {"path":"sound/pci/korg1212/korg1212.c","line":1585,"status":"reported"},
  {"path":"drivers/tty/synclink_gt.c","line":1159,"status":"reported"},
  {"path":"sound/pci/ens1370.c","line":814,"status":"reported"},
  {"path":"drivers/net/wan/sbni.c","line":1185,"status":"reported"},
  {"path":"drivers/tty/serial/zs.c","line":717,"status":"unresolved"},
  {"path":"drivers/gpu/drm/rockchip/rockchip_drm_vop.c","line":1687,"status":"unresolved"},
  {"path":"drivers/usb/gadget/udc/mv_udc_core.c","line":2005,"status":"unresolved"},
  {"path":"drivers/net/ethernet/altera/altera_tse_main.c","line":531,"status":"unresolved"},
  {"path":"drivers/usb/gadget/udc/pch_udc.c","line":2779,"status":"unresolved"},
  {"path":"drivers/staging/emxx_udc/emxx_udc.c","line":2357,"status":"unresolved"},
  {"path":"drivers/tty/hvc/hvcs.c","line":531,"status":"unresolved"},
  {"path":"drivers/usb/gadget/udc/atmel_usba_udc.c","line":1715,"status":"unresolved"}],
 "updated":"2026-11-18"}
tmp=CK+".tmp"; open(tmp,"w").write(json.dumps(ckpt,indent=1)); os.replace(tmp,CK)

art={
 "version":1,"intent_id":"i055","branch":"hardirq-shared-lock","execution_status":"complete",
 "snapshots_checked":["s11"],
 "findings":[
  {"snapshot":"s11","path":"sound/pci/korg1212/korg1212.c","start":1576,"end":1613,
   "quote":"spin_lock(&korg1212->lock);",
   "confidence":"high",
   "reason":"Untrusted trigger: PCI card doorbell interrupt (attacker-influenced device events, e.g. playback/capture period completion). Hardirq side: snd_korg1212_interrupt registered via request_irq at korg1212.c:2231 takes spin_lock(&korg1212->lock) plainly at 1109 (drop/reacquire at 1167-1175, unlock 1183). Non-irq side: ALSA PCM trigger callback snd_korg1212_trigger (process context, IRQs enabled) takes the same lock plainly at 1585. Invariant violated: a lock also acquired in hardirq context must use spin_lock_irqsave/irq at every non-irq site; plain spin_lock only disables preemption. Unsafe use: same-CPU korg1212 PCI IRQ preempts the trigger holder and spins forever on the held lock the preempted context can never release - interrupt-context lockup, watchdog/RCU stall, PCM device wedged. Counterevidence checked: many sibling sites in the file do use irqrestore/irq variants (583/614/1552/1729/1795...), so this is a mixed-discipline defect, not a file-wide convention; no local_irq_disable wraps the trigger path.",
   "conclusion":"korg1212.c snd_korg1212_trigger takes korg1212->lock plainly (1585) while hardirq snd_korg1212_interrupt (request_irq:2231) takes it plainly (1109) - same-CPU IRQ self-deadlock; high-confidence interrupt-context DoS."},
  {"snapshot":"s11","path":"drivers/tty/synclink_gt.c","start":1151,"end":1178,
   "quote":"spin_lock(&info->lock);",
   "confidence":"high",
   "reason":"Untrusted trigger: synclink_gt adapter interrupt (line status/RX/TX events, driver-reachable by traffic on the serial link). Hardirq side: slgt_interrupt registered via request_irq at synclink_gt.c:3638 takes the same info->lock plainly at 2362 (and per-port locks at 2348/2381). Non-irq side: 32-bit compat ioctl path set_params32 (MGSL_IOCSPARAMS32, process context with IRQs enabled) takes info->lock plainly at 1159. Invariant violated: hardirq-shared lock needs irqsave at non-irq sites. Unsafe use: same-CPU adapter IRQ preempts the ioctl holder and spins forever - interrupt-context lockup/DoS. Counterevidence checked: every other info->lock site in the file uses spin_lock_irqsave (780/843/957/1106/1241/...), confirming the plain acquisition is the defect, not the convention.",
   "conclusion":"synclink_gt.c compat ioctl set_params32 holds info->lock with plain spin_lock (1159) while hardirq slgt_interrupt (request_irq:3638) takes the same lock plainly (2362) - same-CPU IRQ preemption spins forever; high-confidence interrupt-context DoS."},
  {"snapshot":"s11","path":"sound/pci/ens1370.c","start":808,"end":850,
   "quote":"spin_lock(&ensoniq->reg_lock);",
   "confidence":"high",
   "reason":"Untrusted trigger: Ensoniq 1370 PCI audio interrupt (DAC/ADC interrupt status bits, driven by audio stream progress). Hardirq side: snd_audiopci_interrupt registered via request_irq at ens1370.c:2067 takes ensoniq->reg_lock plainly at 2325. Non-irq side: PCM trigger callback takes reg_lock plainly at 814 (pause) and 840 (start/stop), and PCM pointer callbacks take it plainly at 990/1007/1024 - all process context with IRQs enabled. Invariant violated: hardirq-shared lock requires irqsave/irq at every non-irq acquisition. Unsafe use: same-CPU audio IRQ preempts a trigger/pointer holder and spins forever on reg_lock - interrupt-context lockup, sound card wedged. Counterevidence checked: many sibling sites use spin_lock_irq (871/919/959/1111/1322/2178/2195/2211), so the plain sites are a mixed-discipline defect; no local IRQ disable wraps these callbacks.",
   "conclusion":"ens1370.c PCM trigger (814/840) and pointer callbacks (990/1007/1024) take reg_lock plainly while hardirq snd_audiopci_interrupt (request_irq:2067) takes it plainly (2325) - same-CPU IRQ self-deadlock; high-confidence DoS."},
  {"snapshot":"s11","path":"drivers/net/wan/sbni.c","start":1183,"end":1190,
   "quote":"spin_lock( &nl->lock );",
   "confidence":"high",
   "reason":"Untrusted trigger: sbni (Granch SBNI12 leased-line WAN) adapter interrupt, reachable by inbound line traffic once the IRQ is attached at request_irq (sbni.c:1178). Non-irq side: card_open path takes nl->lock plainly at 1185 immediately after handler_attached (process context, open(), IRQs enabled); further plain process-context ioctl sites at 1223/1328/1392/1424. Hardirq side: sbni_interrupt takes nl->lock plainly at 509. Invariant violated: lock shared with a hardirq handler must disable interrupts at process-context sites. Unsafe use: same-CPU adapter IRQ preempts the open/ioctl holder and spins forever on nl->lock - interrupt-context lockup, netdev wedged. Counterevidence checked: no irqsave variant of nl->lock acquisition exists anywhere in sbni.c (only plain spin_lock at 451/475/509/511/543/1185/1223/1328/1392/1424), so the entire file shares the lock with hardirq without IRQ protection.",
   "conclusion":"sbni.c card_open/ioctl paths take nl->lock plainly (1185/1223/1328/1392/1424) while hardirq sbni_interrupt (request_irq:1178) takes it plainly (509) - same-CPU IRQ self-deadlock; high-confidence DoS."}],
 "candidates":[
  {"snapshot":"s11","path":"sound/pci/korg1212/korg1212.c","line":1585,"status":"reported",
   "reason":"Plain process-context PCM trigger acquisition of korg1212->lock (1585) against plain hardirq acquisition in snd_korg1212_interrupt (1109, request_irq:2231); both source lines verified verbatim.","conclusion":""},
  {"snapshot":"s11","path":"drivers/tty/synclink_gt.c","line":1159,"status":"reported",
   "reason":"Plain compat-ioctl acquisition of info->lock (1159) against plain hardirq acquisition in slgt_interrupt (2362, request_irq:3638); all other file sites use irqsave.","conclusion":""},
  {"snapshot":"s11","path":"sound/pci/ens1370.c","line":814,"status":"reported",
   "reason":"Plain PCM trigger/pointer acquisitions of reg_lock (814/840/990/1007/1024) against plain hardirq acquisition in snd_audiopci_interrupt (2325, request_irq:2067).","conclusion":""},
  {"snapshot":"s11","path":"drivers/net/wan/sbni.c","line":1185,"status":"reported",
   "reason":"Plain process-context acquisitions of nl->lock (1185 card_open; 1223/1328/1392/1424 ioctls) against plain hardirq acquisition in sbni_interrupt (509, request_irq:1178); no irqsave variant exists in the file.","conclusion":""},
  {"snapshot":"s11","path":"drivers/tty/serial/zs.c","line":717,"status":"unresolved",
   "reason":"zs_interrupt takes zlock plainly at 717 and 15 other plain zlock sites exist in the file (382-693 range); caller contexts not traced.","conclusion":"Follow up: classify each zs.c plain zlock site by caller context - an IRQ-enabled process-context holder against the plain ISR taker at 717 is a reportable hardirq lockup."},
  {"snapshot":"s11","path":"drivers/gpu/drm/rockchip/rockchip_drm_vop.c","line":1687,"status":"unresolved",
   "reason":"vop_isr takes irq_lock plainly at 1687 and 12 other plain sites exist in the file; enclosing functions and contexts not traced.","conclusion":"Follow up: classify rockchip_drm_vop.c plain irq_lock sites by context; any process-context holder (e.g. vop_crtc helpers) against the plain ISR taker at 1687 is reportable."},
  {"snapshot":"s11","path":"drivers/usb/gadget/udc/mv_udc_core.c","line":2005,"status":"unresolved",
   "reason":"mv_udc_irq takes udc->lock plainly at 2005 with 11 other plain sites in the file; caller contexts not traced.","conclusion":"Follow up: classify each plain spin_lock(&udc->lock) site in mv_udc_core.c by caller context against the plain hardirq taker at 2005."},
  {"snapshot":"s11","path":"drivers/net/ethernet/altera/altera_tse_main.c","line":531,"status":"unresolved",
   "reason":"altera_isr takes rxdma_irq_lock plainly at 531/538 with 10 other plain sites; contexts not traced.","conclusion":"Follow up: trace altera_tse_main.c plain rxdma_irq_lock sites (xmit/NAPI/open) against the plain hardirq takers at 531/538."},
  {"snapshot":"s11","path":"drivers/usb/gadget/udc/pch_udc.c","line":2779,"status":"unresolved",
   "reason":"pch_udc_isr takes udc->lock plainly at 2779 with 10 other plain sites; contexts not traced.","conclusion":"Follow up: classify pch_udc.c plain udc->lock sites by caller context; a process-context plain holder against the ISR taker at 2779 is reportable."},
  {"snapshot":"s11","path":"drivers/staging/emxx_udc/emxx_udc.c","line":2357,"status":"unresolved",
   "reason":"_nbu2ss_udc_irq (2357) and _nbu2ss_vbus_irq (2333) take udc->lock plainly with 8 other plain sites; contexts not traced.","conclusion":"Follow up: trace emxx_udc.c plain udc->lock sites to their callers; any process-context plain holder against the plain hardirq takers is reportable."},
  {"snapshot":"s11","path":"drivers/tty/hvc/hvcs.c","line":531,"status":"unresolved",
   "reason":"hvcs_handle_interrupt takes hvcsd->lock plainly at 531 with 8 other plain sites; contexts not traced.","conclusion":"Follow up: classify hvcs.c plain lock sites (open/write/ioctl vs softirq hvc callbacks) against the plain hardirq taker at 531."},
  {"snapshot":"s11","path":"drivers/usb/gadget/udc/atmel_usba_udc.c","line":1715,"status":"unresolved",
   "reason":"usba_udc_irq takes udc->lock plainly at 1715/1734/1756/1800 with 8 other plain sites; contexts not traced.","conclusion":"Follow up: classify atmel_usba_udc.c plain udc->lock sites by caller context against the plain hardirq takers at 1715-1800."}],
 "coverage_gaps":[
  "Cross-index resolved 2112 of 4011 irq-request sites to in-file handler definitions; handlers defined in other files, macro-declared, or registered via function pointers were never checked for lock usage.",
  "Lock correlation was textual on the lock-expression base name within the registering file only; locks shared across files (exported helpers) or spelled differently (&priv->lock vs &dev->lock aliases) could not be matched.",
  "request_threaded_irq registrations were not split into primary hardirq handler vs thread_fn; thread-context acquisitions of primary-handler-shared locks were not separately audited.",
  "The cross-table produced 288 (file,lock) pairs with handler-plain + other-plain acquisitions; only the top ~60 rows were triaged and only 12 candidates classified - remaining rows (ymfpci, net2280, r8a66597, exynos-iommu, atmel_serial, at91_udc, fm801, via82xx, sun6i-dma, thunderbolt/nhi, dwc2, goku, m66592, net2272, es1968, dbri, pmi, fec_mpc52xx, ravb, rtc-sh, imx, fotg210, fusb300, maestro3, cs46xx, trident, vpif, s5p-mfc, hpilo, rtsx_pcr, macb, defxx, ni_pcidio, several serial drivers) were not deeply read."],
 "limitations":[
  "Analysis is source-only; no compilation or runtime reproducer was built, so interrupt-context self-deadlock is a well-grounded hypothesis, not an exploit demonstration.",
  "Process-context classification of the four reported sites relies on their roles (ALSA PCM ops, tty compat ioctl, netdev open/ioctl) being invoked with hard IRQs enabled; explicit IRQ-disabled wrappers around those paths were not exhaustively ruled out beyond the sibling-site survey.",
  "Hardirq-side preemption assumes the IRQ is not threaded at runtime (no threaded handler passed at the audited request_irq sites) and can land on the same CPU as the holder, which is the normal case for non-threaded device IRQs."]}
tmp=FA+".tmp"; open(tmp,"w").write(json.dumps(art,indent=1)); os.replace(tmp,FA)
print("artifact written", os.path.getsize(FA))
