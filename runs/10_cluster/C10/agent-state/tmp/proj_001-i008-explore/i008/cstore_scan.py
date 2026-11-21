import re, os, json

S02 = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s02"
files = """./drivers/acpi/acpi_configfs.c ./drivers/block/null_blk/main.c ./drivers/gpio/gpio-sim.c ./drivers/hwtracing/coresight/coresight-syscfg-configfs.c ./drivers/hwtracing/stm/policy.c ./drivers/hwtracing/stm/p_sys-t.c ./drivers/infiniband/core/cma_configfs.c ./drivers/infiniband/ulp/srpt/ib_srpt.c ./drivers/most/configfs.c ./drivers/net/netconsole.c ./drivers/nvme/target/configfs.c ./drivers/pci/endpoint/functions/pci-epf-ntb.c ./drivers/pci/endpoint/functions/pci-epf-vntb.c ./drivers/pci/endpoint/pci-ep-cfs.c ./drivers/scsi/elx/efct/efct_lio.c ./drivers/scsi/ibmvscsi_tgt/ibmvscsi_tgt.c ./drivers/scsi/qla2xxx/tcm_qla2xxx.c ./drivers/target/iscsi/iscsi_target_configfs.c ./drivers/target/iscsi/iscsi_target_stat.c ./drivers/target/loopback/tcm_loop.c ./drivers/target/sbp/sbp_target.c ./drivers/target/target_core_configfs.c ./drivers/target/target_core_fabric_configfs.c ./drivers/target/target_core_stat.c ./drivers/target/target_core_user.c ./drivers/target/tcm_fc/tfc_conf.c ./drivers/target/tcm_remote/tcm_remote.c ./drivers/usb/gadget/configfs.c ./drivers/usb/gadget/function/f_acm.c ./drivers/usb/gadget/function/f_fs.c ./drivers/usb/gadget/function/f_hid.c ./drivers/usb/gadget/function/f_loopback.c ./drivers/usb/gadget/function/f_mass_storage.c ./drivers/usb/gadget/function/f_midi2.c ./drivers/usb/gadget/function/f_midi.c ./drivers/usb/gadget/function/f_ncm.c ./drivers/usb/gadget/function/f_obex.c ./drivers/usb/gadget/function/f_phonet.c ./drivers/usb/gadget/function/f_printer.c ./drivers/usb/gadget/function/f_serial.c ./drivers/usb/gadget/function/f_sourcesink.c ./drivers/usb/gadget/function/f_tcm.c ./drivers/usb/gadget/function/f_uac1.c ./drivers/usb/gadget/function/f_uac1_legacy.c ./drivers/usb/gadget/function/f_uac2.c ./drivers/vhost/scsi.c ./drivers/virt/coco/tsm.c ./drivers/xen/xen-scsiback.c ./fs/dlm/config.c ./fs/ocfs2/cluster/heartbeat.c ./fs/ocfs2/cluster/nodemanager.c ./lib/fault-inject.c ./samples/configfs/configfs_sample.c""".split()

COPY = re.compile(r'(copy_from_user|memdup_user|memcpy\s*\()')
STRINGOPS = re.compile(r'\b(sscanf|simple_strtoul|simple_strtol|simple_strtoll|simple_strtoull|strcmp|strncmp|strlen|strnlen|strchr|strscpy|strcpy|strstr|strsep|strim|strstrip)\s*\(')

# find all _store functions and check for own-copy + string ops
found = []
for f in files:
    p = os.path.join(S02, f.lstrip('./'))
    src = open(p, errors='replace').read()
    # find function bodies named *_store
    for m in re.finditer(r'^\s*(?:static\s+)?(?:ssize_t|ssize_t)\s+(\w*_store)\s*\(\s*struct config_item', src, re.M):
        fn = m.group(1)
        i = src.find('{', m.start())
        depth = 0; end = i
        for j in range(i, len(src)):
            if src[j] == '{': depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0: end = j; break
        body = src[i:end]
        has_copy = bool(COPY.search(body))
        strops = set(x.group(1) for x in STRINGOPS.finditer(body))
        if strops:
            found.append((f, fn, src[:m.start()].count('\n')+1, sorted(strops), has_copy))
print("configfs _store functions using string ops:", len(found))
for f, fn, ln, ops, cp in found:
    print(f"{f}:{ln} {fn} strops={ops} own-copy={cp}")
