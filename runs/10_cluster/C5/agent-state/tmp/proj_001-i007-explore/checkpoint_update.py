import json
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C5/agent-state/checkpoints/i007.json"
d = json.load(open(p))
d["phase"] = "scan_complete"
d["scan"] = "1321 functions with user-fetches scanned; 140 functions with >=2 fetches sharing a user-pointer token; raw output in agent-state/tmp/proj_001-i007-explore/scan_out.txt"
d["candidates_pending"] = [
  "arch/mips/kernel/branch.c:__microMIPS_compute_return_epc pc16 x4",
  "arch/mips/kernel/traps.c:do_ri epc x2",
  "arch/nios2/kernel/misaligned.c:handle_unaligned_c addr+0/+1 x3",
  "drivers/net/wireless/cisco/airo.c:flashcard comp->data x3; airo_ioctl rq->ifr_data x2",
  "drivers/isdn/capi/kcapi.c:old_capi_manufacturer data x5",
  "drivers/isdn/hisax/isar.c:isar_load_firmware p x3",
  "drivers/isdn/hardware/avm/b1.c:b1_load_t4file dp x2; c4.c c4_load_t4file dp x2",
  "drivers/scsi/dpt_i2o.c:adpt_i2o_passthru user_msg x2",
  "drivers/scsi/megaraid.c:megadev_ioctl/mega_m_to_n/mega_n_to_m",
  "sound/pci/emu10k1/emufx.c:snd_emu10k1_fx8010_ioctl",
  "sound/isa/wavefront/wavefront_synth.c:wavefront_load_patch header->hdrptr x6",
  "kernel/seccomp.c:seccomp_prepare_user_filter user_filter x2",
  "fs/namei.c:getname_flags filename x2",
  "drivers/gpu/drm/radeon/radeon_cs.c:radeon_cs_ib_fill ib_chunk->user_ptr x2",
  "drivers/usb/misc/rio500.c:ioctl_rio rio_cmd.buffer x2",
  "ipc msg/sem/shm copy_*_from_user dispatchers",
  "net/core/ethtool.c:ethtool_set_features useraddr x2",
  "sound/synth/emux/soundfont.c:load_info data x2"
]
json.dump(d, open(p, 'w'), indent=1)
print("ok")
