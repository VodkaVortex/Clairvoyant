import json
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i037.json"
doc = {
  "version": 1, "intent_id": "i037", "branch": "if-alt-count", "snapshot": "s09", "phase": "post-primary-search",
  "candidates": [
    {"path": "drivers/hid/wacom_sys.c", "line": 2532, "status": "strong",
     "evidence": "wacom_wireless_work indexes usbdev->config->interface[1] and [2] (2532/2538); grep of wacom_sys.c+wacom_wac.c returns ZERO bNumInterfaces; only guard is usbdev != NULL."},
    {"path": "sound/usb/misc/ua101.c", "line": 990, "status": "safe",
     "evidence": "find_format_descriptor rejects num_altsetting != 2 (874), altsetting[0].bNumEndpoints != 0 (880), altsetting[1].bNumEndpoints != 1 (886) for BOTH interfaces before detect_usb_format's altsetting[1].endpoint[0] reads at 990/998."},
    {"path": "sound/usb/quirks.c", "line": 239, "status": "safe",
     "evidence": "create_auto_pcm_quirk checks iface->num_altsetting < 2 (237) then altsd->bNumEndpoints < 1 (243) before altsetting[1] use at 239/245; create_uaxx_quirk checks num_altsetting < 2 (417) before altsetting[1] at 419."},
    {"path": "sound/usb/mixer.c", "line": 3332, "status": "safe",
     "evidence": "UAC3 BADD loop NULL-checks usb_ifnum_to_if (3316-3318), rejects num < 2 (3322), rejects altsd->bNumEndpoints < 1 (3335) before altsetting[1].endpoint reads at 3332-3340."},
    {"path": "sound/usb/mixer_quirks.c", "line": 1947, "status": "safe",
     "evidence": "snd_microii_spdif_default_get NULL-checks usb_ifnum_to_if(chip->dev, 1), rejects num_altsetting < 2 (1945) and bNumEndpoints < 1 (1948) before altsetting[1] endpoint read at 1947/1950."},
    {"path": "sound/usb/midi.c", "line": 2120, "status": "safe",
     "evidence": "snd_usbmidi_switch_roland_altsetting returns unless intf->num_altsetting == 2 (2117) and intfd->bNumEndpoints == 2 (2125) before altsetting[1] endpoint reads at 2120/2126-2129."},
    {"path": "sound/usb/midi2.c", "line": 1095, "status": "safe",
     "evidence": "snd_usb_midi_v2_create falls back to MIDI 1.0 unless iface->num_altsetting >= 2 (1091) and hostif->desc.bNumEndpoints non-zero (1100) before altsetting[1] use at 1095."},
    {"path": "sound/usb/implicit.c", "line": 94, "status": "safe",
     "evidence": "add_implicit_fb_sync_ep: when alts==NULL it NULL-checks usb_ifnum_to_if and rejects iface->num_altsetting < 2 (92-93) before altsetting[1] at 94; when alts!=NULL the caller (add_generic_uac2_implicit_fb 119-127, snd_usb_get_host_interface + bNumEndpoints>=1) validated."},
    {"path": "drivers/usb/serial/sierra.c", "line": 138, "status": "safe",
     "evidence": "sierra_probe only usb_set_interface(udev, ifnum, 1) under num_altsetting == 2 (138-143); usb_set_interface validates altnum in usb core; no literal altsetting[N] indexing in file."},
    {"path": "drivers/usb/serial/qcserial.c", "line": 245, "status": "safe",
     "evidence": "qcprobe reads nintf = actconfig->desc.bNumInterfaces (245), QDL path uses usb_altnum_to_altsetting + NULL check (253-258) with bNumEndpoints==2 + bulk type checks (258-260); altsetting literal is core-validated via usb_set_interface (413-414)."},
    {"path": "drivers/net/usb/cdc_mbim.c", "line": 120, "status": "safe",
     "evidence": "cdc_mbim_set_ctrlalt switches only via usb_set_interface (120-122) which usbcore validates against parsed descriptors; bind path re-validates via cdc_ncm_comm_intf_is_mbim + cdc_ncm_bind_common."},
    {"path": "drivers/media/usb/uvc/uvc_video.c", "line": 2060, "status": "safe",
     "evidence": "UVC alt selection loops i < intf->num_altsetting (2020) and finds endpoints via uvc_find_endpoint bounded by alts->desc.bNumEndpoints (uvc_driver.c:46-56); usb_set_interface target altnum comes from the loop, not an assumed literal."}
  ],
  "notes": "Remaining: (a) wacom_sys trigger chain (wacom_wireless_irq -> schedule_work) + full deref evidence; (b) pcm.c altsetting sites; (c) usbvision absent (confirmed: no usbvision anywhere in s09); (d) ttusb-dec usb_set_interface(0,8), dvb-ttusb-budget(1,1), uss720(2), hso(1), ipheth, catc, cdc-phonet switch sites; (e) variable-index interface[] sweep under other dirs; (f) btusb altsetting[i] loop; (g) usbtest."
}
with open(path, "w") as f: json.dump(doc, f, indent=1)
print("ok")
