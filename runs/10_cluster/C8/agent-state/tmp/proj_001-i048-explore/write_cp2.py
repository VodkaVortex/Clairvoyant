import json, os
cp_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/agent-state/checkpoints/i048.json"
data = {
  "version": 1, "intent_id": "i048", "branch": "fixed-epidx-rest", "snapshot": "s12",
  "phase": "candidate triage in progress",
  "invariant": "USB consumer code must validate altsetting[i].desc.bNumEndpoints > k before indexing endpoint[k].desc.* (or altsetting[0].desc.* at probe/bind/init) outside drivers/media/usb and drivers/net; interface/altsetting-count gaps belong to if-alt-count branch.",
  "queries_run": [
    "grep -rn '\\.endpoint\\[' and 'endpoint\\[' excluding drivers/media/usb, drivers/net, tools",
    "grep -rn '\\->endpoint\\[' excluding media-usb/net-usb/tools",
    "grep -rn 'get_endpoint(' sound/usb (helper.h macro wrapper)",
    "grep -rn 'bNumEndpoints' excluding media-usb/net-usb/gadget/tools",
    "comm endpoint-indexing files minus bNumEndpoints files -> zero-check candidate list",
    "grep usb_pipe_endpoint outside core/host/media/net"
  ],
  "classified_safe": [
    "drivers/media/rc: ati_remote (!=2), iguanair (<2), igorplugusb (!=1), streamzap (!=1), xbox_remote (==1), imon/imon_raw/redrat3/mceusb/ir_toy/ttusbir/si470x loops bounded by bNumEndpoints",
    "drivers/input: cm109/yealink/powermate (<1), ati_remote2 (<1), ims-pcu (<1 / !=2), aiptek (<1), acecad (!=1), hanwang (<1), kbtab (<1), pegasus_notetaker (<1), sur40 (<5), usbtouchscreen loop, xpad (!=2), iforce (<2), appletouch/synaptics_usb loops",
    "drivers/hid/usbhid: usbkbd (!=1), usbmouse (!=1)",
    "drivers/comedi: vmk80xx (!=2), ni_usb6501 (!=2), dt9812 (!=5) all with bounded loops",
    "drivers/mfd/dln2 (<2 before [0]/[1])",
    "drivers/usb/image: mdc800 (!=4), microtek (!=MTS_EP_TOTAL)",
    "drivers/usb/class: cdc-acm (<2 data / ==0 ctrl guards), cdc-wdm (!=1)",
    "drivers/usb/storage: onetouch (!=3), uas-detect.h loop bounded",
    "drivers/mmc: ushc (<1), vub300 loop",
    "drivers/i2c/i2c-diolan-u2c (<2), drivers/w1/ds2490 (!=NUM_EP-1)",
    "drivers/nfc: port100/pn533/nfcmrvl loops",
    "drivers/bluetooth: btusb loops, bfusb (<2)",
    "drivers/usb/serial: qcserial (==2), others loop-bounded",
    "sound/usb: stream.c parse guard bNumEndpoints<1; pcm.c <2 guard; mixer.c 3093/3523 guards; mixer_quirks 1660 guard; quirks.c 185 (<=ep_idx), 239, 354, 456, 481 guards; implicit.c 225 (!=2); midi.c 2264 (<3/5), 2079 (!=2); ua101 altsetting[0]!=0 and [1]!=1 guards before endpoint[0]"
  ],
  "reported": [
    "drivers/hid/hid-thrustmaster.c:163 thrustmaster_interrupts reads usbif->cur_altsetting->endpoint[1] (whole usb_host_endpoint struct copy semantics: &...->endpoint[1] address-of; then ep->desc.bEndpointAddress) with NO bNumEndpoints check anywhere in file; called from thrustmaster_probe at plug-in; endpoint[1] OOB read when bNumEndpoints<2. Need to confirm ep->desc read and probe path (done: probe calls thrustmaster_interrupts)."
  ],
  "unresolved": [
    "sound/usb/stream.c:582 parse_uac_endpoint_attributes reads alts->endpoint[0].extra/.extralen without bNumEndpoints check in that function; need to verify all callers guarantee >=1 endpoint (stream.c 1118 filter requires bNumEndpoints<1 skip for alts passed to snd_usb_get_audioformat_uac12/3 -> parse_uac_endpoint_attributes at 834/1063)"
  ],
  "notes": "Still to check: drivers/staging (r8188eu usb_intf.c, rtl8712), drivers/greybus/es2.c loop, drivers/most/most_usb.c loop, drivers/usb/misc (usbtest.c, idmouse, uss720, lvstest absent?), drivers/usb/atm speedtch loop, drivers/isdn/hfcsusb, drivers/usb/class/cdc-acm detail, sound/usb/implicit.c 128/157/168/186/196/220/252 (get_endpoint(alts,0) sites), fcp.c absent (f032 was s08). hid-thrustmaster is the strongest new candidate."
}
os.makedirs(os.path.dirname(cp_path), exist_ok=True)
tmp = cp_path + '.tmp'
with open(tmp,'w') as f: json.dump(data,f,indent=1)
os.replace(tmp,cp_path)
print("wrote")
