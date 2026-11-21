# Candidate evidence evaluation status (from deep reads):
# 1) cdc-phonet.c:369-378 - data_desc->endpoint[0..1] guarded by bNumEndpoints==2 -> SAFE
# 2) qmi_wwan.c:699 - info->control->cur_altsetting->endpoint[0] unguarded -> CANDIDATE (needs deeper)
# 3) lan78xx.c:4708 - endpoint[2] guarded by bNumEndpoints<3 check -> SAFE
# 4) sierra_net.c - numendpoints != 3 check -> SAFE
# 5) cdc_ether.c:305-308 - guarded by ==1 check -> SAFE
# 6) zd1211rw/ath9k - bNumEndpoints<2 guard -> SAFE
# 7) drivers/net/wwan - no USB drivers -> nothing
# qmi_wwan.c:699 deep-read conclusion:
#   qmi_wwan_bind (line 744) -> qmi_wwan_register_subdriver (line 690) reads
#   info->control->cur_altsetting->endpoint[0] with NO bNumEndpoints>0 check on
#   the control interface. info->control is either intf itself or an interface
#   resolved via cdc_union->bMasterInterface0 (usb_ifnum_to_if). For dynamic
#   FF/FF/FF matches (Quectel etc.), only bNumEndpoints==2 is rejected;
#   bNumEndpoints==0/1 passes and endpoint[0] is OOB (flex array len 0 ->
#   container_of NULL-ish deref). usb_cdc_wdm_register then dereferences
#   dev->status->desc in wdm_create (usb_endpoint_is_int_in(ep)).
# STRONG CANDIDATE for seed-mechanism variant.
