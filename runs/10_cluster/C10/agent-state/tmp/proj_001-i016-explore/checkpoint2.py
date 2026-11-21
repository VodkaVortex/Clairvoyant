import json
p='/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/agent-state/checkpoints/i016.json'
d={"version":1,"intent_id":"i016","branch":"proc-config-write-unterminated","status":"in_progress","snapshot":"s04",
"step":"triaged memdup_user+string and copy_from_user+sscanf candidates",
"candidates":[
 {"path":"drivers/scsi/bfa/bfad_debugfs.c","line":253,"status":"candidate","note":"seed pattern itself: memdup_user(buf,nbytes)+sscanf, debugfs (belongs to branch1)"},
 {"path":"drivers/net/ethernet/brocade/bna/bnad_debugfs.c","line":315,"status":"candidate","note":"memdup_user(buf,nbytes)+sscanf regrd, debugfs (branch1 analogue)"},
 {"path":"drivers/net/ethernet/brocade/bna/bnad_debugfs.c","line":375,"status":"candidate","note":"memdup_user(buf,nbytes)+sscanf regwr, debugfs"},
 {"path":"drivers/net/ethernet/intel/ice/ice_debugfs.c","line":174,"status":"candidate","note":"memdup_user(buf,count<=8)+sscanf(cmd_buf,'%s',user_val[16]) - writes %s of unbounded token into 16-byte user_val; count<=8 limits source len to 8 so user_val OK; but sscanf on non-NUL-terminated cmd_buf can read past allocation"},
 {"path":"drivers/net/ethernet/intel/ice/ice_debugfs.c","line":260,"status":"candidate","note":"count<=4, sscanf(cmd_buf,'%s',user_val[8])"},
 {"path":"drivers/net/ethernet/intel/ice/ice_debugfs.c","line":335,"status":"candidate","note":"count<=2"},
 {"path":"drivers/net/ethernet/intel/ice/ice_debugfs.c","line":431,"status":"rejected","note":"data write: only checks non-empty, no string use"},
 {"path":"drivers/net/ethernet/marvell/octeontx2/af/rvu_debugfs.c","line":1002,"status":"safe","note":"memdup_user(buffer, count+1) + cmd_buf[count]='\\0' explicit terminator"},
 {"path":"drivers/s390/cio/cio_inject.c","line":98,"status":"candidate","note":"vmemdup_user(buf,lbuf)+sscanf 7 hex fields; debugfs registered"},
 {"path":"fs/btrfs/ioctl.c","line":1138,"status":"safe","note":"btrfs_check_ioctl_vol_args_path memchr NUL check"},
 {"path":"fs/btrfs/ioctl.c","line":2795,"status":"safe","note":"same memchr NUL check"},
 {"path":"security/smack/smackfs.c","line":2548,"status":"safe","note":"smk_parse_smack uses len-bounded scan + kstrndup"},
 {"path":"drivers/acpi/proc.c","line":101,"status":"safe","note":"strbuf[5], count capped at 4, strbuf[count]='\\0' explicit terminator"},
 {"path":"drivers/block/aoe/aoechr.c","line":101,"status":"safe","note":"buf[16], size<16 enforced, buf[15]='\\0' pre-set, sscanf bounded"},
 {"path":"drivers/net/netdevsim/fib.c","line":1382,"status":"candidate","note":"copy_from_user(buf,user_buf,size<=128) into char buf[128] NO NUL terminator, then sscanf(buf,'%u %hu') - unbounded scan if user fills 128 bytes without NUL"}
]}
json.dump(d,open(p,'w'),indent=1)
print("ok")
