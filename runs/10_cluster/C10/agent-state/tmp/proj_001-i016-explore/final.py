import json
p='/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/agent-state/findings/i016.json'
artifact={
 "version":1,
 "intent_id":"i016",
 "branch":"proc-config-write-unterminated",
 "execution_status":"complete",
 "snapshots_checked":["s04"],
 "findings":[
  {
   "snapshot":"s04",
   "path":"drivers/net/netdevsim/fib.c",
   "start":1378,
   "end":1385,
   "quote":"if (size > sizeof(buf))\n\t\treturn -EINVAL;\n\tif (copy_from_user(buf, user_buf, size))\n\t\treturn -EFAULT;\n\tif (sscanf(buf, \"%u %hu\", &nhid, &bucket_index) != 2)\n\t\treturn -EINVAL;",
   "confidence":"medium",
   "reason":"Untrusted source: the debugfs control file 'nexthop_bucket_activity' (drivers/net/netdevsim/fib.c:1537, debugfs_create_file) lets any user able to open it supply size bytes of arbitrary content. Violated invariant: copy_from_user copies exactly the attacker-chosen size (allowed up to sizeof(buf)==128) into the 128-byte stack array buf with NO NUL terminator written (no buf[size]='\\0', no zero-initialization), so the C-string invariant does not hold; size==128 fills the entire array with attacker bytes. Unsafe use: sscanf(buf, \"%u %hu\", ...) scans buf as a NUL-terminated C string, reading past buf into adjacent stack when the user supplies 128 non-NUL bytes (no whitespace digit terminator); each %u/%hu conversion also reads further input than size bytes via the unbounded token scan. Consequence: out-of-bounds stack read (info leak into later behavior/crash) - the same root cause as the seed (memdup_user of exact length then sscanf) with the allocation here being a stack array. Counterevidence checked: no terminator write anywhere between the copy and sscanf (verified full function lines 1364-1390); lbuf usage in dlm, acpi proc, aoe, toshiba, udelay, ntb_tool all explicitly NUL-terminate or cap size < sizeof(buf), unlike here. Not fully proven: actual KASAN reproduction was not run and the file requires the netdevsim module plus debugfs mount; sscanf %u stops at the first non-digit so the OOB read only manifests when all 128 bytes are digits (e.g. 128 '1's) or the scan passes the end without terminating - possible because no in-bounds NUL is guaranteed."
  }
 ],
 "candidates":[
  {"snapshot":"s04","path":"drivers/net/netdevsim/fib.c","line":1382,"status":"reported","reason":"copy_from_user(buf,user_buf,size<=128) into char buf[128] with no NUL terminator, then sscanf(buf,'%u %hu') at 1384 - unterminated stack buffer handed to C-string parser; reported as the primary finding."},
  {"snapshot":"s04","path":"drivers/s390/cio/cio_inject.c","line":98,"status":"reported","reason":"vmemdup_user(buf,lbuf) allocates exactly lbuf bytes (no +1 terminator), then sscanf(buffer,'%x %x %x %x %x %x %x',...) at line 102 scans the buffer as a C string; an all-hex-digit write of arbitrary length makes sscanf read past the allocation. debugfs-registered (cio_inject.c:166) so it is a close analogue of the seed under a debugfs, not proc, file; gated by cio_inject_enabled static key."},
  {"snapshot":"s04","path":"drivers/net/ethernet/intel/ice/ice_debugfs.c","line":174,"status":"unresolved","reason":"memdup_user(buf,count) with count<=8 (line 171) leaves cmd_buf unterminated; sscanf(cmd_buf,'%s',user_val[16]) at line 184 scans cmd_buf as C string past its 1..8 byte allocation unless a NUL is inside. Identical pattern at lines 260/264 (count<=4, user_val[8]), 335/339 (count<=2), 431/435 (count<=5). Small allocation sizes make OOB read short but kmalloc-8/16 slab adjacency still allows crossing into adjacent objects; kept unresolved because impact is tiny and ice has been observed fixing only other paths."},
  {"snapshot":"s04","path":"drivers/net/ethernet/brocade/bna/bnad_debugfs.c","line":315,"status":"unresolved","reason":"memdup_user(buf,nbytes) at 315/375 then sscanf(kern_buf,'%x:%x') at 319/379 - byte-for-byte the seed pattern in the Brocade bna driver (the direct sibling of scsi bfa). This is a strong variant of the seed mechanism but lives in debugfs (branch1 territory, covered by intent i014), kept here as unresolved rather than duplicated as a proc-branch finding."},
  {"snapshot":"s04","path":"drivers/net/ethernet/marvell/octeontx2/af/rvu_debugfs.c","line":1002,"status":"safe","reason":"memdup_user(buffer, count + 1) followed by explicit cmd_buf[count] = '\\0' (line 1008) - terminator slot allocated and written."},
  {"snapshot":"s04","path":"fs/btrfs/ioctl.c","line":1138,"status":"safe","reason":"btrfs_check_ioctl_vol_args_path (ioctl.c:230) enforces memchr(vol_args->name,0,sizeof(name)) != NULL before any strcmp/strchr on the name at 1138-1165 and 2795-2810."},
  {"snapshot":"s04","path":"security/smack/smackfs.c","line":2548,"status":"safe","reason":"smk_write_revoke_subj uses smk_parse_smack(data,count) which scans with explicit len bound and kstrndup (smack_access.c:444-468); no unbounded string consumer on the unterminated memdup_user buffer."},
  {"snapshot":"s04","path":"drivers/acpi/proc.c","line":101,"status":"safe","reason":"acpi_system_write_wakeup_device caps count at 4 into strbuf[5] and explicitly writes strbuf[count]='\\0' (line 103) before sscanf(strbuf,'%s',str)."},
  {"snapshot":"s04","path":"drivers/block/aoe/aoechr.c","line":101,"status":"safe","reason":"revalidate() rejects size>=sizeof(buf) (16) and pre-sets buf[sizeof buf - 1]='\\0' so the copied region is always NUL-terminated within bounds."},
  {"snapshot":"s04","path":"kernel/time/test_udelay.c","line":110,"status":"safe","reason":"udelay_test_write rejects count>=sizeof(lbuf) and writes lbuf[count]='\\0' after copy_from_user."},
  {"snapshot":"s04","path":"drivers/ntb/test/ntb_tool.c","line":934,"status":"safe","reason":"buf_size=min(size,sizeof(buf)-1) and buf[buf_size]='\\0' before sscanf."},
  {"snapshot":"s04","path":"fs/dlm/debug_fs.c","line":714,"status":"safe","reason":"table_write2 copies min(sizeof(buf)-1,count) into zero-initialized buf[256]={} and uses bounded %NNs width in sscanf; line 853 same pattern."},
  {"snapshot":"s04","path":"drivers/platform/x86/toshiba_acpi.c","line":1492,"status":"safe","reason":"lcd/video/fan/keys proc writes either cap len to sizeof(cmd)-1 and write cmd[len]='\\0', or use memdup_user_nul (video_proc_write at 1558)."},
  {"snapshot":"s04","path":"arch/powerpc/platforms/pseries/lparcfg.c","line":681,"status":"safe","reason":"kbuf[64] with count<=sizeof(kbuf) check (count==64 edge: kbuf[count-1] overwrites last byte with NUL, truncating one char but staying in bounds; no OOB)."},
  {"snapshot":"s04","path":"arch/powerpc/platforms/pseries/reconfig.c","line":373,"status":"safe","reason":"ofdt_write uses memdup_user_nul(buf,count)."},
  {"snapshot":"s04","path":"drivers/infiniband/hw/qib/qib_fs.c","line":333,"status":"safe","reason":"flash_write requires count == sizeof(struct qib_flash) and passes the raw buffer to qib_eeprom_write - binary consumption, no string parsing."},
  {"snapshot":"s04","path":"drivers/net/wireless/realtek/rtw89/debug.c","line":145,"status":"unresolved","reason":"rtw89 debugfs writes copy_from_user into a kmalloc'd buf of buf_size and then sscanf/simple_strtoul; allocation and terminator handling not fully audited in this session (only copy sites located); left for the debugfs-branch intent."},
  {"snapshot":"s04","path":"fs/proc/base.c","line":2775,"status":"unresolved","reason":"memdup_user(buf,count) in proc mem-write path; the surrounding parse_mem_rw logic was not fully audited for string consumption; likely binary use (mem_write) but not confirmed."}
 ],
 "limitations":[
  "The netdevsim fib.c finding is a hypothesis from source reading: no kernel build, KASAN run, or reproducer was executed (snapshot tree is read-only; analysis artifacts kept under $TMPDIR only).",
  "The proc-write file list (53 files with .proc_write) was scanned with a 10-line copy_from_user-to-string proximity window; string uses farther than 10 lines after the copy, or reached through helper functions, could be missed.",
  "212 memdup_user/vmemdup_user call sites were enumerated and only those with string functions within 12 lines were inspected; helpers that later re-parse the copied buffer (e.g. ioctl structs re-serialized) were not traced.",
  "configfs ->store_* callbacks and securityfs/tracefs control writers were only partially enumerated; the smackfs sample examined was safe, but the full configfs surface was not exhaustively audited.",
  "Candidates rtw89/debug.c copy_from_user sites (145,222,268,322,1000,1111) and fs/proc/base.c:2775 remain unresolved due to the finalize directive.",
  "The cio_inject.c and ice_debugfs.c candidates are debugfs-registered rather than procfs/configfs; they overlap branch1 (intent i014) and were recorded here only because they surfaced under the same usercopy-then-string invariant."
 ]
}
json.dump(artifact,open(p,'w'),indent=1)
print("artifact written")
