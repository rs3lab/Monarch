# Bug Summary

An assertion in the Lustre client is triggered by the following calls, which leads to a kernel crash then.

```c
r0 = open(&(0x7f0000000080)='./file1\x00', 0x2c2c2, 0x0)
write$binfmt_script(r0, &(0x7f0000000200)={'#! ', './file1', [], 0xa, "a very long array"}, 0xe0b)

// Strace
// open("./file1", O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_DIRECT|O_LARGEFILE|O_NOFOLLOW, 000) = 3
// write(3, "#! ./file1\n}!F\270\v\21k;{\310T+z\311-\311@:\312\27S"..., 3595
```

# Configuration
Three server nodes and one client. Kernel version: Ubuntu-5.4.0-90.101

```bash
# MGS
mkfs.lustre --fsname=lustre --mgs /dev/vda
mount -t lustre /dev/vda /root/lustre-server

# MDS
mkfs.lustre --fsname=lustre --index=0 --mgsnode=$start_ip@tcp0 --mdt /dev/vda
mount -t lustre /dev/vda /root/lustre-server

# OSS
mkfs.lustre --ost --fsname=lustre --index=1 --reformat --mgsnode=$start_ip@tcp0 /dev/vda
mount -t lustre /dev/vda /root/lustre-server

# Client
mount -t lustre $start_ip@tcp0:/lustre /root/lustre-client
```

# Trace

```bash
root@dfs-fuzzing:~# [  154.265547] LustreError: 298:0:(osc_request.c:1819:osc_brw_prep_request()) ASSERTION( page_count == 1 || (ergo(i == 0, poff + pg->count == PAGE_SIZE) && ergo(i > 0 && i < page_count - 1, poff == 0 && pg->count == PAGE_SIZE) && ergo(i == page_count - 1, poff == 0)) ) failed: i: 0/2 pg: 000000005a02f487 off: 0, count: 3595
[  154.268801] LustreError: 298:0:(osc_request.c:1819:osc_brw_prep_request()) LBUG
[  154.269714] Kernel panic - not syncing: LBUG
[  154.270224] CPU: 3 PID: 298 Comm: ptlrpcd_00_00 Tainted: G           O      5.4.148+ #7
[  154.271135] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[  154.272152] Call Trace:
[  154.272455]  dump_stack+0x50/0x63
[  154.272875]  panic+0xfb/0x2bc
[  154.273235]  ? ret_from_fork+0x1f/0x40
[  154.273686]  ? lbug_with_loc.cold+0x1b/0x2c [libcfs]
[  154.274264]  lbug_with_loc.cold+0x2c/0x2c [libcfs]
[  154.274820]  ? libcfs_debug_dumplog+0x170/0x170 [libcfs]
[  154.275445]  osc_brw_prep_request+0x5214/0x6d20 [osc]
[  154.276075]  ? obdo_from_inode+0x526/0x870 [obdclass]
[  154.276677]  ? obdo_set_parent_fid+0x14/0x210 [obdclass]
[  154.277294]  ? osc_release_bounce_pages+0x11b0/0x11b0 [osc]
[  154.277934]  ? osc_req_attr_set+0xfdb/0x1d20 [osc]
[  154.278491]  ? lovsub_req_attr_set+0x554/0x910 [lov]
[  154.279136]  ? osc_attr_update+0x500/0x500 [osc]
[  154.279691]  ? cl_req_attr_set+0x24f/0x490 [obdclass]
[  154.280285]  osc_build_rpc+0x1487/0x3770 [osc]
[  154.280799]  ? osc_grant_work_handler+0x410/0x410 [osc]
[  154.281284]  osc_io_unplug0+0x2f0d/0x5110 [osc]
[  154.281655]  ? save_stack+0x4c/0x80
[  154.281979]  ? save_stack+0x1b/0x80
[  154.282283]  ? osc_extent_finish+0x2f20/0x2f20 [osc]
[  154.282695]  ? ptlrpc_unregister_bulk+0xbd0/0x17f0 [ptlrpc]
[  154.283166]  ? __switch_to_asm+0x40/0x70
[  154.283531]  ? __switch_to_asm+0x34/0x70
[  154.283888]  ? __switch_to_asm+0x40/0x70
[  154.284237]  ? ptlrpc_register_bulk+0x1c50/0x1c50 [ptlrpc]
[  154.284738]  ? __switch_to_asm+0x40/0x70
[  154.285064]  ? __switch_to_asm+0x34/0x70
[  154.285392]  ? __switch_to_asm+0x40/0x70
[  154.285735]  ? __switch_to_asm+0x34/0x70
[  154.286077]  brw_queue_work+0xbe/0x220 [osc]
[  154.286456]  ? osc_update_grant.isra.0.part.0+0x200/0x200 [osc]
[  154.287007]  work_interpreter+0xb3/0x340 [ptlrpc]
[  154.287446]  ? ptlrpcd_add_work_req+0x2f0/0x2f0 [ptlrpc]
[  154.287904]  ptlrpc_check_set+0x1244/0x7a90 [ptlrpc]
[  154.288356]  ? after_reply+0x3240/0x3240 [ptlrpc]
[  154.288883]  ? schedule+0x39/0xa0
[  154.289256]  ? schedule_timeout+0x209/0x320
[  154.289725]  ? __ptlrpc_req_finished+0x10af/0x1670 [ptlrpc]
[  154.290366]  ? kmem_cache_free+0x84/0x2a0
[  154.290839]  ? lu_context_refill+0x66/0xa0 [obdclass]
[  154.291430]  ptlrpcd+0x1296/0x23c0 [ptlrpc]
[  154.291919]  ? __switch_to_asm+0x40/0x70
[  154.292373]  ? __switch_to_asm+0x34/0x70
[  154.292844]  ? ptlrpcd_ctl_init+0x3e0/0x3e0 [ptlrpc]
[  154.293414]  ? __switch_to_asm+0x34/0x70
[  154.293865]  ? do_wait_intr_irq+0x80/0x80
[  154.294342]  ? __switch_to_asm+0x34/0x70
[  154.294780]  ? __switch_to_asm+0x40/0x70
[  154.295223]  ? __switch_to_asm+0x34/0x70
[  154.295663]  ? __switch_to_asm+0x40/0x70
[  154.296108]  ? __switch_to_asm+0x34/0x70
[  154.296566]  ? __switch_to_asm+0x40/0x70
[  154.297015]  ? __switch_to_asm+0x34/0x70
[  154.297463]  ? __switch_to_asm+0x40/0x70
[  154.297905]  ? __switch_to_asm+0x34/0x70
[  154.298351]  kthread+0xfb/0x130
[  154.298722]  ? ptlrpcd_ctl_init+0x3e0/0x3e0 [ptlrpc]
[  154.299282]  ? kthread_park+0x90/0x90
[  154.299703]  ret_from_fork+0x1f/0x40
[  154.300279] Kernel Offset: 0xa400000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[  154.301513] ---[ end Kernel panic - not syncing: LBUG ]---

```

# Bug Location

```c
static int
osc_brw_prep_request(int cmd, struct client_obd *cli, struct obdo *oa,
                     u32 page_count, struct brw_page **pga,
                     struct ptlrpc_request **reqp, int resend)


		LASSERT(page_count > 0);
        pg_prev = pga[0];
        for (requested_nob = i = 0; i < page_count; i++, niobuf++) {
                struct brw_page *pg = pga[i];
                int poff = pg->off & ~PAGE_MASK;

                LASSERT(pg->count > 0);
                /* make sure there is no gap in the middle of page array */
                LASSERTF(page_count == 1 ||
                         (ergo(i == 0, poff + pg->count == PAGE_SIZE) &&
                          ergo(i > 0 && i < page_count - 1,
                               poff == 0 && pg->count == PAGE_SIZE)   &&
                          ergo(i == page_count - 1, poff == 0)),
                         "i: %d/%d pg: %p off: %llu, count: %u\n",
                         i, page_count, pg, pg->off, pg->count);
	...
}
```

