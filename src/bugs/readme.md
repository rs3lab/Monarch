# Bug Summary

| DFS  | Summary | Location | Type | Module | Fault | Consequence | Status |         Config         |
| :--: | :--------------: | --------------------------- | :---: | :---: | :--: | :--: | ---- | ---- |
| NFS  | [null-ptr-deref in nfs4_select_rw_stateid](./nfs-null-dereference-3ab8a45c6fc16de3b64f3dd9004b5fa0ae036426) | fs/nfs/nfs4state.c:1047 | ME | c |  | DoS | CVE-2022-24448 |  |
| NFS | [use-after-free READ in nfs_end_delegation_return](./nfs-use-after-free-8e1fd890d9956dcc2f0d7f12e2fd80a317341be8) | fs/nfs/delegation.c:547 | ME | c |  | Information leakage |  |  |
| NFS | [use-after-free READ in svc_tcp_listen_data_ready](./nfs-use-after-free-f7fd09092abc1bdf8040869d0ba9a402678ad72d) | net/sunrpc/svcsock.c:701 | ME | s |  | Information leakage |  |  |
| NFS | [wild-memory-access WRITE in xdr_expand_hole](./nfs-wild-memory-access-36dc22772d6fac6e93b39f16332ddf4f5a40bd38/) | net/sunrpc/xdr.c:1526 | ME | c |  | Privilege escalation |  |  |
| NFS | [use-after-free READ in nfs_inode_evict_delegation](./nfs-use-after-free-21c01b237d119d81cb82d8319cc29976525d1594) | fs/nfs/delegation.c:733 | ME | c |  | Information leakage |  |  |
| NFS | [use-after-free READ in nfs4_update_lock_stateid](./nfs-use-after-free-2d9c1b15ebeb552f6946422ef7c4cc7c7f367d1a) | fs/nfs/nfs4proc.c:1854 | ME | c |  | Information leakage |  |  |
| NFS | [use-after-free READ in nfs4_put_lock_state.part.0](./nfs-use-after-free-ff0704947b3e48fbd12aaf41e8bff465e7642866) | fs/nfs/nfs4state.c:939 | ME | c |  | Information leakage |  |  |
| NFS | [use-after-free READ in _nfs4_do_setlk](./nfs-use-after-free-d11f2be0ec17321d362338cae9e1726839301ee5) | fs/nfs/nfs4proc.c:7157 | ME | c |  | Information leakage |  |  |
| | | | | |
| GlusterFS | [cross-node consistency about open with O_CREAT\ and O_DIRECTORY](https://github.com/gluster/glusterfs/issues/3624) | - | CNI | s |  |  | Ack |  |
| GlusterFS | [Crash consistency about fsync](https://github.com/gluster/glusterfs/issues/3983) | - | PCI | s | Y | Data loss | Fixed | |
| GlusterFS | [client get stuck forever](https://github.com/gluster/glusterfs/issues/3936) | - | Hang |  |  | DoS |  |  |
| GlusterFS | [use-after-free READ in dht_setxattr_mds_cbk](https://github.com/gluster/glusterfs/issues/3732), [analysis](./glusterfs-use-after-free-read-dht_setxattr_mds_cbk) | xlators/cluster/dht/src/dht-common.c:3944 | ME | c | Y | Information leakage | CVE-2022-48340 | 2 1 distributed failure |
| GlusterFS | [heap-use-after-free READ in fuse_fd_inherit_directio](./glusterfs-use-after-free-818f935a171c7b0827d4ff3cc01a110e2981017e) | xlators/mount/fuse/src/fuse-bridge.c:1564 | ME | c |  | Information leakage |  |  |
| GlusterFS | [stack-buffer-overflow READ in notify](https://github.com/gluster/glusterfs/issues/3954) | xlators/mount/fuse/src/fuse-bridge.c:6538 | ME | c |  | Information leakage | CVE-2023-26253 |  |
| GlusterFS | [heap-use-after-free READ in dht_setxattr_mds_cbk](./glusterfs-use-after-free-dht-comment-3983-dht_setxattr_mds_cbk) | xlators/cluster/dht/src/dht-common.c:3983 | ME | c | Y | Information leakage |  | 3 1 distributed failure |
| GlusterFS | [heap-use-after-free READ in dht_xattrop_mds_cbk](./glusterfs-use-after-free-dht-common-4046-dht_xattrop_mds_cbk) | xlators/cluster/dht/src/dht-common.c:4046 | ME | c | Y | Information leakage |  | 3 1 distributed failure |
| GlusterFS | [heap-use-after-free READ in dht_xattrop_mds_cbk](./glusterfs-use-after-free-dht-common-4058-dht_xattrop_mds_cbk) | xlators/cluster/dht/src/dht-common.c:4058 | ME | c | Y | Information leakage |  | 3 1 distributed failure |
| GlusterFS | [heap-use-after-free READ in dht_dir_common_set_remove_xattr](./glusterfs-use-after-free-dht-common-5494-dht_dir_common_set_remove_xattr) | xlators/cluster/dht/src/dht-common.c:5494 | ME | c | Y | Information leakage |  | 3 1 distributed failure |
| GlusterFS | [heap-use-after-free READ in gf_print_trace](./glusterfs-use-after-free-common-utils-652-gf-print-trace) | libglusterfs/src/common-utils.c:652 | ME | c |  | Information leakage |  |  |
| GlusterFS | [heap-use-after-free READ in dht_rmdir_opendir_cbk](./glusterfs-use-after-free-dht-common-10612-dht-rmdir-opendir-cbk) | xlators/cluster/dht/src/dht-common.c:10612 | ME | c | Y | Information leakage |  | 3 1 distributed failure |
| GlusterFS | [heap-use-after-free READ in default_notify (report9)](./glusterfs-use-after-free-defaults.c-3386-default_notify) | libglusterfs/src/defaults.c:3386 | ME | s | Y | Information leakage |  | 3 1 rep/disp failure |
| GlusterFS | [stack-buffer-underflow READ in gfx_stat_from_iattx](./glusterfs-stack-underflow-glusterfs3.h-661-gfx_stat_from_iattx) | rpc/xdr/src/glusterfs3.h:661 | ME | s | Y | Information leakage |  | 3 1 rep/disp failure |
| GlusterFS | [use-after-free READ in inode_unref](./glusterfs-use-after-free-read-inode_unref) | libglusterfs/src/inode.c:621 | ME | s | Y | Information leakage | |  |
| GlusterFS | [use-after-free READ in afr_notify](./glusterfs-use-after-free-read-afr_notify) | xlators/cluster/afr/src/afr-common.c:6396 | ME | s | Y | Information leakage | |  |
| GlusterFS | [use-after-free READ in _gf_log](./glusterfs-use-after-free-read-_gf_log) | libglusterfs/src/logging.c:2026 | ME | s | Y | Information leakage | |  |
| GlusterFS | [use-after-free READ in afr_shd_index_healer](./glusterfs-use-after-free-read-afr_shd_index_healer/) | xlators/cluster/afr/src/afr-self-heald.c:1026 | ME | s | Y | Information leakage | |  |
| GlusterFS | [use-after-free WRITE in dht_rename_lookup_cbk](./glusterfs-use-after-free-write-dht_rename_lookup_cbk) | xlators/cluster/dht/src/dht-rename.c:1591 | ME | c |  | Privilege escalation | |  |
| | | | | |
| CephFS | [null-ptr-deref in unsafe_request_wait](./cephfs-null-dereference-8023a61267cc1885f21473fb8aa7e070fc9c3176) | fs/ceph/caps.c:2266 | ME | c |       | DoS | Fixed |  |
| CephFS | [use-after-free READ in have_mon_and_osd_map](./cephfs-use-after-free-ceph-open-session) , [Patch](https://patchwork.kernel.org/project/ceph-devel/patch/20200218033042.40047-1-xiubli@redhat.com/) | net/ceph/ceph_common.c:814 | ME | c |  | Information leakage | Fixed |  |
| CephFS | [use-after-free WRITE in ceph_fl_release_lock](./cephfs-use-after-free-ceph_fl_release_lock/) , [Patch](https://github.com/ceph/ceph-client/commit/8e1858710d9a71d88acd922f2e95d1eddb90eea0) | fs/ceph/locks.c:46 | ME | c |  | Privilege escalation | Fixed | |
| CephFS | [use-after-free WRITE in encode_cap_msg](./cephfs-use-after-free-encode_cap_msg), [reporting](https://tracker.ceph.com/issues/59259) | fs/ceph/caps.c:1271 | ME | c | | Privilege escalation | | |
| CephFS | [Inconsistent file mode](./cephfs-mode-inconsistency/), [reporting](https://tracker.ceph.com/issues/63906) | | Semantic bugs| | | |  | 1Mon, 2OSD, 3MDS, 2Clt |
| | | | | |
| Lustre | [null-ptr-deref in lov_iocontrol](./lustre-null-ptr-osc_request.c-3358-osc_iocontrol/report.md), [report](https://jira.whamcloud.com/browse/LU-16617) | lustre/osc/osc_request.c:3358 | ME | c |  | DoS | Fixed ||
| Lustre | [null-ptr-deref in lustre_set_wire_obdo](./lustre-null-ptr-deref-lustre_set_wire_obdo), [report](https://jira.whamcloud.com/browse/LU-16634) | lustre/obdclass/obdo.c:182 | ME | c |  | DoS | Fixed | |
| Lustre | [assertion in osc_brw_prep_request](./lustre-assertion-osc_request.c-1819-osc_brw_prep_request/report.md), [report](https://jira.whamcloud.com/browse/LU-16616) | lustre/osc/osc_request.c:1819 | LB | c |  | DoS | Fixed ||
| Lustre | [assertion in ll_direct_rw_pages](./lustre-assertion-ll_direct_rw_pages/) | lustre/llite/rw26.c:374 | LB | c |  | DoS |  | |
| Lustre | [assertion in osc_extent_make_ready](./lustre-assertion-osc_extent_make_ready/) | lustre/osc/osc_cache.c:1116 | LB | c |  | DoS |  | |
| Lustre | [assertion in osc_page_delete](./lustre-assertion-osc_page_delete/) | lustre/osc/osc_page.c:173 | LB | c |  | DoS |  | |
| Lustre | [assertion in osc_queue_async_io](./lustre-assertion-osc_queue_async_io/) | lustre/osc/osc_cache.c:2437 | LB | c |  | DoS |  | |
| Lustre | [assertion in ll_obd_statfs](./lustre-assertion-ll_obd_statfs) , [report](https://jira.whamcloud.com/browse/LU-16688) | lustre/llite/llite_lib.c:3394 | LB | c |  | DoS | Fixed | |
| | | | | |
| OrangeFS | [stack-buffer-overflow WRITE in dbpf_keyval_read_op_svc](./orangefs-stack-buffer-overflow-dbpf_keyval_read_op_svc/) | src/io/trove/trove-dbpf/dbpf-keyval.c: | ME | s |  | Privilege escalation |  | |
| OrangeFS | [use-after-free READ in mdb_txn_renew0](./orangefs-use-after-free-multiple/) | src/common/lmdb/mdb.c | ME | s | Y | Privilege escalation |  | |
| OrangeFS | [stack-buffer-underflow READ in PINT_encrypt_dirdata](./orangefs-stack-buffer-overflow-PINT_encrypt_dirdata) | src/common/misc/dist-dir-utils.c:293 | ME | c | Y | Privilege escalation | | |
| | | | | |
| BeeGFS | [crash consistency on fsync on file](https://groups.google.com/g/fhgfs-user/c/WkYEhjZe3z0) | - | PCI |  | Y | Data loss | | |
| BeeGFS | [crash consistency on fdatasync on dir entries](https://groups.google.com/g/fhgfs-user/c/WkYEhjZe3z0) | - | PCI |  | Y | Data loss | | |
<!---
| BeeGFS | [use-after-free READ in Atomic Atomic::read()](./beegfs-use-after-free-read-Atomic) | common/source/common/threading/Atomics.h:154 | ME | s | Y | Information leakage | | |
-->
