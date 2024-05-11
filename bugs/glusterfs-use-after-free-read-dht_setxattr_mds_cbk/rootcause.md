GlusterFS stores directories on every server in distribution configuration mode, with one server serving as the metadata server and the others as non-metadata servers. When a user issues metadata modification syscalls, the client first attempts to update the metadata server and then the non-metadata servers. If the non-metadata server is the last server added in the configuration steps and it becomes unreachable from the client during `removexattr`, then it will release the allocated heap memory which stores the context information. However, when it returns it try to use that memory and thus leads to a use-after-free.

```
    #0 0x7ffff769a7cf in __interceptor_free (/lib/x86_64-linux-gnu/libasan.so.5+0x10d7cf)
    #1 0x7ffff7355e19 in __gf_free /root/glusterfs/libglusterfs/src/mem-pool.c:383
    #2 0x7fffeedbbacd in dht_local_wipe /root/glusterfs/xlators/cluster/dht/src/dht-helper.c:805
    #3 0x7fffeedbbacd in dht_local_wipe /root/glusterfs/xlators/cluster/dht/src/dht-helper.c:713
    #4 0x7fffeeea7312 in dht_setxattr_non_mds_cbk /root/glusterfs/xlators/cluster/dht/src/dht-common.c:3898
    #5 0x7fffef034527 in client4_0_removexattr_cbk /root/glusterfs/xlators/protocol/client/src/client-rpc-fops_v2.c:
1061 [the non-metadata server is unreachable and thus directly call the callback and finally frees the memory.]
    #6 0x7fffeefe35ac in client_submit_request /root/glusterfs/xlators/protocol/client/src/client.c:288
    #7 0x7fffef01b198 in client4_0_removexattr /root/glusterfs/xlators/protocol/client/src/client-rpc-fops_v2.c:4481
    #8 0x7fffeefce5da in client_removexattr /root/glusterfs/xlators/protocol/client/src/client.c:1439
    #9 0x7fffeee38f1d in dht_setxattr_mds_cbk /root/glusterfs/xlators/cluster/dht/src/dht-common.c:3977 [try to request to other non-metadata servers.] [However, when it returns to here finally, it reused the freed memory.]
    #10 0x7fffef034527 in client4_0_removexattr_cbk /root/glusterfs/xlators/protocol/client/src/client-rpc-fops_v2.c
:1061 [the reply for the request to metadata server is back, and this callback is called]
    #11 0x7ffff721ffca in rpc_clnt_handle_reply /root/glusterfs/rpc/rpc-lib/src/rpc-clnt.c:723
    #12 0x7ffff721ffca in rpc_clnt_notify /root/glusterfs/rpc/rpc-lib/src/rpc-clnt.c:890
    #13 0x7ffff7219983 in rpc_transport_notify /root/glusterfs/rpc/rpc-lib/src/rpc-transport.c:521
    #14 0x7ffff018a5a6 in socket_event_poll_in_async /root/glusterfs/rpc/rpc-transport/socket/src/socket.c:2358
    #15 0x7ffff019ab39 in gf_async ../../../../libglusterfs/src/glusterfs/async.h:187
    #16 0x7ffff019ab39 in socket_event_poll_in /root/glusterfs/rpc/rpc-transport/socket/src/socket.c:2399
    #17 0x7ffff019ab39 in socket_event_handler /root/glusterfs/rpc/rpc-transport/socket/src/socket.c:2790
    #18 0x7ffff019ab39 in socket_event_handler /root/glusterfs/rpc/rpc-transport/socket/src/socket.c:2710
    #19 0x7ffff73fa6c0 in event_dispatch_epoll_handler /root/glusterfs/libglusterfs/src/event-epoll.c:631
    #20 0x7ffff73fa6c0 in event_dispatch_epoll_worker /root/glusterfs/libglusterfs/src/event-epoll.c:742
    #21 0x7ffff71bf608 in start_thread /build/glibc-YYA7BZ/glibc-2.31/nptl/pthread_create.c:477
```
