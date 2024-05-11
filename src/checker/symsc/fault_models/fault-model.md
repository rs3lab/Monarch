# CephFS

- [Monitor: paxos and quorum](https://docs.ceph.com/en/latest/architecture/)

- OSD 集群和 monitor 集群之间相互传输节点状态信息，共同得出系统的总体工作状态，并形成一个记录 ceph 系统全局状态数据结构，即所谓的 cluster map。

-  monitor 并不主动轮询各个 OSD 的当前状态。正相反，OSD 需要向 monitor 上报状态信息。常见的上报有两种情况：
一是新的 OSD 被加入集群
二是某个 OSD 发现自身或者其他 OSD 发生异常。
在收到这些上报信息后，monitor 将更新 cluster map 信息并加以扩散，举例



- Acting set：支持一个 PG 的所有 osd daemon 的有序列表，其中第一个 OSD 是主 OSD，其余为次。acting set 是 CRUSH 算法分配的，但是不一定已经生效了。

- Up set：某一个 PG map 历史版本的 acting set。在大多数情况下，acting set 和 up set 是一致的，除非出现了 pg_temp。

- [blog](https://blog.wotiecity.com/docs/%E5%88%86%E5%B8%83%E5%BC%8F%E5%AD%98%E5%82%A8/01.%E5%88%86%E5%B8%83%E5%BC%8F%E5%AF%B9%E8%B1%A1%E5%AD%98%E5%82%A8ceph/01.%E5%88%86%E5%B8%83%E5%BC%8F%E5%AD%98%E5%82%A8ceph%E7%90%86%E8%AE%BA%E7%AF%87.html)

- [Cluster map propagation](https://gaodq.github.io/2017/06/05/ceph-rados-review/)


```bash
# Get the object of a file

# Get the information of an object
ceph osd map <pool> <object>

https://docs.ceph.com/en/latest/rados/configuration/mon-osd-interaction/

ceph daemon osd.1 config show | osd_heartbeat

mon_osd_down_out_interval = 30
mon_osd_report_timeout = 30
mon_osd_min_down_reporters = 1
osd_heartbeat_interval = 1
osd_heartbeat_grace = 10
osd_mon_heartbeat_interval = 2
osd_mon_report_interval = 5

# Read out the content of an object
rados -p cephfs_data get 10000000000.00000000 outfile

# Get the info of pools
ceph osd dump | grep 'replicated size'

# allows you to list all the rados objects that are stored in a specific placement group.
rados --pgid <pgid> ls 

# Get PGs per pool
ceph pg ls-by-pool <POOL>         
# 3.0 (version) 24 0 0  ... [...]

# Get mapping of a PG
ceph pg map 3.0
# osdmap e182 pg 3.0 (3.0) -> up [5,7,0] acting [5,7,0]

# list all osds as tree structure
ceph osd tree


# https://stackoverflow.com/questions/63456581/1-pg-undersized-health-warn-in-rook-ceph-on-single-node-clusterminikube/63472905#63472905
# As you mentioned in your question you should change your crush failure-domain-type to OSD that it means it will replicate your data between OSDs not hosts. By default it is host and when you have only one host it doesn't have any other hosts to replicate your data and so your pg will always be undersized.
# In the config file
osd crush chooseleaf type = 0
```

# CephFS fault model

- File data distribution

    - `ino`: Ceph allows pre-allocate inodes to each client, this procedure is not clear to me now. If we disable this setting `"mds_client_prealloc_inos = 0"` in the config file, then every time inodes are assigned in increasing order.
    
    - `ono`: file data can be splited into objects with fixed size (e.g., 4MB). Objects are indexed from 0 and this index becomes the object number, a.k.a, `ono`. Details see `ceph_calc_file_object_mapping()`.
    
    - `oid <= (ino, non)`: `= snprintf("%llx.%08llx", ino, ono)`

    - `pgid <- hash(oid) & mask`: Map an object id to one placement group like below (see `ceph_object_locator_to_pg()` for details):
        ```c
        // If no pool namespaces
        if (!oloc->pool_ns)
            // Normally use CEPH_STR_HASH_RJENKINS hashing algorithm 
            raw_pgid->seed = ceph_str_hash_linux(OID)
        else
            raw_pgid->seed = ceph_str_hash_linux(oloc->pool_ns->str + OID)
        // raw_pgid->pool????
        pgid = ("%llu.%x", raw_pgid->pool, raw_pgid->seed)
        // pi->pg_num???, pi->pg_num_mask???
        pgid->seed = ceph_stable_mod(raw_pgid->seed, pi->pg_num, pi->pg_num_mask);
        ```
    
    - `CRUSH(pgid) -> osds`: 

    `see ceph_pg_to_acting_primary()`

    https://zhuanlan.zhihu.com/p/123351674
    https://zhuanlan.zhihu.com/p/58888246
    
    ceph_pg_to_up_acting_osds
        CRUSH -> pg_to_raw_osds(osdmap, pi, raw_pgid, up, &pps);
            ceph_osds_init
            crush_find_rule
            do_crush
                crush_do_rule
        apply_upmap(osdmap, &pgid, up);
        raw_to_up_osds(osdmap, pi, up);
        apply_primary_affinity(osdmap, pi, pps, up);
        get_temp_osds(osdmap, pi, &pgid, acting);



	- Q4: how to build the osdmap? Is it permissive that map is not updated timely?
		OSD = 
- Metadata distribution
    Q1: MDS subtree partitioning MDS object to OSD


# GlusterFS

```python
def exec_success(dfs_config, fault_state, next_call):
    # condsider syscalls hang and there is timeout

    # Cephfs:
    # if monitor_alive && one mds && osd.No > mim_size

    # GlusterFS
    # 
```

- Replicated Glusterfs Volume
- Distributed Replicated Glusterfs Volume
- Dispersed Glusterfs Volume
- Distributed Dispersed Glusterfs Volume


RAID and erasure codes