# 1. Kernel compilation
```bash
make -j`nproc` CC="/home/tlyu/dfs-fuzzing/dfs-fuzzing/bin/dfs-gcc 2 fs/ceph net/ceph"
```

# 2. Software download and compilation

```bash
#Copy dfs-usp-gcc and dfs-usp-g++ to VM
mkdir /root/dfs-fuzzing
scp user@ip:$BIN/dfs-usp-g* /root/dfs-fuzzing

#Already donw in create-image
git clone --recursive https://github.com/ceph/ceph.git
cd ceph
git submodule update --force --init --recursive
git checkout v15.2.1

#we must meet the network problems when git clone, download in host and scp to VMs.
./install-deps.sh
#Workaround for src/tcmalloc.cc:332] Attempt to free invalid pointer
#apt-get remove libtcmalloc-minimal4

export CC="/root/monarch/dfs-usp-gcc ucov 21 src/lua src/pybind src/lua boost src/arrow src/blkin src/c-ares src/dmclock src/fmt src/googletest src/isa-l src/libkmip src/rapidjson src/rocksdb src/s3select src/seastar src/spawn src/spdk src/utf8proc src/xxHash src/zstd -pthread -fsanitize=address"
export CXX="/root/monarch/dfs-usp-g++ ucov 21 src/lua src/pybind src/lua boost src/arrow src/blkin src/c-ares src/dmclock src/fmt src/googletest src/isa-l src/libkmip src/rapidjson src/rocksdb src/s3select src/seastar src/spawn src/spdk src/utf8proc src/xxHash src/zstd -pthread -fsanitize=address"
export CFLAGS="-L/root/monarch -lucov"
export CXXFLAGS="-L/root/monarch -lucov"
export LDFLAGS="-L/root/monarch -lucov"

#-DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -CMAKE_INSTALL_LIBEXECDIR=/usr/lib -CMAKE_INSTALL_SYSCONFDIR=/etc
#Sanitizer options: -DWITH_ASAN=ON -DWITH_ASAN_LEAK=ON -DWITH_TSAN=ON -DWITH_UBSAN=ON
./do_cmake.sh -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DWITH_TESTS=OFF -DWITH_RADOSGW=OFF -DWITH_RBD=OFF -DWITH_MGR_DASHBOARD_FRONTEND=OFF -DWITH_KRBD=OFF -DALLOCATOR=libc
cd build
make -j`nproc`
make install
```

# 3. Enviroment configuration

```bash
cp /root/ceph/build/systemd/* /etc/systemd/system/
cp /root/ceph/systemd/ceph-volume* /etc/systemd/system/

#change "/usr/lib/ceph/ceph-osd-prestart.sh" -> "/usr/libexec/ceph/ceph-osd-prestart.sh" at /etc/systemd/system/ceph-osd\@.service
sed -i 's/\/usr\/lib\/ceph\/ceph-osd-prestart.sh/\/usr\/libexec\/ceph\/ceph-osd-prestart.sh/' /etc/systemd/system/ceph-osd\@.service

#Redirect output and error to a file
sed -i 's/^ExecStart=.*$/& \nStandardOutput=append:\/logdir\/daemon-log\nStandardError=append:\/logdir\/daemon-log/' /etc/systemd/system/ceph-*

#Set ASAN_OPTIONS
sed -i 's/^\[Service\]/\[Service\]\nEnvironment="ASAN_OPTIONS=log_path=\/logdir\/daemon-log:detect_leaks=0"/g' /etc/systemd/system/ceph-*

#No daemon restart, no limit on restart frequency
#/etc/systemd/system/*.service
#/etc/systemd/system/ceph-mds\@.service
sed -i 's/^StartLimitBurst=.*$/StartLimitBurst=5/g' /etc/systemd/system/ceph-*.service
sed -i 's/^Restart=.*$/Restart=no/g' /etc/systemd/system/ceph-*.service
sed -i 's/^StartLimitInterval.*$/StartLimitInterval=0/g' /etc/systemd/system/ceph-*.service

#Set ASAN log file
export ASAN_OPTIONS="log_path=/logdir/daemon-log:detect_leak=0" >> /etc/environment

#Stupid ceph configuration file
sed -i 's/\/usr\/sbin\/ceph-volume-systemd/\/usr\/bin\/ceph-volume-systemd/' /etc/systemd/system/ceph-volume\@.service

#reload system unit files
systemctl daemon-reload

#Allow ssh or scp with password
sed -i 's/.*PermitRootLogin.*/\PermitRootLogin yes/' /etc/ssh/sshd_config
systemctl restart ssh

#change root passwd in order to using scp between nodes
echo "root:123456" | chpasswd

apt-get install lvm2 sshpass

echo "kernel.randomize_va_space=0" >> /etc/sysctl.conf
sysctl -p
```

# 4. Scripts for CephFS setup

- Refer to [ceph-start.sh](./ceph-start.sh)

# 5. Operations

- **Remove an OSD and re-create**

  Show OSD list: `ceph osd tree`, Here we show the rest commands using  OSD named `osd.0`

  ```bash
  ceph osd down osd.0
  ceph osd out osd.0
  ceph osd rm osd.0
  ceph osd crush rm osd.0
  ceph auth del osd.0
  ceph-volume lvm create --data /dev/vda
  ```

- **1 monitors have not enabled msgr2**

  ```bash
  ceph mon enable-msgr2
  ```

- **Remove a MDS**

  ```bash
  systemctl stop ceph-mds@node1
  rm -rf /var/lib/ceph/mds/ceph-node1
  #Otherwise, you will meet this error: Error EEXIST: entity mds.node1 exists but key does not match
  ceph auth del mds.node1
  ```

- **Remove a CephFS**

  ```
  ceph fs set <fs_name> joinable false
  ceph mds fail <fs_name>
  ceph fs rm <fs_name> --yes-i-really-mean-it
  ```

- **Allow root user for ssh login**

  ```bash
  #Add the following line to /etc/ssh/sshd_config
  PermitRootLogin yes
  ssh-copy-id root@192.168.0.1
  ```

- **Othe operations**

  ```bash
    # Get PGs (pgid) per pool
    ceph pg ls-by-pool <POOL>         
    # 3.0 (version) 24 0 0  ... [...]

    # Get mapping of a PG
    ceph pg map 3.0
    # osdmap e182 pg 3.0 (3.0) -> up [5,7,0] acting [5,7,0]

    # allows you to list all the rados objects
    # that are stored in a specific placement group.
    rados --pgid <pgid> ls 

    # Get the information of an object
    ceph osd map <pool> <object>

    # Read out the content of an object
    rados -p cephfs_data get 10000000000.00000000 outfile

    # Given a file, covert its inode number to hex,
    # and then padding with .00000000, then its the object of the file data.

    # Show the config of osd
    ceph daemon osd.1 config show | osd_heartbeat

    # Get the info of pools
    ceph osd dump | grep 'replicated size'

    # list all osds as tree structure
    ceph osd tree

    # Dump raw osdmap and crushmap
    ceph osd getmap > osdmap.txt
    ceph osd getcrushmap -o crushmap.txt

    # Decode and encode raw crushmap
     crushtool -d crushmap.txt -o decrushmap.txt
     crushtool -c decrushmap.txt -o crushmap-v2.txt
    
    # Import crushmap to an osdmap
    osdmaptool --import-crush crushmap-v2.txt osdmap-v2.txt

    # Do PG->OSD mapping
    osdmaptool --test-map-pg 4.1c osdmap.txt

    # Change the osd state and then do the PG->OSD mapping
    osdmaptool --mark-out 2 --test-map-pg 1.1c osdmap.txt
    # osdmaptool: osdmap file 'osdmap.txt'
    # marking OSD@2 as out
    # parsed '1.1c' -> 1.1c
    # 1.1c raw ([], p-1) up ([], p-1) acting ([], p-1)
    osdmaptool --mark-up-in --test-map-pg 1.1c osdmap.txt
    # osdmaptool: osdmap file 'osdmap.txt'
    # marking all OSDs up and in
    # parsed '1.1c' -> 1.1c
    # 1.1c raw ([2,1,3,0], p2) up ([2,1,3,0], p2) acting ([2,1,3,0], p2)
  ```

# 6. Techniques

- [Ceph: A Scalable, High-Performance Distributed File System](https://www3.nd.edu/~dthain/courses/cse40771/spring2007/papers/ceph.pdf)
- [File Systems Unfit as Distributed Storage Backends: Lessons from 10 Years of Ceph Evolution](https://www.pdl.cmu.edu/PDL-FTP/Storage/ceph-exp-sosp19.pdf)
- **CRUSH MAP** : determines how to store and retrieve data by computing storage locations.
- **Why need PG (Placement Groups)?** : https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/4/html/storage_strategies_guide/placement_groups_pgs: Tracking object placement on a per-object basis within a pool is computationally expensive at scale. To facilitate high performance at scale, Ceph subdivides a pool into placement groups, assigns each individual object to a placement group, and assigns the placement group to a primary OSD. If an OSD fails or the cluster re-balances, Ceph can move or replicate an entire placement group—i.e., all of the objects in the placement groups—without having to address each object individually. This allows a Ceph cluster to re-balance or recover efficiently. 
- [Ceph replication](https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/4/html/architecture_guide/the-core-ceph-components)
- [CephFS POSIX semantic, write atomicity](https://docs.ceph.com/en/reef/cephfs/posix/?highlight=atomicity#bottom-line)
    > In shared simultaneous writer situations, a write that crosses object boundaries is not necessarily atomic. This means that you could have writer A write “aa|aa” and writer B write “bb|bb” simultaneously (where | is the object boundary), and end up with “aa|bb” rather than the proper “aa|aa” or “bb|bb”.

# 7. CephFS Fault Model

- A CephFS cluster usually consists of three kinds of nodes:
monitor, object storage deamon (OSD), and metadata server (MDS).
  - **Monitors**: maintain a global overview of the states of all nodes/daemons. Moreover, to provide the fault tolerance, multiple monitors and the consensus protocol [PAXOS](https://docs.ceph.com/en/latest/architecture/) are applied.
  Generally it requires odds number of nodes for successful voting.
  - **OSD**: an object in CephFS cluster is usually categoried into different placement groups, which act as the unit of replication.
  For one PG,
  the acting set is all the OSDs saving the replicas of that PG. 
  The up set is one of the historical version of the acting set.
  Generally, the cluster is configured with to parameters
  `osd pool default size = X`
  `osd pool default min size = Y`.
  The former is the number of replicas (including origional one), 
  while the latter is the minimal number of replicas for acknoledging a write operaiton.
  Note PG replication can be configured among OSDs or hosts (hosts with different hostnames) using `osd crush chooseleaf type = 0`. [See here](https://stackoverflow.com/questions/63456581/1-pg-undersized-health-warn-in-rook-ceph-on-single-node-clusterminikube/63472905#63472905)
  - **MDS**: Generally, there should be two MDS servers,
  one is active while another one is standby.
  But one is also enough for procedding.

- [State propgation among nodes](https://gaodq.github.io/2017/06/05/ceph-rados-review/)
  - Intead of monitors send heartbeats to the monitors to detect the liveness of the nodes/daemons, nodes/daemons send heartbeats to each other and monitors with fixed interval and report the down ones to monitors.
  [Arguments](https://docs.ceph.com/en/latest/rados/configuration/mon-osd-interaction/
)
    ```bash
      mon_osd_down_out_interval = 30
      mon_osd_report_timeout = 30
      mon_osd_min_down_reporters = 1
      osd_heartbeat_interval = 1
      osd_heartbeat_grace = 10
      osd_mon_heartbeat_interval = 2
      osd_mon_report_interval = 5
    ```

- [Ceph OSD weight and reweight](https://ivanzz1001.github.io/records/post/ceph/2018/09/07/ceph-weight-reweight)
