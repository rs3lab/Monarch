# 1. Software download and compilation

```bash
apt-get install make automake autoconf libtool flex bison pkg-config libssl-dev libxml2-dev python-dev-is-python3 libaio-dev libibverbs-dev librdmacm-dev libreadline-dev liblvm2-dev libglib2.0-dev liburcu-dev libsqlite3-dev libacl1-dev git libgoogle-perftools-dev g++ wget sshpass attr

#optional
git clone https://github.com/axboe/liburing.git
cd liburing
make -j
make install
cd ../
rm -r liburing

#compile glusterfs
git clone https://github.com/gluster/glusterfs.git
cd glusterfs

#code annotation
void __ucov_start(unsigned long req_pid);
void __ucov_stop(void);
__ucov_start(finh->pid);  #fuse_dispatch
__ucov_start(stub->frame->root->pid); #iot_worker

export CC="/root/dfs-fuzzing/dfs-usp-gcc ucov 0 -pthread"
export CXX="/root/dfs-fuzzing/dfs-usp-g++ ucov 0 -pthread"
export CFLAGS="-L/root/dfs-fuzzing -lucov"
export CXXFLAGS="-L/root/dfs-fuzzing -lucov"

./autogen.sh
./configure --disable-linux-io_uring --enable-asan
#Note: since glusterfs processes are daemon processes, use 'export ASAN_OPTIONS=log_path=/path/to/xxx.log' to collect sanitizer output. Further details and more options can be found at https://github.com/google/sanitizers.

make -j`nproc`
make install

/sbin/mount.glusterfs:581: xlator_options+=($value) -> xlator_option+=$value

#Disable daemon automatic restart after failures. And decrease the limitation on restart frequency
#/usr/local/lib/systemd/system/gluster*
#/usr/local/lib/systemd/system/glusterd.service
sed -i 's/^StartLimitBurst=.*$/StartLimitBurst=5/g' /usr/local/lib/systemd/system/gluster*
sed -i 's/^Restart=.*$/Restart=no/g' /usr/local/lib/systemd/system/gluster*
sed -i 's/^StartLimitInterval.*$/StartLimitInterval=0/g' /usr/local/lib/systemd/system/gluster*
```

# 2. Environment configuration


```bash
# Set ASAN_OPTIONS for daemons
sed -i 's/^\[Service\]/\[Service\]\nEnvironment="ASAN_OPTIONS=log_path=\/root\/daemon-log:detect_leaks=0"/g' /usr/local/lib/systemd/system/gluster*

echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"' > /etc/environment
echo 'ASAN_OPTIONS="log_path=/root/daemon-log:detect_leaks=0:verify_asan_link_order=0"' >> /etc/environment
echo "/usr/local/lib" > /etc/ld.so.conf.d/glusterfs.conf
echo "/root/dfs-fuzzing" >> /etc/ld.so.conf.d/glusterfs.conf
ldconfig
cp /root/glusterfs/xlators/mount/fuse/utils/mount.glusterfs /sbin/
systemctl daemon-reload
echo "kernel.randomize_va_space=0" >> /etc/sysctl.conf
sysctl -p

#set ping-timeout in file /usr/local/etc/glusterfs/glusterd.vol
#ref: https://thornelabs.net/posts/change-gluster-volume-connection-timeout-for-glusterfs-native-client/
volume test-volume
    type protocol/client
    option ping-timeout 1
end-volume
```

# 3. Node configuration

```bash
#args
start_ip=$1
srv_cnt=$2
client_cnt=$3

cur_ip=$start_ip

nextip(){
    IP=$1
    IP_HEX=$(printf '%.2X%.2X%.2X%.2X\n' `echo $IP | sed -e 's/\./ /g'`)
    NEXT_IP_HEX=$(printf %.8X `echo $(( 0x$IP_HEX + 1 ))`)
    NEXT_IP=$(printf '%d.%d.%d.%d\n' `echo $NEXT_IP_HEX | sed -r 's/(..)/0x\1 /g'`)
    echo "$NEXT_IP"
}

i=0
srvs=""    
while [ $i -lt $srv_cnt ]
do
	{
		if [ $i -eq 0 ]; then
        	systemctl restart glusterd      
	    else
    	    sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip LD_PRELOAD=/root/dfs-fuzzing/libucov.so systemctl restart glusterd
        	echo gluster peer probe $cur_ip
		gluster peer probe $cur_ip
    	fi
	}&
    srvs="${srvs} ${cur_ip}:/root/glusterfs-server"
    cur_ip=$(nextip $cur_ip)
    i=$(( i + 1 ))
done

wait

sleep 2s
gluster peer status
echo gluster volume create test-volume disperse 3 redundancy 1 $srvs force
LD_PRELOAD=/root/dfs-fuzzing/libucov.so gluster volume create test-volume disperse 3 redundancy 1 $srvs force
#gluster volume create test-volume $srvs force
LD_PRELOAD=/root/dfs-fuzzing/libucov.so gluster volume start test-volume

#client
i=0
while [ $i -lt $client_cnt ]
do
    #export ASAN_OPTIONS=detect_leaks=0
    sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip mount -t glusterfs $start_ip:/test-volume glusterfs-client &
    cur_ip=$(nextip $cur_ip)
    i=$(( i + 1 ))
done
echo "mount finished"
wait
```

# 4. Node reconfiguration

```bash
#args
start_ip=$1
srv_cnt=$2
client_cnt=$3
cur_idx=$4

if [ $cur_idx -lt $srv_cnt ]; then
	systemctl restart glusterd
else
	mount -t glusterfs $start_ip:/test-volume glusterfs-client
fi
```

# 5. Failure configuration

```bash
#node_down.sh
pids=$(ps -aux|grep "sbin/gluster"|awk '{print $2}')
for pid in $pids; do kill -9 $pid; done
#node_up.sh
systemctl restart glusterd
```

# 6. Manually start VMs

```bash
sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=28324 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-0 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm30,id=shm30 -device ivshmem-plain,memdev=shm30,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm31,id=shm31 -device ivshmem-plain,memdev=shm31,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn30 -device virtio-net,netdev=hn30,mac=e6:c8:ff:09:76:1e -hda /home/tlyu/dfs-fuzzing/disk-images/glusterfs-test/srv1.qcow2 -drive file=/home/tlyu/dfs-fuzzing/disk-images/glusterfs-test/data.img,format=raw,if=virtio,index=1 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-glusterfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.30"

sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=58121 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-1 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm30,id=shm30 -device ivshmem-plain,memdev=shm30,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm32,id=shm32 -device ivshmem-plain,memdev=shm32,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn31 -device virtio-net,netdev=hn31,mac=e6:c8:ff:09:76:1f -hda /home/tlyu/dfs-fuzzing/disk-images/glusterfs-test/srv2.qcow2 -drive file=/home/tlyu/dfs-fuzzing/disk-images/glusterfs-test/data2.img,format=raw,if=virtio,index=1 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-glusterfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.31"

sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=26856 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-2 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm30,id=shm30 -device ivshmem-plain,memdev=shm30,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm33,id=shm33 -device ivshmem-plain,memdev=shm33,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn32 -device virtio-net,netdev=hn32,mac=e6:c8:ff:09:76:20 -hda /home/tlyu/dfs-fuzzing/disk-images/glusterfs-test/srv3.qcow2 -drive file=/home/tlyu/dfs-fuzzing/disk-images/glusterfs-test/data3.img,format=raw,if=virtio,index=1 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-glusterfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.32"

sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=46407 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-3 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm30,id=shm30 -device ivshmem-plain,memdev=shm30,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm34,id=shm34 -device ivshmem-plain,memdev=shm34,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn33 -device virtio-net,netdev=hn33,mac=e6:c8:ff:09:76:21 -hda /home/tlyu/dfs-fuzzing/disk-images/glusterfs-test/client1.qcow2 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-glusterfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.33"

sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=48495 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-4 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm30,id=shm30 -device ivshmem-plain,memdev=shm30,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm35,id=shm35 -device ivshmem-plain,memdev=shm35,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn34 -device virtio-net,netdev=hn34,mac=e6:c8:ff:09:76:22 -hda /home/tlyu/dfs-fuzzing/disk-images/glusterfs-test/client2.qcow2 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-glusterfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.34"

sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=27246 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-5 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm30,id=shm30 -device ivshmem-plain,memdev=shm30,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm36,id=shm36 -device ivshmem-plain,memdev=shm36,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn35 -device virtio-net,netdev=hn35,mac=e6:c8:ff:09:76:23 -hda /home/tlyu/dfs-fuzzing/disk-images/glusterfs-test/client3.qcow2 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-glusterfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.35"
```

# 7. Documentations

- [GlusterFS tuning operations](https://docs.gluster.org/en/main/Administrator-Guide/Tuning-Volume-Options/)

    ```bash
    # List volume information
    gluster volume info

    # List one specific option
    gluster volume get test-volume performance.cache-invalidation

    # Set one specific option
    gluster volume set test-volume performance.open-behind off
    ```

    - [Open-behind](https://github.com/gluster/glusterfs/discussions/2543): not sending open syscalls to the network individually. Instead, send it together with the next calls, such as read/write.

    - [Write-behind](https://gluster-documentations.readthedocs.io/en/latest/Developer-guide/write-behind/): asynchronous writes, like IO-uring, the return of writes doesn't mean the write has finished.

    - [Quick-read](https://github.com/gluster/glusterfs/issues/3121): Prefetch data.
