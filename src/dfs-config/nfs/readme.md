# 1. Kernel compliation
```bash
make -j`nproc` CC="/home/tlyu/dfs-fuzzing/dfs-fuzzing/bin/dfs-gcc 4 fs/nfs fs/nfsd fs/nfs-common net/sunrpc"
```

# 2. Configuration
```bash
systemctl disable nfs-kernel-server
```

# 3. Manually start
```bash
sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=31901 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-0 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm2,id=shm2 -device ivshmem-plain,memdev=shm2,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm3,id=shm3 -device ivshmem-plain,memdev=shm3,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn2 -device virtio-net,netdev=hn2,mac=e6:c8:ff:09:76:02 -hda /home/tlyu/dfs-fuzzing/disk-images/nfs-test/srv.qcow2 -drive file=/home/tlyu/dfs-fuzzing/disk-images/nfs-test/data.img,format=raw,if=virtio,index=1 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-nfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.2"

sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=50072 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-1 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm2,id=shm2 -device ivshmem-plain,memdev=shm2,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm4,id=shm4 -device ivshmem-plain,memdev=shm4,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn3 -device virtio-net,netdev=hn3,mac=e6:c8:ff:09:76:03 -hda /home/tlyu/dfs-fuzzing/disk-images/nfs-test/client1.qcow2 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-nfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.3"

sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=45664 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-2 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm2,id=shm2 -device ivshmem-plain,memdev=shm2,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm5,id=shm5 -device ivshmem-plain,memdev=shm5,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn4 -device virtio-net,netdev=hn4,mac=e6:c8:ff:09:76:04 -hda /home/tlyu/dfs-fuzzing/disk-images/nfs-test/client2.qcow2 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-nfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.4"

sudo qemu-system-x86_64 -m 10240 -smp 4 -chardev socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=43151 -mon chardev=SOCKSYZ,mode=control -display none -serial stdio -name VM-3 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm2,id=shm2 -device ivshmem-plain,memdev=shm2,bus=pci.0,addr=0x10,master=on -object memory-backend-file,size=1M,share,mem-path=/dev/shm/shm6,id=shm6 -device ivshmem-plain,memdev=shm6,bus=pci.0,addr=0x11,master=on -device virtio-rng-pci -enable-kvm -cpu host,migratable=off -netdev bridge,id=hn5 -device virtio-net,netdev=hn5,mac=e6:c8:ff:09:76:05 -hda /home/tlyu/dfs-fuzzing/disk-images/nfs-test/client3.qcow2 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-nfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0 net.ifnames=0 ip=192.168.0.5"
```

# 4. Options

- Client
	- cto/nocto: close-to-open consistency (cto). nocto means the flush point is non-derministic.
	- async/sync: sync will flush every operation before it returns to applications, while async doesn't.
	- noac: no attribute cache at clients.
	- actimeo: if caching attributes, how long it should be invalidate. 

- Server
	- sync/async: whether flush operation to disk before repsonding clients.
