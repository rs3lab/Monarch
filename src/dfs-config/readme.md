<!---
# Start VMs with user mode network
```bash
sudo qemu-system-x86_64 -m 10240 -smp 4 -net nic,model=e1000 -net user,hostfwd=tcp:127.0.0.1:1569-:22 -drive file=/home/tlyu/dfs-fuzzing/disk-images/cephfs-images-v2/focal.qcow2 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15-new/kernel-5.15-nfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0"

ip addr add 10.0.2.15/24 dev enp0s3
ip link set enp0s3 up
10.0.2.3 -> /etc/resolv.conf
```
--->

# Configure password and login when create a new image
```bash
#Allow ssh or scp with password
sed -i 's/.*PermitRootLogin.*/\PermitRootLogin yes/' /etc/ssh/sshd_config
systemctl restart ssh
#change root passwd in order to using scp between nodes
echo "root:123456" | chpasswd
apt-get install lvm2 sshpass
```

# Extend disk

```bash
qemu-img resize image.qcow2 +10G
resize2fs /dev/sda

https://uwot.eu/blog/resize-qcow2-disk-image/
```

# Permanently add a path to LD_LIBRARY_PATH
```bash
echo "path" > /etc/ld.so.conf.d/new.conf
sudo ldconfig
```

# [Configure NAT network for qemu VMs to connect internet](https://futurewei-cloud.github.io/ARM-Datacenter/qemu/network-aarch64-qemu-guests/)
```bash
#Host
sudo ip link add name br0 type bridge
sudo ip addr add 192.168.100.1/24 brd + dev br0
sudo ip link set br0 up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t filter -A FORWARD -i br0 -j ACCEPT
sudo iptables -t filter -A FORWARD -o br0 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o enp0s31f6 -j MASQUERADE

#Guest
ip addr add 192.168.100.2/24 brd + dev enp0s3
ip link set enp0s3 up
ip route add default via 192.168.100.1 dev enp0s3
#8.8.8.8 -> /etc/resolv.conf

#VM start cmd
sudo qemu-system-x86_64 -enable-kvm -m 30720 -smp 10 -drive file=/home/tlyu/dfs-fuzzing/disk-images/cephfs-images-v2/focal.qcow2 -kernel /home/tlyu/dfs-fuzzing/kernels/kernel-5.15/kernel-5.15-cephfs/arch/x86_64/boot/bzImage -append "root=/dev/sda console=ttyS0" -nic bridge,br=br0,model=virtio-net-pci,mac=02:76:7d:d7:1e:3f
```

# Certificate Error
```bash
#Certificate verification failed: The certificate is NOT trusted. The certificate issuer is unknown.  Could not handshake: Error in the certificate verification. [IP: XX.XXX.XX.XXX]

#Solution-1:
sudo apt install ca-certificates

#Solution-2:
touch /etc/apt/apt.conf.d/99verify-peer.conf && echo >>/etc/apt/apt.conf.d/99verify-peer.conf "Acquire { https::Verify-Peer false }"
```

# [Repair qcow2 Ext3 FS](https://news.numlock.ch/it/how-to-check-filesystems-in-a-qcow2-image)
