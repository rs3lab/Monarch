# 1. Software download and compilation
```bash
# building instructions
https://doc.beegfs.io/latest/advanced_topics/building_from_sources.html

# get source code
# In VMs, Server certificate verification failed -> export GIT_SSL_NO_VERIFY=1
git clone https://git.beegfs.io/pub/v7 beegfs-v7
cd beegfs-v7

# update source.list
deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse

deb http://archive.canonical.com/ubuntu focal partner
deb-src http://archive.canonical.com/ubuntu focal partner

# install dependent packages
sudo apt install build-essential autoconf automake pkg-config devscripts debhelper \
libtool libattr1-dev xfslibs-dev lsb-release kmod librdmacm-dev libibverbs-dev \
default-jdk ant dh-systemd zlib1g-dev libssl-dev libcurl4-openssl-dev libblkid-dev uuid-dev dkms

# compile
make
```


# 2. Installation
## 2.1 Package installation
```bash
make package-deb PACKAGE_DIR=packages
cd packages
dpkg -i *
```

## 2.2 Manual installation
```bash
# install
make install

mkdir /etc/beegfs

cp /root/beegfs-v7/mgmtd/build/dist/etc/beegfs-mgmtd.conf /etc/beegfs/
/root/beegfs-v7/mgmtd/build/dist/sbin/beegfs-setup-mgmtd -p /data/beegfs/beegfs_mgmtd

cp /root/beegfs-v7/meta/build/dist/etc/beegfs-meta.conf /etc/beegfs/
/root/beegfs-v7/meta/build/dist/sbin/beegfs-setup-meta -p /data/beegfs/beegfs_meta -s 2 -m localhost

cp /root/beegfs-v7/storage/build/dist/etc/beegfs-storage.conf /etc/beegfs/
/root/beegfs-v7/storage/build/dist/sbin/beegfs-setup-storage -p /mnt/myraid1/beegfs_storage -s 3 -i 301 -m localhost

cp /root/beegfs-v7/helperd/build/dist/etc/beegfs-helperd.conf /etc/beegfs

cp /root/beegfs-v7/client_module/build/dist/etc/beegfs-client.conf /etc/beegfs
/root/beegfs-v7/client_module/build/dist/sbin/beegfs-setup-client -m localhost


cp /root/beegfs-v7/mgmtd/build/dist/usr/lib/systemd/system/* /usr/lib/systemd/system
systemctl start beegfs-mgmtd

cp /root/beegfs-v7/meta/build/dist/usr/lib/systemd/system/* /usr/lib/systemd/system
systemctl start beegfs-meta

cp /root/beegfs-v7/storage/build/dist/usr/lib/systemd/system/* /usr/lib/systemd/system
systemctl start beegfs-storage

cp /root/beegfs-v7/helperd/build/dist/usr/lib/systemd/system/* /usr/lib/systemd/system
systemctl start beegfs-helperd

cp /root/beegfs-v7/client_module/build/dist/usr/lib/systemd/system/* /usr/lib/systemd/system

cp /root/beegfs-v7/client_module/build/dist/etc/init.d/beegfs-client.init /etc/init.d/beegfs-client
chmod +x /etc/init.d/beegfs-client

mkdir /etc/beegfs/lib
cp /root/beegfs-v7/client_module/scripts/etc/beegfs/lib/init-multi-mode.beegfs-client /etc/beegfs/lib

cp /root/beegfs-v7/client_module/build/dist/etc/default/beegfs-client /etc/default

cp /root/beegfs-v7/client_module/build/dist/etc/beegfs-client-autobuild.conf /etc/beegfs/

mkdir /lib/modules/5.4.0/kernel/beegfs
cp /opt/beegfs/lib/modules/kernel/beegfs/beegfs.ko /lib/modules/5.4.0/kernel/beegfs
depmod -a

cp /root/beegfs-v7/client_module/build/dist/etc/beegfs-mounts.conf /etc/beegfs

systemctl start beegfs-client
```


# 3. Node configuration

```bash
# https://doc.beegfs.io/latest/quick_start_guide/quick_start_guide.html#

/root/beegfs-v7/mgmtd/build/dist/sbin/beegfs-setup-mgmtd -p /data/beegfs/beegfs_mgmtd
/root/beegfs-v7/meta/build/dist/sbin/beegfs-setup-meta -p /data/beegfs/beegfs_meta -s 2 -m localhost
/root/beegfs-v7/storage/build/dist/sbin/beegfs-setup-storage -p /mnt/myraid1/beegfs_storage -s 3 -i 301 -m localhost
/root/beegfs-v7/client_module/build/dist/sbin/beegfs-setup-client -m localhost

systemctl start beegfs-mgmtd
systemctl start beegfs-meta
systemctl start beegfs-storage
systemctl start beegfs-helperd
systemctl start beegfs-client
```

# 4. Troubleshooting
## 4.1 Version magic does not match when insert BeeGFS kernel module
Solution:<br />
Compile and install modules the kernel with in the VM

## 4.2 BeeGFS kernel module is loaded successfully, but filesystem type is unrecognized
Solution:<br />
set Kconfig<br />
Enable loadable module support<br />
&nbsp;&nbsp;&nbsp;&nbsp;Enable unused/obsolete exported symbols --> NO
  
## 4.3 Enabling broadcast for UDP socket failed
Solution:<br />


