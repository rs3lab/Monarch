# 1. Lustre compilation and installation
## 1.1 Build compilation environment
```bash
# building instructions
https://wiki.lustre.org/Compiling_Lustre
https://wiki.whamcloud.com/display/PUB/Build+Lustre+MASTER+with+Ldiskfs+on+Ubuntu+20.04.1+from+Git

# Download kernel source code
git clone git://kernel.ubuntu.com/ubuntu/ubuntu-focal.git
# After compilation, the version is 5.4.148+
mv ubuntu-focal ubuntu-5.4.0-90.101
cd ubuntu-5.4.0-90.101
git checkout Ubuntu-5.4.0-90.101
# Use the config file in this repo
make menuconfig # Enable kcov and kasan
make -j`nproc` CC="/root/monarch/dfs-gcc 0"
make modules_install
# Reboot the VM to this new kernel and start compiling Lustre

# install dependencies
apt install dpkg-dev libkeyutils-dev libnl-genl-3-dev libyaml-dev e2fslibs-dev
apt install texinfo libfuse-dev dh-exec
apt install module-assistant debhelper dpatch libsnmp-dev mpi-default-dev quilt rsync swig ed
```

## 1.2 Lustre server compilation and installation
```bash
# Get lustre source code
git clone git://git.whamcloud.com/fs/lustre-release.git lustre-server
cd lustre-server

# Configure
sh autogen.sh
# Edit configure file:
# 1. configure:66672 : <<'END'
# 2. configure:67005 END
# 3. add "LDISKFS_SERIES=5.11.0-40-ubuntu20.series" at configure:67007 
./configure --enable-server --with-linux=/root/ubuntu-5.11.0-40/ --with-zfs=no

# Compile
make debs -j`nproc`

# Install
cd debs
dpkg -i *.deb # this will not succeedd, missing dependencies
apt --fix-broken install # install missing dependencies automatically
dpkg -i *.deb # this will succeed
```

## 1.3 e2fsprog compilation and installation (server side)

```bash
# compilation
mkdir e2fs && cd e2fs
git clone git://git.whamcloud.com/tools/e2fsprogs.git
cd e2fsprogs
git checkout master-lustre
sed -i 's/ext2_types-wrapper.h$//g' lib/ext2fs/Makefile.in
./configure
dpkg-buildpackage -b -us -uc

# installation
cd ~/e2fs
dpkg -i \
e2fsprogs_1.46.6-wc1_amd64.deb \
libext2fs-dev_1.46.6-wc1_amd64.deb \
comerr-dev_2.1-1.46.6-wc1_amd64.deb \
libext2fs2_1.46.6-wc1_amd64.deb \
libcom-err2_1.46.6-wc1_amd64.deb \
libss2_1.46.6-wc1_amd64.deb
```

## 1.4 Lustre client compilation and installation

```bash
# Get lustre source code
git clone git://git.whamcloud.com/fs/lustre-release.git lustre-client
cd lustre-client

# Configure
sh autogen.sh
# Edit configure file:
# 1. configure:66672 : <<'END'
# 2. configure:67005 END
# 3. add "LDISKFS_SERIES = 5.4.0-90-ubuntu20.series" at configure:67007 
./configure --disable-server --enable-client --with-linux=/root/ubuntu-5.4.0-90.101

# Compile
make debs -j `nproc`

# Install
cd debs
dpkg -i *.deb # this will not succeedd, missing dependencies
apt --fix-broken install # install missing dependencies automatically
dpkg -i *.deb # this will succeed
```

# 3. Node configuration
## 3.1 [Server side configuration](https://wiki.lustre.org/Configuring_the_Lustre_File_System)
```bash
# create virtual disks
dd if=/dev/zero of=mdt.img bs=1M count=512
losetup -Pf --show mdt.img
dd if=/dev/zero of=ost.img bs=1M count=512
losetup -Pf --show ost.img

# configure block devices for MDT and OST
mkfs.lustre --fsname=lustre --mgs --mdt /dev/loop0
mkfs.lustre --ost --fsname=lustre --index=1 --reformat --mgsnode=192.168.0.10@tcp0 /dev/loop1

# create mount point
mkdir /mnt/mdt
mkdir /mnt/ost

# mount MDT and OST
mount -t lustre /dev/loop0 /mnt/mdt
mount -t lustre /dev/loop1 /mnt/ost
```

## 3.2 [Client side configuration](https://wiki.lustre.org/Mounting_a_Lustre_File_System_on_Client_Nodes)
```bash
# create mount point
mkdir /root/lustre-client
# mount
mount -t lustre 192.168.0.10@tcp0:/lustre /root/lustre-client
```
