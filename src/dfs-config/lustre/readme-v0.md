# 1. Lustre compilation and installation
## 1.1 Build compilation environment
```bash
# building instructions
https://wiki.lustre.org/Compiling_Lustre
https://wiki.whamcloud.com/display/PUB/Build+Lustre+MASTER+with+Ldiskfs+on+Ubuntu+20.04.1+from+Git

# install kernel related packages
apt install linux-headers-5.4.0-137-generic linux-image-5.4.0-137-generic linux-modules-5.4.0-137-generic linux-modules-extra-5.4.0-137-generic
# get kernel source code
mkdir ~/build && cd ~/build
apt source linux-image-unsigned-5.4.0-generic
# copy kernel ext4 source code into linux-headers
cp -r ~/build/linux-5.4.0/fs/ext4/ /usr/src/linux-headers-5.4.0-137/fs/
# get ext4.h and namei.c from Ubuntu-5.4.0-90.101 source tree
wget https://kernel.ubuntu.com/git/ubuntu/ubuntu-focal.git/plain/fs/ext4/ext4.h?h=Ubuntu-5.4.0-90.101
wget https://kernel.ubuntu.com/git/ubuntu/ubuntu-focal.git/plain/fs/ext4/namei.c?h=Ubuntu-5.4.0-90.101
# replace the two files in linux-headers
mv ext4.h /usr/src/linux-headers-5.4.0-137/fs/ext4/
mv namei.c /usr/src/linux-headers-5.4.0-137/fs/ext4/

# install dependencies
apt install dpkg-dev libkeyutils-dev libnl-genl-3-dev libyaml-dev e2fslibs-dev
apt install texinfo libfuse-dev dh-exec
apt install module-assistant debhelper dpatch libsnmp-dev mpi-default-dev quilt rsync swig ed
```

## 1.2 Lustre server compilation and installation
```bash
# get lustre source code
git clone git://git.whamcloud.com/fs/lustre-release.git lustre-server
cd lustre-server

# configure
sh autogen.sh
./configure --enable-server --with-linux=/usr/src/linux-headers-5.4.0-137-generic --with-zfs=no

# compile
make debs -j `nproc`

# install
cd debs
dpkg -i *.deb # this will not succeedd, missing dependencies
apt --fix-broken install # install missing dependencies automatically
dpkg -i *.deb # this will succeed
```

## 1.3 Lustre client compilation and installation
```bash
# get lustre source code
git clone git://git.whamcloud.com/fs/lustre-release.git lustre-client
cd lustre-client

# configure
sh autogen.sh
./configure --disable-server --enable-client --with-linux=/usr/src/linux-headers-5.4.0-137-generic

# compile
make debs -j `nproc`

# install
cd debs
dpkg -i *.deb # this will not succeedd, missing dependencies
apt --fix-broken install # install missing dependencies automatically
dpkg -i *.deb # this will succeed
```

# 2. e2fsprog compilation and installation (server side)
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

# 3. Node configuration
```bash
# configuration instructions
https://wiki.lustre.org/Configuring_the_Lustre_File_System
https://wiki.lustre.org/Mounting_a_Lustre_File_System_on_Client_Nodes
```

## 3.1 Server side configuration
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

## 3.2 Client side configuration
```bash
# create mount point
mkdir /mnt/lustre

# mount
mount -t lustre 192.168.0.10@tcp0:/lustre /mnt/lustre
```
