# 1. [Software download and compilation](https://doc.beegfs.io/latest/advanced_topics/building_from_sources.html)
```bash
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

# Set instrumentation CC and libraries
# Copy dfs-usp-gcc and dfs-usp-g++ and libucov.so
# cp libucov.so /usr/local/lib
# *NOTE:Have to comment __libc_vfork because the libso in the VM image doesn't export this symbol
ldconfig

# Add the following ENV VARIABLES to /root/beegfs-v7/build/Makefile:174
CXXFLAGS := -lucov -fsanitize=address $(CXXFLAGS)
CFLAGS := -lucov -fsanitize=address $(CFLAGS)
CC := /root/monarch/dfs-usp-g++ ucov 0 -pthread
CXX := /root/monarch/dfs-usp-g++ ucov 0 -pthread
LDFLAGS := -fsanitize=address $(LDFLAGS)

# Compilation
rm -r packages
make package-deb PACKAGE_DIR=packages DEBUILD_OPTS='-j`nproc`'
cd packages
dpkg -i *

# Disable automatical starting.
systemctl disable beegfs-mgmtd
systemctl disable beegfs-meta
systemctl disable beegfs-storage
systemctl disable beegfs-helperd
systemctl disable beegfs-client

# Set restart frequency limitation
sed -i 's/^\[Service\]/\[Service\]\nRestart=no\nStartLimitBurst=5\nStartLimitInterval=0/g' /lib/systemd/system/beegfs-*
# Set env variables
sed -i 's/^\[Service\]/\[Service\]\nEnvironment="ASAN_OPTIONS=log_path=\/root\/daemon-log:detect_leaks=0"/g' /lib/systemd/system/beegfs-*




# Remove /mnt/myraid1/beegfs_storage/ from /etc/beegfs/beegfs-storage.conf
```

# 2. [Node configuration](https://doc.beegfs.io/latest/quick_start_guide/quick_start_guide.html#)

```bash
# Management server configuration and starting
/root/beegfs-v7/mgmtd/build/dist/sbin/beegfs-setup-mgmtd -p /root/beegfs-server/beegfs_mgmtd
systemctl start beegfs-mgmtd
# Metadata server configuration and starting
/root/beegfs-v7/meta/build/dist/sbin/beegfs-setup-meta -p /root/beegfs-server/beegfs_meta -s 2 -m localhost
systemctl start beegfs-meta
# Storage server configuration and starting
/root/beegfs-v7/storage/build/dist/sbin/beegfs-setup-storage -p /root/beegfs-server/beegfs_storage -s 3 -i 301 -m localhost
systemctl start beegfs-storage

# Client configuration and starting
# Edict /etc/beegfs/beegfs-mounts.conf for modifying mount location
/root/beegfs-v7/client_module/build/dist/sbin/beegfs-setup-client -m localhost
systemctl start beegfs-helperd
# Need to wait a few seconds here
systemctl start beegfs-client
```
