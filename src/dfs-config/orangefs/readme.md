# 1. [Source code download and compilation](https://docs.orangefs.com/quickstart/quickstart-build/)

```bash
# install dependent packages
sudo apt install automake build-essential bison flex libattr1 libattr1-dev libfuse-dev libdb-dev

# Set instrumentation CC and libraries
# Copy dfs-usp-gcc and dfs-usp-g++ and libucov.so
# cp libucov.so /usr/local/lib
# *NOTE:Have to comment __libc_vfork because the libso in the VM image doesn't export this symbol.
export CC="/root/monarch/dfs-usp-gcc ucov 0 -pthread"
export CXX="/root/monarch/dfs-usp-g++ ucov 0 -pthread"
export CFLAGS="-lucov -fsanitize=address"
export CXXFLAGS="-lucov -fsanitize=address"
export LDFLAGS="-fsanitize=address"

# get source code
wget https://s3.amazonaws.com/download.orangefs.org/current/source/orangefs-2.9.8.tar.gz
tar -xzf orangefs-2.9.8.tar.gz
mv orangefs-v.2.9.8 orangefs-v.2.9.8-server
tar -xzf orangefs-2.9.8.tar.gz
mv orangefs-v.2.9.8 orangefs-v.2.9.8-client

# Server compilation
cd orangefs-v.2.9.8-server
./configure --prefix=/opt/orangefs --with-db-backend=lmdb
make -j`nproc`
make install

# FUSE client compilation
# backup the compiled files for server and get a new source code for client
cd orangefs-v.2.9.8-client
./configure --prefix=/opt/orangefs --disable-server --disable-usrint --disable-opt --enable-fuse
make -j`nproc`
make install

# Kernel client compilation
# make -j`nproc` CC="/home/tlyu/dfs-fuzzing/dfs-fuzzing/bin/dfs-gcc 1 fs/orangefs"
```

# 2. Server Setup

```bash
# Creating the OrangeFS Configuration File 
/opt/orangefs/bin/pvfs2-genconfig /opt/orangefs/etc/orangefs-server.conf

# Initialize the Storage Directories
#/opt/orangefs/sbin/pvfs2-server -f -a localhost /opt/orangefs/etc/orangefs-server.conf
/opt/orangefs/sbin/pvfs2-server -f -a 192.168.0.10 /opt/orangefs/etc/orangefs-server.conf

# Start the Server Process
#/opt/orangefs/sbin/pvfs2-server -a localhost /opt/orangefs/etc/orangefs-server.conf
/opt/orangefs/sbin/pvfs2-server -a 192.168.0.10 /opt/orangefs/etc/orangefs-server.conf

# Stopping the Server Process 
# killall pvfs2-server
```

# 3. Client Setup

```bash
# Create a directory as the mount point
mkdir /root/orangefs-client

# Mount an OrangeFS filesystem
/opt/orangefs/bin/pvfs2fuse /root/orangefs-client -o fs_spec=tcp://192.168.0.10:3334/orangefs
```

# 4. Compile fuse on Host

- Version fuse-2.9.9

```bash
# add annotation code at lib/fuse_lowlevel.c:
# void __ucov_start(unsigned long req_pid);
# void __ucov_stop(void);
# __ucov_start(req->ctx.pid);   lib/fuse_lowlevel.c:2440
# __ucov_stop();                lib/fuse_lowlevel.c:2448
git clone https://github.com/libfuse/libfuse.git
cd libfuse
git checkout fuse-2.9.9

export CFLAGS="-pthread -L/home/tlyu/dfs-fuzzing/dfs-fuzzing/bin/ -lucov"
export CXXFLAGS="-pthread -L/home/tlyu/dfs-fuzzing/dfs-fuzzing/bin/ -lucov"
./makeconf.sh
./configure
make -j`nproc`

# Copy libfuse.so.2.9.9 to the dir /lib/x86_64-linux-gnu in the VM image.
cp libfuse/lib/.libs/libfuse.so.2.9.9 /lib/x86_64-linux-gnu
```
