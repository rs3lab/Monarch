# 1. Software download and compilation

```bash
# building instructions
# https://docs.orangefs.com/quickstart/quickstart-build/

# get source code
# wget http://download.orangefs.org/current/source/orangefs-2.9.8.tar.gz
wget https://s3.amazonaws.com/download.orangefs.org/current/source/orangefs-2.9.8.tar.gz
tar -xzf orangefs-2.9.8.tar.gz
cd orangefs-v.2.9.8

# install dependent packages
sudo apt install automake build-essential bison flex libattr1 libattr1-dev

# ./configure --prefix=/opt/orangefs --with-kernel= /lib/modules/5.15.0-56-generic/build --with-db-backend=lmdb
./configure --prefix=/opt/orangefs --with-db-backend=lmdb
make -j`nproc`
make install
```

<details>
  <summary>Output of make install </summary>

```bash
# output =>
#
# install -d /opt/orangefs/share/man/man1
# install -d /opt/orangefs/share/man/man5
# rm -f /opt/orangefs/share/man/man1/pvfs2*.gz
# rm -f /opt/orangefs/share/man/man5/pvfs2*.gz
# install -m 644 ./doc/man/*.1 /opt/orangefs/share/man/man1
# install -m 644 ./doc/man/*.5 /opt/orangefs/share/man/man5
# gzip -f /opt/orangefs/share/man/man1/pvfs2*.1
# gzip -f /opt/orangefs/share/man/man5/pvfs2*.5
# ln -fs pvfs2-getmattr.1.gz /opt/orangefs/share/man/man1/getmattr.1.gz
# ln -fs pvfs2-ls.1.gz /opt/orangefs/share/man/man1/pvfs2-lsplus.1.gz
# ln -fs pvfs2-setmattr.1.gz /opt/orangefs/share/man/man1/setmattr.1.gz
# install -d /opt/orangefs/include
# install -m 644 /root/orangefs-v.2.9.8/include/orange.h /opt/orangefs/include
# install -m 644 /root/orangefs-v.2.9.8/include/pvfs2.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-request.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-debug.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-sysint.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-usrint.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-mgmt.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-types.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-util.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-encode-stubs.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-hint.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-compat.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-mirror.h /opt/orangefs/include
# install -d /opt/orangefs/lib
# for i in libpvfs2.a ; do \
#     install -m 644 lib/$i /opt/orangefs/lib ;\
# done
# install -d /opt/orangefs/bin
# install -m 755 src/apps/admin/pvfs2-set-debugmask src/apps/admin/pvfs2-set-mode src/apps/admin/pvfs2-set-perf-h
# istory src/apps/admin/pvfs2-set-perf-interval src/apps/admin/pvfs2-set-eventmask src/apps/admin/pvfs2-set-sync 
# src/apps/admin/pvfs2-set-turn-off-timeouts src/apps/admin/pvfs2-ls src/apps/admin/pvfs2-ping src/apps/admin/pvf
# s2-stat src/apps/admin/pvfs2-statfs src/apps/admin/pvfs2-perf-mon-example src/apps/admin/pvfs2-perf-mon-snmp sr
# c/apps/admin/pvfs2-mkdir src/apps/admin/pvfs2-chmod src/apps/admin/pvfs2-chown src/apps/admin/pvfs2-fs-dump src
# /apps/admin/pvfs2-fsck src/apps/admin/pvfs2-validate src/apps/admin/pvfs2-cp src/apps/admin/pvfs2-write src/app
# s/admin/pvfs2-viewdist src/apps/admin/pvfs2-xattr src/apps/admin/pvfs2-touch src/apps/admin/pvfs2-remove-object
#  src/apps/admin/pvfs2-ln src/apps/admin/pvfs2-perror src/apps/admin/pvfs2-check-server src/apps/admin/pvfs2-dro
# p-caches src/apps/admin/pvfs2-get-uid /opt/orangefs/bin
# # for compatibility in case anyone really wants "lsplus"
# ln -snf pvfs2-ls /opt/orangefs/bin/pvfs2-lsplus
# install -m 755 src/apps/admin/pvfs2-config /opt/orangefs/bin
# install -m 755 ./src/apps/admin/pvfs2-genconfig /opt/orangefs/bin
# install -m 755 ./src/apps/admin/pvfs2-getmattr /opt/orangefs/bin
# install -m 755 ./src/apps/admin/pvfs2-setmattr /opt/orangefs/bin
# # install any development tools built
# for i in src/apps/devel/lmdb/mdb_copy src/apps/devel/lmdb/mdb_dump src/apps/devel/lmdb/mdb_load src/apps/devel/
# lmdb/mdb_stat src/apps/devel/pvfs2-db-display src/apps/devel/pvfs2-remove-prealloc src/apps/devel/mem_analysis 
# ; do \
# 	if [ -f $i ]; then install -m 755 $i /opt/orangefs/bin; fi;\
# done
# install -d /opt/orangefs/sbin
# install -m 755 ./src/apps/admin/pvfs2-start-all /opt/orangefs/sbin
# install -m 755 ./src/apps/admin/pvfs2-stop-all /opt/orangefs/sbin
# install -m 755 src/apps/admin/pvfs2-mkspace src/apps/admin/pvfs2-showcoll /opt/orangefs/bin
# install -m 755 src/apps/kernel/linux/pvfs2-client src/apps/kernel/linux/pvfs2-client-core  /opt/orangefs/sbin
# install -m 755 src/server/pvfs2-server /opt/orangefs/sbin
# rm -f /opt/orangefs/bin/.pvfs2-genconfig-* &> /dev/null
# # create etc dir under install dir
# install -d /opt/orangefs/etc
```
</details>



# 2. Configuration

```bash
# Creating the OrangeFS Configuration File 
/opt/orangefs/bin/pvfs2-genconfig /opt/orangefs/etc/orangefs-server.conf
```

<details>
  <summary>Output</summary>

```bash
# output =>
#
# ****************************************************************************
#     Welcome to the OrangeFS Configuration Generator:

# This interactive script will generate a configuration file suitable for use
# with a new OrangeFS (aka PVFS2) file system.  Please see the OrangeFS 
# documentation at http://www.orangefs.org/documentation for details.

# ****************************************************************************
# You must first select the network protocol that your file system will use.
# The currently supported options are "tcp", "gm", "mx", "ib", and "portals".
# (For multi-homed configurations, use e.g. "ib,tcp".)

# * Enter protocol type [Default is tcp]: 

# Choose a TCP/IP port for the servers to listen on.  Note that this
# script assumes that all servers will use the same port number.

# * Enter port number [Default is 3334]: 

# Choose a directory for each server to store data in.

# * Enter directory name: [Default is /opt/orangefs/storage/data]: 

# Choose a directory for each server to store metadata in.

# * Enter directory name: [Default is /opt/orangefs/storage/meta]: 

# Choose a file for each server to write log messages to.

# * Enter log file location [Default is /var/log/orangefs-server.log]: 

# Next you must list the hostnames of the I/O servers.
# Acceptable syntax is "node1, node2, ..." or "node{#-#,#,#}".

# * Enter hostnames [Default is localhost]: 

# Use same servers for metadata? (recommended)

# * Enter yes or no [Default is yes]: 

# Configured a total of 1 servers:
# 1 of them are I/O servers.
# 1 of them are Metadata servers.

# * Would you like to verify server list (y/n) [Default is n]? 

# Writing fs config file... 3
# done
```
</details>

# 3. Add servers

```bash
# Initialize the Storage Directories
/opt/orangefs/sbin/pvfs2-server -f -a localhost /opt/orangefs/etc/orangefs-server.conf

# Start the Server Process
/opt/orangefs/sbin/pvfs2-server -a localhost /opt/orangefs/etc/orangefs-server.conf

# Stopping the Server Process 
killall pvfs2-server
```

# 4. Add clients

```bash
# backup the compiled diles for server and get a new source code for client
mv orangefs-v.2.9.8 orangefs-v.2.9.8-server
tar -xzf orangefs-2.9.8.tar.gz
mv orangefs-v.2.9.8 orangefs-v.2.9.8-fuse

# compile fuse related files
cd orangefs-v.2.9.8-fuse
apt install libfuse-dev libdb-dev
./configure --prefix=/opt/orangefs --disable-server --disable-usrint --disable-opt --enable-fuse
make -j`nproc`
make install
```

<details>
  <summary>Output of make install</summary>

```bash
# output =>
#
# install -d /opt/orangefs/share/man/man1
# install -d /opt/orangefs/share/man/man5
# rm -f /opt/orangefs/share/man/man1/pvfs2*.gz
# rm -f /opt/orangefs/share/man/man5/pvfs2*.gz
# install -m 644 ./doc/man/*.1 /opt/orangefs/share/man/man1
# install -m 644 ./doc/man/*.5 /opt/orangefs/share/man/man5
# gzip -f /opt/orangefs/share/man/man1/pvfs2*.1
# gzip -f /opt/orangefs/share/man/man5/pvfs2*.5
# ln -fs pvfs2-getmattr.1.gz /opt/orangefs/share/man/man1/getmattr.1.gz
# ln -fs pvfs2-ls.1.gz /opt/orangefs/share/man/man1/pvfs2-lsplus.1.gz
# ln -fs pvfs2-setmattr.1.gz /opt/orangefs/share/man/man1/setmattr.1.gz
# install -d /opt/orangefs/include
# install -m 644 /root/orangefs-v.2.9.8/include/orange.h /opt/orangefs/include
# install -m 644 /root/orangefs-v.2.9.8/include/pvfs2.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-request.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-debug.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-sysint.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-usrint.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-mgmt.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-types.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-util.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-encode-stubs.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-hint.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-compat.h /opt/orangefs/include
# install -m 644 ./include/pvfs2-mirror.h /opt/orangefs/include
# install -d /opt/orangefs/lib
# for i in libpvfs2.a ; do \
#     install -m 644 lib/$i /opt/orangefs/lib ;\
# done
# install -d /opt/orangefs/bin
# install -m 755 src/apps/admin/pvfs2-set-debugmask src/apps/admin/pvfs2-set-mode src/apps/admin/pvfs2-set-perf-h
# istory src/apps/admin/pvfs2-set-perf-interval src/apps/admin/pvfs2-set-eventmask src/apps/admin/pvfs2-set-sync 
# src/apps/admin/pvfs2-set-turn-off-timeouts src/apps/admin/pvfs2-ls src/apps/admin/pvfs2-ping src/apps/admin/pvf
# s2-stat src/apps/admin/pvfs2-statfs src/apps/admin/pvfs2-perf-mon-example src/apps/admin/pvfs2-perf-mon-snmp sr
# c/apps/admin/pvfs2-mkdir src/apps/admin/pvfs2-chmod src/apps/admin/pvfs2-chown src/apps/admin/pvfs2-fs-dump src
# /apps/admin/pvfs2-fsck src/apps/admin/pvfs2-validate src/apps/admin/pvfs2-cp src/apps/admin/pvfs2-write src/app
# s/admin/pvfs2-viewdist src/apps/admin/pvfs2-xattr src/apps/admin/pvfs2-touch src/apps/admin/pvfs2-remove-object
#  src/apps/admin/pvfs2-ln src/apps/admin/pvfs2-perror src/apps/admin/pvfs2-check-server src/apps/admin/pvfs2-dro
# p-caches src/apps/admin/pvfs2-get-uid /opt/orangefs/bin
# # for compatibility in case anyone really wants "lsplus"
# ln -snf pvfs2-ls /opt/orangefs/bin/pvfs2-lsplus
# install -m 755 src/apps/admin/pvfs2-config /opt/orangefs/bin
# install -m 755 ./src/apps/admin/pvfs2-genconfig /opt/orangefs/bin
# install -m 755 ./src/apps/admin/pvfs2-getmattr /opt/orangefs/bin
# install -m 755 ./src/apps/admin/pvfs2-setmattr /opt/orangefs/bin
# install -m 755 src/apps/fuse/pvfs2fuse /opt/orangefs/bin
# # install any development tools built
# for i in src/apps/devel/lmdb/mdb_copy src/apps/devel/lmdb/mdb_dump src/apps/devel/lmdb/mdb_load src/apps/devel/
# lmdb/mdb_stat src/apps/devel/pvfs2-db-display src/apps/devel/pvfs2-remove-prealloc src/apps/devel/mem_analysis 
# ; do \
#     if [ -f $i ]; then install -m 755 $i /opt/orangefs/bin; fi;\
# done
# install -d /opt/orangefs/sbin
# install -m 755 ./src/apps/admin/pvfs2-start-all /opt/orangefs/sbin
# install -m 755 ./src/apps/admin/pvfs2-stop-all /opt/orangefs/sbin
# # create etc dir under install dir
# install -d /opt/orangefs/etc
```
</details>

```bash
# Create a directory as the mount point
mkdir /mnt/orangefs

# Mount an OrangeFS filesystem
/opt/orangefs/bin/pvfs2fuse /mnt/orangefs -o fs_spec=tcp://localhost:3334/orangefs
```
