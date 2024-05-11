pipe_file="/root/areas"

hostname osd$2

useradd ceph
mkdir /etc/ceph
chown ceph:ceph /etc/ceph/
mkdir /var/lib/ceph/
chown ceph:ceph /var/lib/ceph/
mkdir /var/lib/ceph/bootstrap-osd
chown ceph:ceph /var/lib/ceph/bootstrap-osd/
mkdir /var/lib/ceph/osd/
chown ceph:ceph /var/lib/ceph/osd/
mkdir /var/run/ceph
chown ceph:ceph /var/run/ceph

export ASAN_OPTIONS=verify_asan_link_order=0
#
#export ASAN_OPTIONS=detect_leaks=0

#If wanna to execute ceph command on OSDs, you have to copy /etc/ceph/ceph.conf and /etc/ceph/ceph.client.admin.keyring from monitor server to OSD servers. Also add the following lines to /etc/ceph/ceph.conf
#[client]
#keyring = /etc/ceph/ceph.client.admin.keyring
sshpass -p "123456" scp -o StrictHostKeyChecking=no root@$1:/var/lib/ceph/bootstrap-osd/ceph.keyring /var/lib/ceph/bootstrap-osd/ceph.keyring
sshpass -p "123456" scp -o StrictHostKeyChecking=no root@$1:/etc/ceph/ceph.conf /etc/ceph/ceph.conf
sshpass -p "123456" scp -o StrictHostKeyChecking=no root@$1:/etc/ceph/ceph.client.admin.keyring /etc/ceph/ceph.client.admin.keyring
echo "[client]
keyring = /etc/ceph/ceph.client.admin.keyring" >> /etc/ceph/ceph.conf

#while [ ! -p "$pipe_file" ]; do echo 1; done
ceph-volume lvm create --data /dev/vda
#ceph-volume raw prepare --bluestore --data /dev/vda
#ceph-volume raw activate --device /dev/vda
sync
