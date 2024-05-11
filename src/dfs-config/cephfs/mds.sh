ID=$1
mon_ip=$2
pipe_file="/root/areas"

hostname $ID

useradd ceph
mkdir /etc/ceph
chown ceph:ceph /etc/ceph/
mkdir /var/lib/ceph/
chown ceph:ceph /var/lib/ceph/
mkdir /var/lib/ceph/mds/
chown ceph:ceph /var/lib/ceph/mds/
mkdir /var/run/ceph
chown ceph:ceph /var/run/ceph

rm -r /var/lib/ceph/mds/ceph-$ID
mkdir -p /var/lib/ceph/mds/ceph-$ID

export ASAN_OPTIONS=verify_asan_link_order=0

sshpass -p "123456" scp -o StrictHostKeyChecking=no root@$mon_ip:/etc/ceph/ceph.client.admin.keyring /etc/ceph/ceph.client.admin.keyring
sshpass -p "123456" scp -o StrictHostKeyChecking=no root@$mon_ip:/etc/ceph/ceph.conf /etc/ceph/ceph.conf

#
#export ASAN_OPTIONS=detect_leaks=0
#while [ ! -p "$pipe_file" ]; do echo 1; done

ceph-authtool --create-keyring /var/lib/ceph/mds/ceph-$ID/keyring --gen-key -n mds.$ID
chown ceph:ceph /var/lib/ceph/mds/ceph-$ID/keyring
ceph auth add mds.$ID osd "allow rwx" mds "allow *" mon "allow profile mds" -i /var/lib/ceph/mds/ceph-$ID/keyring
echo "[mds.$ID]
host = $ID" >> /etc/ceph/ceph.conf
ceph-mds --cluster ceph -i $ID -m $mon_ip
sync
