hostname client$2

rm -r /etc/ceph
mkdir /etc/ceph
sshpass -p "123456" scp -o StrictHostKeyChecking=no root@$1:/etc/ceph/ceph.client.admin.keyring /etc/ceph/ceph.client.admin.keyring
sshpass -p "123456" scp -o StrictHostKeyChecking=no root@$1:/etc/ceph/ceph.conf /etc/ceph/ceph.conf
mount -t ceph $1:/ cephfs-client -o name=admin
sync
