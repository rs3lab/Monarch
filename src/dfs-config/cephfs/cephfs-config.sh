#Args
start_ip=$1
mon_cnt=$2
osd_cnt=$3
mds_cnt=$4
client_cnt=$5

cur_ip=$start_ip

nextip(){
	IP=$1
    IP_HEX=$(printf '%.2X%.2X%.2X%.2X\n' `echo $IP | sed -e 's/\./ /g'`)
    NEXT_IP_HEX=$(printf %.8X `echo $(( 0x$IP_HEX + 1 ))`)
    NEXT_IP=$(printf '%d.%d.%d.%d\n' `echo $NEXT_IP_HEX | sed -r 's/(..)/0x\1 /g'`)
    echo "$NEXT_IP"
}

#mon
hostnamectl set-hostname node1
echo "$cur_ip node1" >> /etc/hosts
#
useradd ceph
mkdir /etc/ceph
chown ceph:ceph /etc/ceph/
mkdir /var/lib/ceph/
chown ceph:ceph /var/lib/ceph/
mkdir /var/lib/ceph/bootstrap-osd
chown ceph:ceph /var/lib/ceph/bootstrap-osd/
mkdir /var/lib/ceph/mon
chown ceph:ceph /var/lib/ceph/mon/
mkdir /var/lib/ceph/mgr
chown ceph:ceph /var/lib/ceph/mgr/
mkdir /var/run/ceph
chown ceph:ceph /var/run/ceph
#
uuid=$(uuidgen)
echo "[global]
fsid = $uuid
mon_initial_members = node1
mon_host = $cur_ip
public network = 192.168.0.0/24
auth_cluster_required = cephx
auth_service_required = cephx
auth_client_required = cephx
osd pool default size = $osd_cnt
osd pool default min size = 2
osd crush chooseleaf type = 0
osd_heartbeat_interval = 2
mds_client_prealloc_inos = 0
" > /etc/ceph/ceph.conf
# 
# osd_mon_heartbeat_interval = 6
# mon_osd_down_out_interval = 60
# mon_osd_report_timeout = 60
# mon_osd_min_down_reporters = 1
# osd_heartbeat_grace = 20
# osd_mon_report_interval = 60

#Disable LeakSanitizer
#export ASAN_OPTIONS=detect_leaks=0
#
rm -r /tmp/*
ceph-authtool --create-keyring /tmp/ceph.mon.keyring --gen-key -n mon. --cap mon 'allow *'
ceph-authtool --create-keyring /etc/ceph/ceph.client.admin.keyring --gen-key -n client.admin --cap mon 'allow *' --cap osd 'allow *' --cap mds 'allow *' --cap mgr 'allow *'
ceph-authtool --create-keyring /var/lib/ceph/bootstrap-osd/ceph.keyring --gen-key -n client.bootstrap-osd --cap mon 'profile bootstrap-osd' --cap mgr 'allow r'
ceph-authtool /tmp/ceph.mon.keyring --import-keyring /etc/ceph/ceph.client.admin.keyring
ceph-authtool /tmp/ceph.mon.keyring --import-keyring /var/lib/ceph/bootstrap-osd/ceph.keyring
chown ceph:ceph /tmp/ceph.mon.keyring
monmaptool --create --add node1 $cur_ip --fsid $uuid /tmp/monmap
rm -r /var/lib/ceph/mon/ceph-node1
sudo -u ceph mkdir /var/lib/ceph/mon/ceph-node1
sudo -u ceph ceph-mon --mkfs -i node1 --monmap /tmp/monmap --keyring /tmp/ceph.mon.keyring
systemctl start ceph-mon@node1

#mgr
rm -r /var/lib/ceph/mgr/ceph-node1
mkdir /var/lib/ceph/mgr/ceph-node1
export ASAN_OPTIONS=verify_asan_link_order=0
ceph auth get-or-create mgr.node1 mon 'allow profile mgr' osd 'allow *' mds 'allow *' > /var/lib/ceph/mgr/ceph-node1/keyring
ceph-mgr -i node1
ceph mon enable-msgr2
sync

#osd
i=0
while [ "$i" -lt $osd_cnt ]
do
	cur_ip=$(nextip $cur_ip)
	sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip /root/osd.sh $start_ip $i &
    i=$(( i + 1 ))
done
wait

#mds
i=0
while [ "$i" -lt $mds_cnt ]
do
    cur_ip=$(nextip $cur_ip)
    sshpass -p "123456" ssh -o "StrictHostKeyChecking no" root@$cur_ip /root/mds.sh mds$i $start_ip &
    i=$(( i + 1 ))
done
#Now the MDS status is up:standy, and it will become up:active when you create a ceph file system.
wait

#cephfs
ceph osd pool create cephfs_data
ceph osd pool create cephfs_metadata
ceph fs new cephfs cephfs_metadata cephfs_data
sync

#mount
sleep 20s
i=0
while [ "$i" -lt $client_cnt ]
do
    cur_ip=$(nextip $cur_ip)
	sshpass -p "123456" ssh -o "StrictHostKeyChecking no" root@$cur_ip /root/mount.sh $start_ip $i &
    i=$(( i + 1 ))
done
#Mount might report "modprobe: FATAL: Module ceph not found in directory /lib/modules/5.15.0. failed to load ceph kernel module (1)". But it still successfully mounts cephfs.
wait
