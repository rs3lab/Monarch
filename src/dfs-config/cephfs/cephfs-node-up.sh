mon_ip=$1
mon_cnt=$2
osd_cnt=$3
mds_cnt=$4
client_cnt=$5
cur_id=$6

mon_range=$mon_cnt
osd_range=$(($mon_range+$osd_cnt))
mds_range=$(($osd_range+$mds_cnt))
client_range=$(($mds_range+$client_cnt))

if [ $cur_id -lt $mon_range ] && [ $cur_id -ge 0 ]; then
    systemctl restart ceph-mon@node1
elif [ $cur_id -lt $osd_range ] && [ $cur_id -ge $mon_range ]; then
	osd_id=$(ls /var/lib/ceph/osd/ | awk -F"\-" '{print $2}')
	systemctl restart ceph-osd@$osd_id #$(systemctl list-units|grep ceph-osd@|awk -F"." '{print $1}')
elif [ $cur_id -lt $mds_range ] && [ $cur_id -ge $osd_range ]; then
    mds_id=$(($cur_id-$osd_range))
    ceph-mds --cluster ceph -i mds$mds_id -m $mon_ip
elif [ $cur_id -lt $client_range ] && [ $cur_id -ge $mds_range ]; then
    mount -t ceph $mon_ip:/ /root/cephfs-client -o name=admin
fi
