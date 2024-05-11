#args
start_ip=$1
srv_cnt=$2
client_cnt=$3
mode=$4
cur_idx=$5

if [ $cur_idx -lt $srv_cnt ]; then
	#mount -t ext4 /dev/vda /root/glusterfs-server -o sync
    systemctl restart glusterd
else
	umount -f /root/glusterfs-client
	mount -t glusterfs $start_ip:/test-volume /root/glusterfs-client
fi
sleep 1s
