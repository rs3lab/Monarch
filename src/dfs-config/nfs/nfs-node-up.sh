#args
start_ip=$1
client_cnt=$2
mount_opts=$3
cur_idx=$4

if [ $cur_idx -lt 1 ]; then
	exportfs -a
	systemctl restart nfs-kernel-server
else
	umount -f /root/nfs-client
	mount -t nfs -o vers=4.2,timeo=1,retrans=1,soft,$mount_opts $start_ip:/ /root/nfs-client
fi
