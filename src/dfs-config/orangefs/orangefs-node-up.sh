#args
start_ip=$1
srv_cnt=$2
clt_cnt=$3
cur_idx=$4

srv_range=$2
clt_range=$((srv_range+clt_cnt))

if [ $cur_idx -lt $srv_range ]; then
	/opt/orangefs/sbin/pvfs2-server -a $start_ip /opt/orangefs/etc/orangefs-server.conf
elif [ $cur_idx -lt $clt_range ]; then
	/opt/orangefs/bin/pvfs2fuse /root/orangefs-client -o fs_spec=tcp://$start_ip:3334/orangefs
fi
