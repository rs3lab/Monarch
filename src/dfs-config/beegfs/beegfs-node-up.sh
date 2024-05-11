#args
start_ip=$1
manage_cnt=$2
meta_cnt=$3
storage_cnt=$4
clt_cnt=$5
cur_idx=$6

manage_range=$2
meta_range=$((manage_range+meta_cnt))
storage_range=$((meta_range+storage_cnt))
clt_range=$((storage_range+clt_cnt))

if [ $cur_idx -lt $manage_range ]; then
	systemctl restart beegfs-mgmtd
	#systemctl status beegfs-mgmtd
elif [ $cur_idx -lt $meta_range ]; then
	systemctl restart beegfs-meta
	#systemctl status beegfs-meta
elif [ $cur_idx -lt $storage_range ]; then
	systemctl restart beegfs-storage
	#systemctl status beegfs-storage
elif [ $cur_idx -lt $clt_range ]; then
	systemctl restart beegfs-helperd
	systemctl restart beegfs-client
fi
