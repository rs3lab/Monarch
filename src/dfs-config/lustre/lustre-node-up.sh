#args
start_ip=$1
mgs_cnt=$2
mds_cnt=$3
oss_cnt=$4
clt_cnt=$5
cur_idx=$6

# Range
mgs_range=$mgs_cnt
mds_range=$(($mgs_range+$mds_cnt))
oss_range=$(($mds_range+$oss_cnt))
clt_range=$(($oss_range+$clt_cnt))

# MGS
if [ $cur_idx -lt $mgs_range ]; then
	mount -t lustre /dev/vda /root/lustre-server
# MDS
elif [ $cur_idx -lt $mds_range ]; then
	mount -t lustre /dev/vda /root/lustre-server
# OSS
elif [ $cur_idx -lt $oss_range ]; then
	mount -t lustre /dev/vda /root/lustre-server
# Clients
elif [ $cur_idx -lt $clt_range ]; then
	mount -t lustre $start_ip@tcp0:/lustre /root/lustre-client
fi
