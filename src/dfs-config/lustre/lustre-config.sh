#args
start_ip=$1
mgs_cnt=$2
mds_cnt=$3
oss_cnt=$4
clt_cnt=$5

cur_ip=$start_ip

nextip(){
    IP=$1
    IP_HEX=$(printf '%.2X%.2X%.2X%.2X\n' `echo $IP | sed -e 's/\./ /g'`)
    NEXT_IP_HEX=$(printf %.8X `echo $(( 0x$IP_HEX + 1 ))`)
    NEXT_IP=$(printf '%d.%d.%d.%d\n' `echo $NEXT_IP_HEX | sed -r 's/(..)/0x\1 /g'`)
    echo "$NEXT_IP"
}

# MGS
i=0
while [ $i -lt $mgs_cnt ]
do
	if [ $i -eq 0 ]; then
		mkfs.lustre --fsname=lustre --mgs /dev/vda; mount -t lustre /dev/vda /root/lustre-server
	else
		mk_cmd="mkfs.lustre --fsname=lustre --mgs /dev/vda"
		mount_cmd="mount -t lustre /dev/vda /root/lustre-server"
		sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip "$mk_cmd;$mount_cmd"
	fi
    cur_ip=$(nextip $cur_ip)
    i=$(( i + 1 ))
done

# MDS
idx=0
i=0
while [ $i -lt $mds_cnt ]
do
	mk_cmd="mkfs.lustre --fsname=lustre --index=$idx --mgsnode=$start_ip@tcp0 --mdt /dev/vda"
	mount_cmd="mount -t lustre /dev/vda /root/lustre-server"
	sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip "$mk_cmd;$mount_cmd"
    cur_ip=$(nextip $cur_ip)
    i=$(( i + 1 ))
	idx=$((idx+1))
done

# OSS
i=0
while [ $i -lt $oss_cnt ]
do
	mk_cmd="mkfs.lustre --ost --fsname=lustre --index=$idx --reformat --mgsnode=$start_ip@tcp0 /dev/vda"
	mount_cmd="mount -t lustre /dev/vda /root/lustre-server"
	sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip "$mk_cmd;$mount_cmd"
    cur_ip=$(nextip $cur_ip)
    i=$(( i + 1 ))
	idx=$((idx+1))
done

# Clients
i=0
while [ $i -lt $clt_cnt ]
do
	sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip \
		mount -t lustre $start_ip@tcp0:/lustre /root/lustre-client
	cur_ip=$(nextip $cur_ip)
    i=$(( i + 1 ))
done
