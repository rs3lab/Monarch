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

# MGS and MDS
i=0
while [ $i -lt $mds_cnt ]
do
	mkfs.lustre --fsname=lustre --mgs --mdt /dev/vda
	mount -t lustre /dev/vda /root/lustre-server
	i=$((i+1))
done
cur_ip=$(nextip $cur_ip)

# OSS
idx=1
i=0
while [ $i -lt $oss_cnt ]
do
	sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip \
				"\"mkfs.lustre --ost --fsname=lustre --index=$idx --reformat --mgsnode=$start_ip@tcp0 /dev/vda;\
				 mount -t lustre /dev/vda /root/lustre-server\""
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
