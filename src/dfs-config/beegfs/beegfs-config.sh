#args
start_ip=$1
manage_cnt=$2
meta_cnt=$3
storage_cnt=$4
clt_cnt=$5

cur_ip=$start_ip

nextip(){
    IP=$1
    IP_HEX=$(printf '%.2X%.2X%.2X%.2X\n' `echo $IP | sed -e 's/\./ /g'`)
    NEXT_IP_HEX=$(printf %.8X `echo $(( 0x$IP_HEX + 1 ))`)
    NEXT_IP=$(printf '%d.%d.%d.%d\n' `echo $NEXT_IP_HEX | sed -r 's/(..)/0x\1 /g'`)
    echo "$NEXT_IP"
}


# Management server
/root/beegfs-v7/mgmtd/build/dist/sbin/beegfs-setup-mgmtd -p /root/beegfs-server/beegfs_mgmtd
systemctl start beegfs-mgmtd
systemctl status beegfs-mgmtd
sync
cur_ip=$(nextip $cur_ip)

# Metasdata server
i=0
while [ $i -lt $meta_cnt ]
do
	sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip "/root/beegfs-v7/meta/build/dist/sbin/beegfs-setup-meta -p /root/beegfs-server/beegfs_meta -s $((i+1)) -m $start_ip; systemctl start beegfs-meta; systemctl status beegfs-meta; sync"
	cur_ip=$(nextip $cur_ip)
	i=$(( i + 1 ))
done

# Storage server
i=0
while [ $i -lt $storage_cnt ]
do
	sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip "/root/beegfs-v7/storage/build/dist/sbin/beegfs-setup-storage -p /root/beegfs-server/beegfs_storage -s $((i+1)) -i $(((i+1)*100+(i+1))) -m $start_ip; systemctl start beegfs-storage; systemctl status beegfs-storage; sync"
	cur_ip=$(nextip $cur_ip)
	i=$(( i + 1 ))
done

# Client
i=0
while [ $i -lt $clt_cnt ]
do
	sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip "/root/beegfs-v7/client_module/build/dist/sbin/beegfs-setup-client -m $start_ip; systemctl start beegfs-helperd; systemctl status beegfs-helperd; sleep 20; systemctl start beegfs-client; systemctl status beegfs-client; sync"
	cur_ip=$(nextip $cur_ip)
	i=$(( i + 1 ))
done
