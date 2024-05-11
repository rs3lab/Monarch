start_ip=$1
client_cnt=$2
mount_opts=$3

nextip(){
    IP=$1
    IP_HEX=$(printf '%.2X%.2X%.2X%.2X\n' `echo $IP | sed -e 's/\./ /g'`)
    NEXT_IP_HEX=$(printf %.8X `echo $(( 0x$IP_HEX + 1 ))`)
    NEXT_IP=$(printf '%d.%d.%d.%d\n' `echo $NEXT_IP_HEX | sed -r 's/(..)/0x\1 /g'`)
    echo "$NEXT_IP"
}

sync

#Server config
exportfs -a
systemctl restart nfs-kernel-server

#Client config
cur_ip=$start_ip
cur_ip=$(nextip $cur_ip)
i=0
while [ $i -lt $client_cnt ]
do
    sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip mount -t nfs -o vers=4.2,timeo=1,retrans=1,soft,$mount_opts $start_ip:/ /root/nfs-client &
    cur_ip=$(nextip $cur_ip)
    i=$(( i + 1 ))
done
wait
