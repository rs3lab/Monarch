#args
start_ip=$1
srv_cnt=$2
client_cnt=$3
mode=$4

cur_ip=$start_ip

nextip(){
    IP=$1
    IP_HEX=$(printf '%.2X%.2X%.2X%.2X\n' `echo $IP | sed -e 's/\./ /g'`)
    NEXT_IP_HEX=$(printf %.8X `echo $(( 0x$IP_HEX + 1 ))`)
    NEXT_IP=$(printf '%d.%d.%d.%d\n' `echo $NEXT_IP_HEX | sed -r 's/(..)/0x\1 /g'`)
    echo "$NEXT_IP"
}

#env_cmd="export ASAN_OPTIONS=\"allow_user_segv_handler=0:log_path=/home/tlyu/trash/daemon-log:detect_leaks=0:verify_asan_link_order=0\""
env_cmd="export ASAN_OPTIONS=\"detect_leaks=0:verify_asan_link_order=0:log_path=/root/daemon-log\""
#env_cmd="ls"

# Config cmd
# Gen ips
srv_ips=$start_ip
srv_ip=$start_ip
i=0
while [ $i -lt $((srv_cnt-1)) ]
do
	srv_ip=$(nextip $srv_ip)
	srv_ips="$srv_ips,$srv_ip"
	i=$((i+1))
done

# Servers
i=0
while [ $i -lt $srv_cnt ]
do
	srv_cmd1="/opt/orangefs/sbin/pvfs2-server -f -a $cur_ip /opt/orangefs/etc/orangefs-server.conf"
	srv_cmd2="/opt/orangefs/sbin/pvfs2-server -a $cur_ip /opt/orangefs/etc/orangefs-server.conf"
	if [ $i -eq 0 ]; then
		/opt/orangefs/bin/pvfs2-genconfig --quiet --protocol tcp --ioservers $srv_ips --metaservers $srv_ips /opt/orangefs/etc/orangefs-server.conf
		$srv_cmd1
		$srv_cmd2
	else
		sshpass -p "123456" scp -o StrictHostKeyChecking=no /opt/orangefs/etc/orangefs-server.conf root@$cur_ip:/opt/orangefs/etc/orangefs-server.conf
		sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip "$env_cmd; $srv_cmd1; $srv_cmd2; sync"
	fi
	cur_ip=$(nextip $cur_ip)
	i=$(( i + 1 ))
done

# Clients
i=0
while [ $i -lt $client_cnt ]
do
	clt_cmd="/opt/orangefs/bin/pvfs2fuse /root/orangefs-client -o fs_spec=tcp://$start_ip:3334/orangefs"
	sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip "$env_cmd; $clt_cmd; sync"
	cur_ip=$(nextip $cur_ip)
	i=$(( i + 1 ))
done

sync
