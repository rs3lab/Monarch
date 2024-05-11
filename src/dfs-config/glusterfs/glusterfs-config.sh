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

i=0
srvs=""    
while [ $i -lt $srv_cnt ]
do
	{
		if [ $i -eq 0 ]; then
        	systemctl restart glusterd      
			#mkfs.ext4 /dev/vda
			#mount -t ext4 /dev/vda /root/glusterfs-server -o sync
	    else
    	    sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip LD_PRELOAD=/root/dfs-fuzzing/libucov.so systemctl restart glusterd
			#sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip mkfs.ext4 /dev/vda
			#sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip mount -t ext4 /dev/vda /root/glusterfs-server -o sync
        	echo gluster peer probe $cur_ip
		gluster peer probe $cur_ip
    	fi
	}&
    srvs="${srvs} ${cur_ip}:/root/glusterfs-server"
    cur_ip=$(nextip $cur_ip)
    i=$(( i + 1 ))
done

wait

sleep 2s
gluster peer status
echo gluster volume create test-volume $mode $srvs force
#disperse 3 redundancy 1
LD_PRELOAD=/root/dfs-fuzzing/libucov.so gluster volume create test-volume $mode $srvs force
#gluster volume create test-volume $srvs force
LD_PRELOAD=/root/dfs-fuzzing/libucov.so gluster volume start test-volume force
gluster volume set test-volume network.ping-timeout 1
gluster volume set test-volume performance.open-behind off
gluster volume set test-volume performance.quick-read off
gluster volume set test-volume performance.write-behind off
gluster volume set test-volume performance.md-cache off
gluster volume set test-volume performance.flush-behind off
gluster volume set test-volume performance.stat-prefetch off
gluster volume set test-volume performance.cache-capability-xattrs off
gluster volume set test-volume performance.flush-behind off
gluster volume set test-volume performance.write-behind-trickling-writes off
gluster volume set test-volume performance.lazy-open off
gluster volume set test-volume performance.read-after-open off
gluster volume set test-volume performance.client-io-threads off
gluster volume set test-volume performance.force-readdirp off
gluster volume set test-volume performance.enable-least-priority off
#
gluster volume set test-volume features.cache-invalidation on
gluster volume set test-volume performance.cache-invalidation on

#client
i=0
while [ $i -lt $client_cnt ]
do
    #export ASAN_OPTIONS=detect_leaks=0
    sshpass -p "123456" ssh -o StrictHostKeyChecking=no root@$cur_ip mount -t glusterfs -o attribute-timeout=0,entry-timeout=0 $start_ip:/test-volume glusterfs-client &
    cur_ip=$(nextip $cur_ip)
    i=$(( i + 1 ))
done
echo "mount finished"
wait
