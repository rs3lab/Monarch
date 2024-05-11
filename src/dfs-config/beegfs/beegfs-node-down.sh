ps -aux|grep "beegfs-"|awk '{print $2}'|while read line ; do kill $line; done
