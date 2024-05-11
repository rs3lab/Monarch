ps -aux|grep ceph-|awk '{print $2}'|while read line ; do kill $line; done
