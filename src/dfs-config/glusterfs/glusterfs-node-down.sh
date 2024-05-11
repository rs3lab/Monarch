ps -aux|grep sbin/gluster|awk '{print $2}'|while read line ; do kill $line; done
