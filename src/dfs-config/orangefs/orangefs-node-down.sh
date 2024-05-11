ps -aux|grep "pvfs2-"|awk '{print $2}'|while read line ; do kill $line; done
