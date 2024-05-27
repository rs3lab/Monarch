#!/bin/bash

if [[ $# -eq 0 ]]; then
	echo "Usage: scripts/kill-a-dfs-eval.sh [nfs|glusterfs|cephfs|lustre|orangefs|beegfs]"
	exit
fi

sudo kill -INT $(ps -aux|grep syz-manage|grep $1 |awk '{print $2}')
