#!/bin/bash -i

display_help() {
	echo "Usage: $0 [options]"
	echo "Options:"
	echo "  -h, --help       Display this help message"
	echo "  -a, --all        Eval the execution state representation of 6 DFSes in fault and non-fault mode"
	echo "  -d, --dfs        Eval the execution state of representation of one DFS in fault and non-fault mode"
}

if [ ! -d $PWD/fuzz-config ]; then
    echo "please chdir to the top level of the repo and re-execute the script"
    exit
fi

nonfault_cfgs=$PWD/fuzz-config/eval-config/non-fault-mode
fault_cfgs=$PWD/fuzz-config/eval-config/fault-mode
dfses=("nfs" "glusterfs" "cephfs" "lustre" "orangefs" "beegfs")

if [[ "$1" == "-a" || "$1" == "--all" ]]; then

	for dfs in "${dfses[@]}"; do
		for cfg in $(ls $nonfault_cfgs/$dfs); do
			sudo $PWD/src/bin/syz-manager -eval -config $nonfault_cfgs/$dfs/$cfg >/dev/zero 2>&1 &
		done
		for cfg in $(ls $fault_cfgs/$dfs); do
			sudo $PWD/src/bin/syz-manager -eval -config $fault_cfgs/$dfs/$cfg >/dev/zero 2>&1 &
		done
	done

elif [[ "$1" == "-d" || "$1" == "--dfs" ]]; then

	dfs=$2
	for cfg in $(ls $nonfault_cfgs/$dfs); do
		sudo $PWD/src/bin/syz-manager -eval -config $nonfault_cfgs/$dfs/$cfg >/dev/zero 2>&1 &
		sleep 10s
	done
	for cfg in $(ls $fault_cfgs/$dfs); do
		sudo $PWD/src/bin/syz-manager -eval -config $fault_cfgs/$dfs/$cfg >/dev/zero 2>&1 &
		sleep 10s
	done

else
	display_help
	exit 0
fi
