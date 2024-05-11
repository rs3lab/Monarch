#!/bin/bash

if [ ! -d $PWD/fuzz-config ]; then
    echo $PWD/fuzz-config
    echo "please chdir to the top level of the repo and re-execute the script"
    exit
fi

avail_space=$(df --output=avail $PWD | tail -n 1)
avail_gb=$((avail_space / 1024 / 1024))

if [ "$avail_gb" -lt 45 ]; then
	echo "Available disk space is less than 45GB and cannot hold the downloaded and decompressed images and kernels."
	exit
fi

if [[ ! -d ./dimage-kernel ]]; then
	mkdir ./dimage-kernel
fi

echo "[+] Downloading and decompressing data image"
wget --no-check-certificate "https://zenodo.org/records/11176798/files/data.img.tar.xz?download=1" -O dimage-kernel/data.img.tar.xz
tar -xf ./dimage-kernel/data.img.tar.xz -C ./dimage-kernel

echo "[+] Downloading and decompressing NFS QEMU image and kernel"
wget --no-check-certificate "https://zenodo.org/records/11176798/files/nfs.tar.xz?download=1" -O dimage-kernel/nfs.tar.xz 
tar -xf ./dimage-kernel/nfs.tar.xz -C ./dimage-kernel

echo "[+] Downloading and decompressing Glustersfs image and kernel"
wget --no-check-certificate "https://zenodo.org/records/11176798/files/glusterfs.tar.xz?download=1" -O dimage-kernel/glusterfs.tar.xz
tar -xf ./dimage-kernel/glusterfs.tar.xz -C ./dimage-kernel

echo "[+] Downloading and decompressing Orangefs image and kernel"
wget --no-check-certificate "https://zenodo.org/records/11176798/files/orangefs.tar.xz?download=1" -O dimage-kernel/orangefs.tar.xz
tar -xf ./dimage-kernel/orangefs.tar.xz -C ./dimage-kernel

echo "[+] Downloading and decompressing Lustre image and kernel"
wget --no-check-certificate "https://zenodo.org/records/11176798/files/lustre.tar.xz?download=1" -O dimage-kernel/lustre.tar.xz
tar -xf ./dimage-kernel/lustre.tar.xz -C ./dimage-kernel

echo "[+] Downloading and decompressing BeeGFS image and kernel"
wget --no-check-certificate "https://zenodo.org/records/11176798/files/beegfs.tar.xz?download=1" -O dimage-kernel/beegfs.tar.xz
tar -xf ./dimage-kernel/beegfs.tar.xz -C ./dimage-kernel

echo "[+] Downloading and decompressing CephFS image and kernel"
wget --no-check-certificate "https://zenodo.org/records/11176798/files/cephfs.tar.xz?download=1" -O dimage-kernel/cephfs.tar.xz
tar -xf ./dimage-kernel/cephfs.tar.xz -C ./dimage-kernel
