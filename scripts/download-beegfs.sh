echo "[+] Downloading and decompressing BeeGFS image and kernel"
wget --no-check-certificate "https://zenodo.org/records/11358529/files/beegfs.qcow2.tar.xz?download=1" -O dimage-kernel/beegfs.qcow2.tar.xz
tar -xf ./dimage-kernel/beegfs.qcow2.tar.xz -C ./dimage-kernel/beegfs/
mv ./dimage-kernel/beegfs/beegfs.qcow2 ./dimage-kernel/beegfs/focal.qcow2
