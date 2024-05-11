#!/bin/bash -i

if [ ! -d $PWD/fuzz-config ]; then
    echo $PWD/fuzz-config
    echo "please chdir to the top level of the repo and re-execute the script"
    exit
fi

# Install go
mkdir go-env
pushd go-env
wget --no-check-certificate https://dl.google.com/go/go1.17.6.linux-amd64.tar.gz
tar -xf go1.17.6.linux-amd64.tar.gz
GOROOT=`pwd`/go
GOPATH=`pwd`/gopath
mkdir $GOPATH
echo "export GOROOT=$GOROOT" >> ~/.bashrc
echo "export PATH=$GOROOT/bin:$PATH" >> ~/.bashrc
echo "export GOPATH=$GOPATH" >> ~/.bashrc
source ~/.bashrc
popd

go_ver=$(go version)
if [[ $go_ver != "go version go1.17.6 linux/amd64" ]]; then
	echo "go env is not installed correctly.
		If you have already set the GOROOT and GOPATH in your ~/.bashrc.
		Please temporally comment out them and re-execute source ~/.bashrc."
	exit
fi

# Install dependencies
sudo apt-get update
sudo apt-get -y install libboost-dev
sudo apt-get -y install g++-9
sudo apt-get -y install gcc-9
sudo apt-get -y install qemu-system
sudo apt-get -y install wget
sudo apt-get -y install xz-utils
sudo apt-get -y install libz-dev
sudo apt-get -y install gnuplot

# Enable the bridge network
sudo scripts/enable-br0.sh
