#!/bin/bash

if [ ! -d $PWD/fuzz-config ]; then
	echo "please chdir to the top level of the repo and re-execute the script"
	exit
fi

find $PWD/fuzz-config -name *.cfg -exec sed -i "s:ROOTDIR:`pwd`:g" {} +
