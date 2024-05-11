#!/bin/bash

display_help() {
	echo "Usage: $0 [options]"
	echo "Options:"
	echo "  -h, --help       Display this help message"
	echo "  --original       Draw Figure 8 in the paper with the original data."
	echo "  --regenerated    Draw Figure 8 in the paer with the newly collected data."
}

if [ ! -d $PWD/fuzz-config ]; then
	echo "please chdir to the top level of the repo and re-execute the script"
	exit
fi

if [[ "$1" == "--original" ]]; then
	OUT=$PWD/fuzzing-dir/cov-org-fig.pdf TARGET=pdf gnuplot $PWD/fuzzing-dir/cov/cov.gp
elif [[ "$1" == "--regenerated" ]]; then
	OUT=$PWD/fuzzing-dir/cov-regen-fig.pdf TARGET=pdf gnuplot $PWD/fuzzing-dir/cov/cov-regen.gp
else
	display_help
	exit
fi
