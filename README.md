<h1> Monarch: <br /> A Fuzzing Framework for Distributed File Systems </h1>


## Overview

**Monarch** is the first multi-node fuzzing framework for
finding memory and semantic bugs in POSIX-compliant distributed file systems (DFSes),
through the following novel designs:

- Testing all cross-node and cross-context components of DFSes holistically
(*Central controller* and *Per-node executor*);
- Testing from both explicit inputs *syscalls* and implicit inputs *faults* (*Two-step mutator*);
- Adopting practical execution state representations in the distributed scenario
(*Instrumentation* and *Coverage collection*);
- Designing a semantic checker *SymSC* for capturing all types of semantic bugs in DFSes.


This repo includes the source code and documentation of Monarch.
Its organization is illustrated below:
```
Monarch
   |------ src                  ; Source code of Monarch
   |        |---- syz-fuzzer    ; Central controller
   |        |---- executor      ; Per-node executor and coverage collection
   |        |---- prog          ; Two-step mutator
   |        |---- instrument    ; Instrumentation
   |        |---- checker       ; The checker SYMSC
   |        
   |------ scripts       ; Scripts for setting up the running environment.
   |------ fuzz-config   ; Fuzzing configurations for six distributed file systems.
   |------ bugs          ; The logs and information of newly found bugs.
   |------ dimage-kernel ; Downloaded QEMU image and kernels of each DFSes (created when downloading).
   |------ fuzzing-dir   ; The runtime data of fuzzing instances.
   |------ README.md
```

## Environment setup

### Download the Monarch repo

```bash
git clone https://github.com/rs3lab/Monarch.git
pushd Monarch
```

### Install the dependencies and enable the bridge network

Run the script below to download the Golang compiler and other dependent tools and libraries.
The Golang compiler is downloaded into a self-created `go-env` directory and
the script automatically sets the `GOROOT` go `GOPATH` environment variables.

```bash
./scripts/env.sh
```

### Compile Monarch

```bash
pushd src
CC="gcc-9" CXX="g++-9" make
popd
```

### Download ready-to-use QEMU images and kernels

As Monarch utilizes VM-based testing design,
we have to install DFSes into virtual machines,
including QEMU images and kernels.

It is tedious and error-prone to compile, instrument and install DFSes.
Thus,
we uploaded the ready-to-use QEMU images and kernels on [zenodo](https://zenodo.org/records/11176798?token=eyJhbGciOiJIUzUxMiJ9.eyJpZCI6IjUwOGY4MjU5LWY1ZjQtNDc4OS1hYzM2LThkZDYzNWY3MzMwNyIsImRhdGEiOnt9LCJyYW5kb20iOiI3ZTYzNzkxMjA1NDQ5NTI1OTFiNDAyOTY0N2ZhYWUxZCJ9.2p9dcAjNo82ANhGR_ZE1_yqrKE0tNCdMoYvcq2uFmt1o-9l1xLLy42-NUaL_ANYW5DSW45XY4-QNuV5zZom2zw).

Run the below command to download and decompress them into the `dimage-kernel` directory.
It includes six sub-directories,
each containing a QEMU image and kernel binary of one DFS.

> Notably,
> the images and kernels occupy a large amount of storage space (around 42GB), and
> it takes time to download and decompress (10-30 minutes).

```bash
./scripts/download.sh
```

## Run evaluations

### How to run Monarch on a distributed file system?

If you have finished all the preparations above,
the only left step is to create a configuration file `config.cfg` and
pass it to Monarch like below:

```bash
# Note: you don't need to execute this command.
# It's just an execution example.
./src/bin/syz-manager -config config.cfg
```

The `-config` option specifies the parameters of the fuzzing instance,
such as the QEMU image and kernel path, the number of virtual CPUs, and memory.
A detailed introduction can be found [here](./fuzz-config/README.md).

We have provided a set of configurations [here](./fuzz-config/).
Before using them, you have to run the following command to complete the absolute paths to downloaded kernels,
QEMU images, and Monarch source code.
```bash
./scripts/complete-cfg.sh
```

Now, pick up one of the configurations and run Monarch with it. For example,
```bash
$ sudo ./src/bin/syz-manager -config fuzz-config/eval-config/non-fault-mode/nfs/nfs-c-normal.cfg
2024/05/08 21:35:51 loading corpus...
2024/05/08 21:35:51 serving http on http://x.x.x.x:2552
...
2024/05/11 14:28:37 executed 436, ....
```

As the example shows,
you will see the following output in the terminal after starting.
Click on the link (`http://x.x.x.x:2552`) to see the fuzzing status,
including coverage, speed, and reported bugs.

If you can see the `executed xxx` from the terminal,
it means the Monarch is running successfully.
Now, you can continue the following evaluations.

> **Note**: Once you start a fuzzing instance, it keeps running until you manually stop (CTRL+C or KILL) it.

### Bug-finding (Section 5.1)

As we discussed in the *"Bug characteristics"* paragraph in Section 5.1,
bugs might only exposed in specific configurations,
e.g., a specific number of nodes.
To reproduce all the bugs we found,
we provide all the fuzzing configurations we used [here](./fuzz-config/all-config/).

For any configuration file *X.cfg*,
you only need to run Monarch with it using the following command:

```bash
sudo ./src/bin/syz-manager -config X.cfg
```

Because fuzzing is dynamic testing with stochastic search,
some bugs are exposed quickly (e.g., several minutes)
while some need longer time, even several weeks,
which becomes difficult to reproduce in the limited artifact evalutation period.
To show we did find these bugs listed in the paper,
we attach [the list of bug logs and their information](./bugs/README.md) produced by Monarch previously.


### DFS Execution State Representation (Section 5.2)

To find out the most practical approach to representing execution states,
we compare the finally achieved coverage in fault and non-fault modes,
when the execution states of each distributed file system in Monarch are represented by
1) both server and client coverage (cs);
2) server coverage only (s);
3) client coverage only (c);

In other words,
you need to run each distributed file system (six DFSes in total) with six fuzzing configurations
(3 representations in both fault and non-fault modes)
and each for 48 hours (72 hours for GlusterFS).

We provide a script [`scripts/eval-exec-state.sh`](./scripts/eval-exec-state.sh)
to automatically boot each fuzzing instance.
It supports evaluating one or all distributed file systems with their six configurations as background processes.
See the command below.
```bash
# Checkout the usage
./scripts/eval-exec-state.sh -h
# Evaluate NFS only
sudo ./scripts/eval-exec-state.sh -d nfs
# Evaluate all distributed file systems
sudo ./scripts/eval-exec-state.sh -a
```

> **Note: If your per-server computing resources are limited,
> we strongly suggest evaluating DFSes individually with the `-d` option.**

If you want to kill the instances of one DFS,
run the following command with the DFS name (e.g., nfs, glusterfs, cephfs, lustre, orangefs, beegfs).
```bash
./scripts/kill-a-dfs-eval.sh DFSNAME
```


After running each fuzzing instance 48/72 hours,
you can execute the command below to generate a pdf located at `fuzzing-dir/cov-regen-fig.pdf`, 
containing the coverage growth trend like Figure 8 in the paper.
```bash
./scripts/visualize-cov.sh --regenerated
```

As the evaluation requires too much computing resources and time,
we also provide our evaluation data in `fuzzing-dir/cov`.
Run the following command to see the coverage growth trend in a pdf file named `fuzzing-dir/cov-org-fig.pdf`.
```bash
./scripts/visualize-cov.sh --original
```

## Contact

If you have any questions or suggestions,
feel free to reach out to us at (tao.lyu@epfl.ch).
