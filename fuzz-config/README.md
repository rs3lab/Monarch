# How to write a config file for distributed file systems.

The configuration file is a json file, which contains the following keys.
We illusrate the meaning of each key with an example value below:

```json
{
  // The architecture of testing VM
  "target": "linux/amd64",
  // The fuzzing workdir path, which saves the fuzzing runtime data.
  "workdir": "$MONARCH/fuzzing-dir/$DFS-dir",
  // The QEMU image
  "image": "$MONARCH/dimage-kernel/$DFS/$DFS.qcow2",
  // The SSH key used to login the VM
  "sshkey": "$MONARCH/dimage-kernel/$DFS/$DFS.id_rsa",
  // The source code location of MONARCH
  "monarch": "$MONARCH/src",
  // Enabled testing file system calls
  "enable_syscalls": ["open", "fgetxattr", ...],
  // Disabled testing syscalls
  "disable_syscalls": ["bpf$*", "mount", "ioctl$*", ...],
  // The number of testing server nodes
  "server_num": 2,
  // The number of all testing nodes
  "fuzzing_vms": 3,
  // The name of distributed file systems under test
  "dfs_name": "glusterfs",
  // The parameters for setting up the distributed file systems
  "dfs_setup_params": "2 1 ''",
  // Is the serve or client in the kernel?
  "kernel_server": false,
  "kernel_client": false,
  // Fuzzing with injected network faults.
  "net_failure": false,
  // Fuzzing with injected node crashes.
  "node_crash":  false,
  // Enable/Disable the semantic checker SYMSC
  "enable_csan": false,
  // Represent the execution states with the coverage of servers, clients, or both.
  "enable_server_feedback": true,
  "enable_client_feedback": true,
  // The resources for each testing VM.
  "vm": {
    "cmdline": "net.ifnames=0",
    // 3 VMs in total
    "count": 3,
    // 2 virtual CPUS
    "cpu": 2,
    // 10G memory
    "mem": 10240,
    // The kernel binary for booting the VM
    "kernel": "$MONARCH/dimage-kernel/$DFS/kernel-5.15-$DFS-bzImage",
  }
}
```