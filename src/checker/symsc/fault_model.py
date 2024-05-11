import common as c
import syscalls
import os
import pdb
import subprocess
import re

def is_available(syscall, argv):
    if c.FSTYPE == "nfs":
        return nfs()
    elif c.FSTYPE == "glusterfs":
        return glusterfs(syscall, argv)
    elif c.FSTYPE == "cephfs":
        return cephfs(syscall, argv)
    else:
        return True


#####################################################################
#                               NFS                                 #
#####################################################################

def nfs():
    # If server node is down, no availability
    # Otherwise, available
    if c.NODESTATE[0] == "down":
        print("node {} is down".format(c.CURNODE))
        return False
    # If the connection between client and server is disconnected,
    # unavailible
    if (0, c.CURNODE) in c.NETSTATE:
        print("node {} is partioned".format(c.CURNODE))
        return False
    
    return True


#####################################################################
#                          GlusterFS                                #
#####################################################################

# Import gf_dm_hashfn as the consistent hashing algorithm
import ctypes
libdir = os.path.dirname(os.path.abspath(__file__))
lib = ctypes.CDLL(libdir+'/fault_models/libhash.so')

def get_consistent_hash(filename, size):
    return (lib.gf_dm_hashfn("/", 1) & 0xffffffff )

def glusterfs_init_vol(srv_nodes_cnt, mode, init_ip):

    c.FSCFG["srv_nodes_cnt"] = srv_nodes_cnt
    c.FSCFG["quorum"] = 0.51
    vol_cnt = 0

    mode = mode.replace("'", "").split(" ")[2:]

    if "redundancy" in mode:
        c.FSCFG["redundancy"] = int(mode[3])

    mode = " ".join(mode)
    print("mode", mode)
    if mode == "":
        c.FSCFG["mode"] = "distributed"
        vol_cnt = srv_nodes_cnt
    elif "replica" in mode or "disperse" in mode:
        if "replica" in mode:
            c.FSCFG["mode"] = "replica"
        elif "disperse" in mode:
            c.FSCFG["mode"] = "disperse"
        subvol_cnt_per_group = int(mode.split(" ")[1])
        vol_cnt = srv_nodes_cnt / subvol_cnt_per_group
        c.FSCFG["subvol_groups"] = list()
        srv_node_ids = [i for i in range(srv_nodes_cnt)]
        for i in range(vol_cnt):
            start = i * subvol_cnt_per_group
            end = (i+1) * subvol_cnt_per_group
            c.FSCFG["subvol_groups"].append(srv_node_ids[start:end])
    else:
        print("WARNING: no matched glusterfs mode")

    print("vol_cnt", vol_cnt)
    start_vol = get_consistent_hash("/", 1)  % vol_cnt
    chunk = 0xffffffff / vol_cnt
    c.FSCFG["lalive_nodesyout"] = [()]*vol_cnt
    # TODO: more accurate
    c.FSCFG["layout"] = [(0,0)]*vol_cnt
    for i in range(vol_cnt):
        idx = (i + start_vol) % vol_cnt
        c.FSCFG["layout"][idx] = (chunk*i, chunk*(i+1)-1)

    c.FSCFG["init_ip"] = init_ip

def glusterfs(syscall_name, argv):

    '''
        Special cases:
        1. close/dup/dup2 doesn't care about the faults as it operates locally.
        2. TODO: sync()/syncfs(): some files are not show on the clients but sync succeeds.
        3. symlink: if op needs targets, the nodes storing the target file and all intermediate paths need to be alive. Otherwise, only the symlink need to be alive.
        4. link: only the node storing the filename used to create the inode need to be alive.
    '''

    filenames, filepaths = get_involved_filenames(syscall_name, argv)
   
    # Check the health of nodes storing each filename
    for filename in filenames:
        if glusterfs_can_op_success(filename) == False:
            return False

    return True


def live_nodes(client_node, target_nodes, ret_ratio=True):

    live = 0
    for node in target_nodes:
        if c.NODESTATE[node] == "up" and \
            (client_node, node) not in c.NETSTATE and \
            (node, client_node) not in c.NETSTATE:
            live += 1
    if ret_ratio:
        return live/float(len(target_nodes))
    else:
        return live

def glusterfs_can_op_success(filename):
    # Storage node assignment => consistent hashing gf_dm_hashfn()
    hash_val = get_consistent_hash(filename, len(filename))
    target_vol = 0
    for idx, disk in enumerate(c.FSCFG["layout"]):
        if disk[0] <= hash_val and disk[1] >= hash_val:
            target_vol = idx
            break

    if c.FSCFG["mode"] == "distributed":
        # The only target node should exist.
        if c.NODESTATE[target_vol] == "down":
            return False
        if (target_vol, c.CURNODE) in c.NETSTATE:
            return False
    elif c.FSCFG["mode"] == "replica":
        # The number of fault nodes should be less than quorum.
        target_nodes = c.FSCFG["subvol_groups"][target_vol]
        live_ratio = live_nodes(c.CURNODE, target_nodes)
        if live_ratio < c.FSCFG["quorum"]:
            return False
    elif c.FSCFG["mode"] == "disperse":
        # The number of fault nodes should be less than the "redundancy".
        target_nodes = c.FSCFG["subvol_groups"][target_vol]
        fault_nodes = len(target_nodes) - live_nodes(c.CURNODE, target_nodes)
        if fault_nodes > c.FSCFG["redundancy"]:
            return False
    
    return True


#####################################################################
#                            CephFS                                 #
#####################################################################

def cephfs(syscall_name, argv, offset=0, min_osds=1):
    
    '''
        Decide pools corresponding to this syscall.
        # ??? "readlink", "symlink", "truncate", "ftruncate", "fsync", "sync", "fdatasync", "syncfs", "fallocate", "utimes",
    '''

    ino = 0x10000000000

    metadata_pool, data_pool = None, None
    metadata_offset, data_offset = 0, offset

    syscall_name = syscall_name.replace("SYS_", "")

    if syscall_name in ["close", "dup", "dup2", "lseek"]:
        return True

    # Data only operation
    elif syscall_name in ["read", "pread64"]:
        data_pool = 2
    # Metadata only operation
    elif syscall_name in ["mkdir", "rmdir", "rename", "link", "unlink", "open",\
        "chmod", "setxattr", "removexattr", "listxattr", "llistxattr", \
        "flistxattr", "lremovexattr", "fremovexattr", "lsetxattr", "fsetxattr",\
        "fchmod", "lgetxattr", "fgetxattr", "getxattr", "stat", "fstat", \
        "getdents"]:
        metadata_pool = 1
    # Both data and metadata -> ["write", "pwrite64", "symlink"]
    else:
        metadata_pool = 1
        data_pool = 2

    # Generate cmds for change osdmap state
    node_stats = ""
    for i, stat in enumerate(c.NODESTATE):
        if stat == "down":
            node_stats += "--mark-down {}".format(i)

    filenames, filepaths = get_involved_filenames(syscall_name, argv)

    for filepath in filepaths:

        ino = 0
        if filepath not in c.DENTRY:
            if syscall_name == "open" and int(argv[2]) & c.O_CREAT or \
               syscall_name == "mkdir":
                ino = c.INODE_CNT
            else:
                continue
        else:
            ino = c.DENTRY[filepath]

        # Calcuate corresponding osds based on the osdmap state
        raw_mds_osds, act_mds_osds = \
                    inode2osds(ino, node_stats, metadata_pool, metadata_offset)
        raw_data_osds, act_data_osds = \
                    inode2osds(ino, node_stats, data_pool, data_offset)

        # FAULT MODEL
        # Rule-1: Monitor must online.
        # Question, does every op need contacing the monitor?
        if c.NODESTATE[0] == 'DOWN':
            return False

        if metadata_pool != None:
            # Rule-2: MDS must exist for metadata ops.
            # Rule-3: MDS must be able to communicate with at least N osds
            if live_nodes(c.CURNODE, [c.FSCFG["mds"][0]]) != 1:
                return False
            if live_nodes(c.FSCFG["mds"][0], raw_mds_osds, False) < min_osds:
                return False

        if data_pool != None:
            # Rule-3: client must be able to communicate with at least N osds
            if live_nodes(c.CURNODE, raw_data_osds, False) < min_osds:
                return False

    return True


def cephfs_init(mode, testdir_ino, init_ip):

    mon, osd, mds, clt = [int(i) for i in mode.split(" ")]
    c.FSCFG["mon"] = 0
    c.FSCFG["osd"] = [i for i in range(mon, mon+osd)]
    c.FSCFG["mds"] = [i for i in range(mon+osd, mon+osd+mds)]
    c.FSCFG["clt"] = [i for i in range(mon+osd+mds, mon+osd+mds+clt)]
    comb = "-{}-{}-{}".format(c.FSCFG["mon"], c.FSCFG["osd"], c.FSCFG["mds"])
    c.FSCFG["osdmap"] = os.path.join(libdir, "osdmap-"+comb+".txt")
    c.INODE_CNT = testdir_ino
    c.FSCFG["init_ip"] = init_ip

def inode2osds(ino, node_stats, pool, offset=0):

    '''
        Calculate the corresponding OSDs.
        oid = (ino, ono)
        pgid = hash(oid) % mask
        osds = crush(pgid)
    '''

    if pool == None:
        return list(), list()

    oid = "{:x}.{:08x}".format(ino, offset/(4194304)) #4MB
    print("oid", oid)

    pg_seed = lib.ceph_str_hash_rjenkins(oid, len(oid)) & 0xffffffff
    print("init pg_seed", "{:x}".format(pg_seed))

    # Mod pgid->see to not exceed the number of all pgs
    pg_num = 32
    pg_num_mask = 2**(pg_num.bit_length()-1) - 1
    if (pg_seed & pg_num_mask) < pg_num:
        pg_seed &= pg_num_mask
    else:
        pg_seed &= (pg_num_mask >> 1)
    print("mod pg_seed", "{:x}".format(pg_seed))

    # PGID
    pgid = "{}.{:x}".format(pool, pg_seed)
    print("pgid", pgid)

    cmd = "LD_PRELOAD='{}/fault_models/libceph-common.so.2' \
     {}/fault_models/osdmaptool {} --test-map-pg {} {}".format(\
     libdir, libdir, node_stats, pgid, c.FSCFG["osdmap"])

    print(cmd)
    # Execute command    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, \
    stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    process.wait()
    output = output.decode('utf-8')
    err = error.decode('utf-8')

    print("output:", output)

    # 1.1c raw ([3], p3) up ([], p-1) acting ([], p-1)
    pattern = r'(\[[0-9,]*])'
    matches = re.findall(pattern, output)

    raw_osds, up_osds, acting_osds = list(), list(), list()
    if len(matches) == 3:
        raw_osds = [int(i) for i in matches[0][1:-1].split(",")] 
        up_osds = [int(i) for i in matches[1][1:-1].split(",")]
        acting_osds = [int(i) for i in matches[2][1:-1].split(",")]

    # up_osds
    return (raw_osds, acting_osds)


def get_involved_filenames(syscall_name, argv):

    filenames, filepaths = [], []
    # One fd
    if syscall_name in ["SYS_ftruncate",
                        "SYS_fsync",
                        "SYS_fdatasync",
                        "SYS_write",
                        "SYS_pwrite64",
                        "SYS_read",
                        "SYS_pread64",
                        "SYS_lseek",
                        "SYS_fallocate",
                        "SYS_fchmod",
                        "SYS_fsetxattr",
                        "SYS_fremovexattr",
                        "SYS_flistxattr",
                        "SYS_fgetxattr",
                        "SYS_getdents",
                        "SYS_fstat"]:
        fd = argv[0]
        varname = fd.replace("(long)", "")
        inode = syscalls._get_inode_of_fd(fd)
        if inode != -1:
            # Using inode.path instead of inode.name is because:
            # after unlink, it will remove inode.name.
            # If we then use a fd pointing to that inode,
            # inode.name is empty and thus code will crash.
            filename = syscalls._get_name(inode.path[0])
            filenames.append(filename)
            filepaths.append(inode.path[0])
    
    # One filename
    elif syscall_name in ["SYS_mkdir",
                        "SYS_rmdir",
                        "SYS_truncate",
                        "SYS_unlink",
                        "SYS_open",
                        "SYS_utime",
                        "SYS_readlink",
                        "SYS_chmod",
                        "SYS_setxattr",
                        "SYS_lsetxattr",
                        "SYS_removexattr",
                        "SYS_lremovexattr",
                        "SYS_listxattr",
                        "SYS_llistxattr",
                        "SYS_getxattr",
                        "SYS_lgetxattr",
                        "SYS_stat",
                        "SYS_lstat"]:
        path = syscalls._get_path(argv[0])
        if path != None:
            # Get the inode of the specified path
            # Skip if the file hasn't been created
            try:
                id = c.DENTRY[path]
                inode = c.MEM[id]
                # If symlink and not accessing symlink itself, resolve it
                if inode.type == c.SYMLINK and\
                             syscall_name not in ["SYS_unlink",
                                                "SYS_readlink",
                                                "SYS_lsetxattr",
                                                "SYS_lremovexattr",
                                                "SYS_llistxattr",
                                                "SYS_lgetxattr",
                                                "SYS_lstat"]:
                    recursive_paths = list()
                    _, target_inode = syscalls._resolve_symlink_path(path,\
                    inode, recursive_paths)
                    if target_inode != -1:
                        all_sym_paths = recursive_paths[:-1]
                        all_sym_paths = [syscalls._get_name(path) for path in all_sym_paths]
                        target_file = syscalls._get_name(target_inode.name[0])
                        filenames += all_sym_paths.append(target_file)
                        filepaths += recursive_paths
                else:
                    # Get the first path of this inode incase multiple links
                    filepaths.append(inode.path[0])
                    filenames.append(inode.name[0])
            except KeyError:
                filepaths.append(path)
                filenames.append(syscalls._get_name(path))    

    # Two filenames
    elif syscall_name in ["SYS_rename",
                          "SYS_link",
                          "SYS_symlink"]:
        # Get the inode of the first path,
        # incase it's a multiply-linked inodes
        path1 = syscalls._get_path(argv[0])
        inode = None
        if path1 != None:
            try:
                id = c.DENTRY[path1]
                inode = c.MEM[id]
                filepaths.append(inode.path[0])
                filenames.append(syscalls._get_name(inode.name[0]))
            except KeyError:
                filepaths.append(path1)
                filenames.append(syscalls._get_name(path1))

        path2 = syscalls._get_path(argv[1])
        if path2 != None:
            filepaths.append(path2)
            filenames.append(syscalls._get_name(path2))

    return (filenames, filepaths)
