import copy

import common as c
import syscalls
import utils
import checker
import depcalls
import pdb

'''
Get the next file operation with the smallest starting timestamp.
And update the seq_programs by removing that popped operation.
'''
def get_next_op(seq_programs):
    new_seq_programs = copy.deepcopy(seq_programs)
    idx_of_min_stime = -1
    min_stime = 0
    for i in range(len(seq_programs)):
        prog = seq_programs[i]
        if len(prog) == 0:
            continue
        op = prog[0]
        print("op:", op, seq_programs)
        if idx_of_min_stime == -1 or c.runtime_state[op]["Stime"] < min_stime:
            min_stime = c.runtime_state[op]["Stime"]
            idx_of_min_stime = i

    if idx_of_min_stime != -1:
        prog = new_seq_programs[idx_of_min_stime]
        return prog[0], idx_of_min_stime
    else:
        return None, -1

def remove_one_op(seq_programs, op):
    new_seq_programs = copy.deepcopy(seq_programs)
    for i in range(len(new_seq_programs)):
        if op in new_seq_programs[i]:
            new_seq_programs[i].remove(op)
    return new_seq_programs

def get_path_fd(state, call_name, call_argv, call_ret):

    fds = list()
    paths = list()

    # One fd as a argument
    if call_name.startswith("f") or \
    call_name == ["getdents", "read", "pread64", "write", "pwrite64", "lseek"]:
        fd, path = syscalls._get_inode_of_fd_from_state(call_argv[0], state)
        fds.append(fd)
        paths += path
    
    # One fd as a return value
    elif call_name in ["open"]:
        fds.append(call_ret)
        paths.append(syscalls._get_raw_path_from_state(call_argv[0], state))

    # Two fds
    elif call_name in ["close", "dup", "dup2"]:
        fd1, path1 = syscalls._get_inode_of_fd_from_state(call_argv[0], state)
        fd2, path2 = syscalls._get_inode_of_fd_from_state(call_ret, state)
        fds += [fd1, fd2]
        paths += path1
        paths += path2

    # Two file names
    elif call_name in ["rename", "link", "symlink"]:
        paths += [syscalls._get_raw_path_from_state(call_argv[0], state),\
                  syscalls._get_raw_path_from_state(call_argv[1], state)]
        print("link path", paths)

    # One file name
    else:
        paths.append(syscalls._get_raw_path_from_state(call_argv[0], state))
    
    new_paths = list()
    new_paths += paths

    # Resolve the path if it's symlink for the below calls
    if call_name in ["open", "open_create", "setxattr", "listxattr", \
    "removexattr", "getxattr", "chmod", "truncate"]:
        for path in paths:
            if path in c.DENTRY:
                inode_id = c.DENTRY[path]
                inode = None
                if inode_id in c.MEM:
                    inode = c.MEM[inode_id]
                elif inode_id in c.DISK:
                    inode = c.DISK[inode_id]
                if inode != None:
                    syscalls._resolve_symlink_path(path, inode, new_paths)

    return new_paths, fds

# sort syscall in get_syscall_name_path
# label open with O_CREAT as open_create
# return call,paths,fds,
def get_syscall_name_path(state, call_idx1, call_idx2):
    
    call_info1 = c.SYSCALL_STACK[call_idx1]
    call1 = call_info1[0].replace("SYS_", "")

    call_info2 = c.SYSCALL_STACK[call_idx2]
    call2 = call_info2[0].replace("SYS_", "")

    all_depcalls = depcalls.file_tree_ops + depcalls.regular_ops

    if call1 == "open" and int(call_info1[1][1]) & c.O_CREAT:
        call1 = "open_create"
    elif call2 == "open" and int(call_info2[1][1]) & c.O_CREAT:
        call2 = "open_create"
        tmp = (call1, call_info1)
        call1, call_info1 = call2, call_info2
        call2, call_info2 = tmp
    elif call1 + ", " + call2 in all_depcalls:
        pass
    elif call2 + ", " + call1 in all_depcalls:
        tmp = (call1, call_info1)
        call1, call_info1 = call2, call_info2
        call2, call_info2 = tmp
    else:
        return None

    print(call1, call_info1[1], call_info1[2])
    paths1, fds1 = get_path_fd(state, call1, call_info1[1], call_info1[2])
    print(call2, call_info2[1], call_info2[2])
    paths2, fds2 = get_path_fd(state, call2, call_info2[1], call_info2[2])
    
    return (call1, paths1, fds1, call2, paths2, fds2)

# there is only one path in path2, but multiple in path1
# as long as one of the path in path1 is the parent of path2
def is_parent(path1, path2):
    for path in path1:
        if path.startswith(path2[0]):
            return True
    return False

def is_dependent(s, next_op):
    # If s[1] -> next_op or next_op -> s[1], they are not dependent
    if c.runtime_state[next_op]["Stime"] >= c.runtime_state[s[1]]["Etime"] or \
       c.runtime_state[s[1]]["Stime"] >= c.runtime_state[next_op]["Etime"]:
        c.t_reduced = True
        return False
    else:
        ret = get_syscall_name_path(s[0], s[1], next_op)
        print("get path:", ret)
        # Not in the depcalls list
        if ret == None:
            return False

        call1,path1,fd1, call2,path2,fd2 = ret
        call_seq = call1 + ", " + call2
        # Regular operations on the same file
        if call_seq in depcalls.regular_ops:
            if path1 == path2:
                return True
            else:
                return False
        # File tree related operations
        else:
            
            # getdents
            if call_seq in ["getdents, mkdir",
                            "getdents, rmdir",
                            "getdents, rename"]:
                return True if is_parent(path1, path2) else False
                # path1 is parent dir of path1
            elif call_seq in ["getdents, open", "getdents, close"]:
                return True if fd1 == fd2 else False
            elif call_seq in ["getdents, dup", "getdents, dup2"]:
                return True if fd1 == [fd2[0]] else False
            elif call_seq in ["getdents, link", "getdents, symlink"]:
                return True if is_parent(path1, [path2[1]]) else False
            elif call_seq in ["getdents, unlink"]:
                return True if is_parent(path1, path2) else False 
            elif call_seq in ["getdents, chmod", "getdents, fchmod"]:
                return True if path1 == path2 else False
            
            # mkdir
            elif call_seq in ["mkdir, rmdir"]:
                if path1 == path2 or is_parent(path2, path1):
                    return True
                else:
                    return False
            elif call_seq in ["mkdir, rename"]:
                if path1[0] in path2 or is_parent(path2, path1):
                    return True
                else:
                    return False
            elif call_seq in ["mkdir, symlink"]:
                if path1[0] == path2[1] or is_parent([path2[1]], path1):
                    return True
                else:
                    return False
            elif call_seq in ["mkdir, open",
                              "mkdir, setxattr",
                              "mkdir, removexattr",
                              "mkdir, listxattr",
                              "mkdir, getxattr",
                              "mkdir, chmod",
                              "mkdir, fchmod",
                              "mkdir, stat",
                              "mkdir, lstat",
                              "mkdir, fstat",
                              "mkdir, fsync"]:
                return True if path1 == path2 else False
            elif call_seq == "mkdir, sync":
                return True
            
            # open with O_CREAT
            elif call1 == "open_create":
                return True if path1[0] in path2 else False

            # open
            elif call_seq in ["open, close",
                              "open, fstat",
                              "open, fsync",
                              "open, fdatasync"]:
                return True if fd1 == fd2 else False
            elif call_seq in ["open, dup",
                              "open, dup2",]:
                return True if fd1[0] == fd2[0] else False
            elif call_seq in ["open, link",
                              "open, symlink"]:
                return True if path1[0] == path2[1] else False
            elif call_seq in ["open, unlink",
                              "open, fchmod"]:
                return True if path1 == path2 else False

            # close
            elif call_seq in ["close, dup",
                              "close, dup2"]:
                return True if fd1[0] == fd2[0] else False
            elif call_seq in ["close, fsetxattr",
                              "close, fremovexattr",
                              "close, flistxattr",
                              "close, fgetxattr",
                              "close, ftruncate",
                              "close, fchmod",
                              "close, fstat",
                              "close, fsync",
                              "close, fdatasync"]:
                return True if fd1 == fd2 else False

            # link
            elif call_seq in ["link, symlink"]:
                return True if path2[1] in path1 else False

            elif call_seq in ["link, unlink"]:
                return True if path2[0] in path1 else False

            elif call_seq in ["link, setxattr",
                              "link, removexattr",
                              "link, listxattr",
                              "link, getxattr",
                              "link, lremovexattr",
                              "link, llistxattr",
                              "link, lgetxattr",
                              "link, truncate",
                              "link, chmod"]:
                return True if path2[0] == path1[1] else False

            elif call_seq in ["link, stat",
                              "link, lstat"]:
                return True if path2[0] in path1 else False

            elif call_seq in ["link, sync"]:
                return True

            elif call_seq in ["link, fsync"]:
                if is_parent(path2, [path1[0]]) or is_parent(path2, [path1[1]]):
                    return True
                else:
                    return False


            # symlink
            elif call_seq in ["symlink, unlink",
                              "symlink, readlink",
                              "symlink, setxattr",
                              "symlink, removexattr",
                              "symlink, listxattr",
                              "symlink, getxattr",
                              "symlink, lremovexattr",
                              "symlink, llistxattr",
                              "symlink, lgetxattr",
                              "symlink, truncate",
                              "symlink, chmod",
                              "symlink, stat",
                              "symlink, lstat"]:
                return True if path2[0] == path1[1] else False

            elif call_seq in ["symlink, fsync"]:
                if path2[0] == path1[1] or is_parent(path2, [path1[1]]):
                    return True
                else:
                    return False

            elif call_seq in ["symlink, sync"]:
                return True

            # unlink
            elif call_seq in ["unlink, readlink",
                              "unlink, setxattr",
                              "unlink, removexattr",
                              "unlink, listxattr",
                              "unlink, getxattr",
                              "unlink, lremovexattr",
                              "unlink, llistxattr",
                              "unlink, lgetxattr",
                              "unlink, truncate",
                              "unlink, chmod",
                              "unlink, stat",
                              "unlink, lstat"]:
                return True if path1 == path2 else False

            elif call_seq in ["unlink, sync"]:
                return True

            elif call_seq in ["unlink, fsync"]:
                if path1 == path2 or is_parent(path2, path1):
                    return True
                else:
                    return False

            else:
                return False

def update_backtrack(cur_S, backtrack, seq_programs):

    if backtrack == None:
        return
    
    for idx, prog in enumerate(seq_programs):
        # Get the next file op from prog
        if len(prog) == 0:
            continue
        next_op = prog[0]

        # update the backtrack list of previous states in S
        # dependent syscalls
        for s in reversed(cur_S):
            c.t_reduced = False
            if s[2] == idx or s[1] == -1:
                continue
            ret = is_dependent(s, next_op)
            if ret == False:
                # If we have already find the next_op happens after state s,
                # then no necessary to continue searching backwards
                if c.t_reduced == True:
                    c.timestamp_reduce += 1
                    break
                else:
                    c.relation_reduce += 1
                    print("relation reduced", s[1], next_op)
            # print("is_dependent: ", ret)
            if ret:
                c.backtracks[s[1]].append((next_op, idx))
                #backtrack.append(next_op)
                break

def explore(S, backtrack, seq_programs):

    c.ident += 1

    cur_S = copy.deepcopy(S)

    update_backtrack(cur_S, backtrack, seq_programs)

    # traverse the ops in the backtrack list
    next_op, prog_id = get_next_op(seq_programs)
    if next_op == None:
        # Check final states
        return checker.check_persistence_state(cur_S[-1][0])
        # return True

    prev_emul_state = cur_S[-1][0] # Si = (emul_state, op)
    
    sets, done = [(next_op, prog_id)], []
    # c.backtracks[next_op] = [next_op]
    # sets, done = c.backtracks[next_op], []
    remaining = list(set(sets)-set(done))
    times = 0
    while len(remaining) != 0:
        if times > 0:
            c.traversed_branches += 1
            print("another branch")
        times += 1
        op, proc_id = remaining[0]
        c.backtracks[op] = sets
        new_seq_programs = remove_one_op(seq_programs, op)
        done.append((op, proc_id))
        remaining = list(set(sets)-set(done))
        # Run syscall
        # TODO:
        # If only a few nodes crashed and are recovered,
        # should we require the FS state latest ????
        retval, emul_state = syscalls.emulate(prev_emul_state, op)
        # Push the current state to the state stack
        cur_S.append((emul_state, op, proc_id))
        # Check whether the runtime state conforms to the emul_state
        if checker.state_check(retval, emul_state, op) == False:
            print("check stat false")
            # The emulate state doesn't match to the runtime state
            # Stop exploring this path
            # But we need to update the backtrack points
            update_backtrack(cur_S, sets, new_seq_programs)
            print("sets:", sets, done)
        else:
            print("check stat true", sets, new_seq_programs)
            # Explore next state
            ret = explore(cur_S, sets, new_seq_programs)
            if ret == True:
                return True
        # Pop out from state stack
        cur_S = cur_S[:-1]

        # Recalculate remaining
        remaining = list(set(sets)-set(done))
    
    c.ident -= 1
    return False
