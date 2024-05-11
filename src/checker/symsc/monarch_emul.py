#!/usr/bin/python2
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: MIT
import pdb
import os
import sys
import tempfile
import shutil
import errno
import argparse
import subprocess
import copy
import binascii
import hashlib

import common as c
import syscalls
import utils
import checker
import depcalls
import dpor
import fault_model

import json
import re

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    #parser.add_argument("-i", dest="img", required=True)
    parser.add_argument("-t", dest="type", required=True)
    parser.add_argument("-p", dest="prog", required=True)
    parser.add_argument("-c", dest="crashed")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-d", "--showdata", action="store_true")
    parser.add_argument("-i", "--input", type=str, help="FileMetadata")
    parser.add_argument("-g", dest="seq_programs", required=True)
    parser.add_argument("-s", dest="srv_nodes_cnt", required=True)
    parser.add_argument("-f", dest="cfg_mode", required=True)
    parser.add_argument("-a", dest="init_ip", required=True)
    parser.add_argument("-n", dest="testdir_ino")

    #c.DISK[0] = 0
    print("start parsing arguments\n")
    args = parser.parse_args()

    if args.crashed:
        args.crashed = args.crashed[1:-2]
        print("prog:\n{}\ncrash state:\n{}\n".format(args.prog, args.crashed))

    if args.verbose:
        c.verbose = 1
    if args.showdata:
        c.SHOWDATA = 1

    c.FSTYPE = args.type

    if c.verbose:
        print("===== RETRIEVE METADATA FROM CRASHED IMG =====")

    if args.crashed:
        tmpmetadata = args.crashed.split("\n")

        for entry in tmpmetadata:
            if entry == "":
                continue
            es = entry.rstrip("\n").split("\t")
            parts = re.split(r'(\\x[0-9a-fA-F].)', es[c.IDX_XATTR])
            es[c.IDX_XATTR] = ''.join([chr(int(part[2:], 16)) if part.startswith("\\x") else part for part in parts])
            print("es:", es)
            c.METADATA.append(es)

    if c.verbose and args.crashed:
        print("============== Crash state: METADATA =================")
        for entry in c.METADATA:
            print(entry)

    if c.verbose:
        print("===== PARSING prog =====")

    # Load syscall idx sequences, [[0, 1], [2], [3, 4]]
    seq_programs = json.loads(args.seq_programs)

    # Initialize fault state
    srv_nodes_cnt = int(args.srv_nodes_cnt)
    if c.FSTYPE == "glusterfs":
        fault_model.glusterfs_init_vol(srv_nodes_cnt,
                                    args.cfg_mode, args.init_ip)
    elif c.FSTYPE == "cephfs":
        fault_model.cephfs_init(args.cfg_mode, \
            int(args.testdir_ino)&0xffffffffffffffff, \
            args.init_ip)

    # Initialize emul_state
    node_cnt = len(seq_programs)
    emul_state = utils.init_state(args.prog, node_cnt)

    # Runtime state
    c.runtime_state = json.loads(args.input)

    # State exploration
    S = [(emul_state, -1, -1)]
    if dpor.explore(S, None, seq_programs) == False:
        print("WARNING: inconsistent emul and runtime state")

    # Statistics for eval
    # Only consider more than one clients has calls
    # and total call numbers should > 1
    
    if len(c.SYSCALL_STACK) > 1 and \
    len([prog for prog in seq_programs[srv_nodes_cnt:] if len(prog) > 0]) > 1:
        print("dport_traversed_path:", c.traversed_branches)
        print("dport_timestamp_reduced:", c.timestamp_reduce)
        print("dport_relation_reduced:", c.relation_reduce)
    
    conc_ratio = utils.calculate_ratio(seq_programs[srv_nodes_cnt:])
    prog_lens = [str(len(prog)) for prog in seq_programs[srv_nodes_cnt:]]
    print(prog_lens)
    data = "{},{},{},{},{}\n".format(str(c.traversed_branches),
        str(c.timestamp_reduce), str(c.relation_reduce),
        str(conc_ratio), ','.join(prog_lens))

    workdir = "../dpor-eval"
    if not os.path.exists(workdir):
        os.makedirs(workdir)


    suffix = "-".join(args.cfg_mode.replace("'", "").split())
    with open("{}/dpor-{}".format(workdir, suffix), "a") as f:
        f.write(data)
        f.flush()
        f.close()