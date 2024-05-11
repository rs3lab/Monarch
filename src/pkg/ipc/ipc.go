// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"fmt"
	//"io"
	"io/ioutil"
	"os"
	"os/exec"
	//"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
	"sync"
	"syscall"
	//"runtime/debug"
	//"bytes"
	"strconv"
	"encoding/binary"
	"path/filepath"
    "sort"

	"monarch/pkg/cover"
	"monarch/pkg/log"
	"monarch/pkg/osutil"
	"monarch/pkg/signal"
	"monarch/prog"
	"monarch/sys/targets"
)

// Configuration flags for Config.Flags.
type EnvFlags uint64

// Note: New / changed flags should be added to parse_env_flags in executor.cc.
const (
	FlagDebug               EnvFlags = 1 << iota // debug output from executor
	FlagSignal                                   // collect feedback signals (coverage)
	FlagSandboxSetuid                            // impersonate nobody user
	FlagSandboxNamespace                         // use namespaces for sandboxing
	FlagSandboxAndroid                           // use Android sandboxing for the untrusted_app domain
	FlagExtraCover                               // collect extra coverage
	FlagEnableTun                                // setup and use /dev/tun for packet injection
	FlagEnableNetDev                             // setup more network devices for testing
	FlagEnableNetReset                           // reset network namespace between programs
	FlagEnableCgroups                            // setup cgroups for testing
	FlagEnableCloseFds                           // close fds after each program
	FlagEnableDevlinkPCI                         // setup devlink PCI device
	FlagEnableVhciInjection                      // setup and use /dev/vhci for hci packet injection
	FlagEnableWifi                               // setup and use mac80211_hwsim for wifi emulation
)

// Per-exec flags for ExecOpts.Flags.
type ExecFlags uint64

const (
	FlagCollectCover         ExecFlags = 1 << iota // collect coverage
	FlagDedupCover                                 // deduplicate coverage in executor
	FlagCollectComps                               // collect KCOV comparisons
	FlagThreaded                                   // use multiple threads to mitigate blocked syscalls
	FlagCollide                                    // collide syscalls to provoke data races
	FlagEnableCoverageFilter                       // setup and use bitmap to do coverage filter
)

type ExecOpts struct {
	Flags ExecFlags
}

// Config is the configuration for Env.
type Config struct {
	// Path to executor binary.
	Executor []string

	UseShmem      bool // use shared memory instead of pipes for communication
	UseForkServer bool // use extended protocol with handshake

	// Flags are configuation flags, defined above.
	Flags EnvFlags

	Timeouts targets.Timeouts

	ServNum        int
	DFSName        string
	FuzzingVMs     int
	InitIp         string
	InitShmId      int
	DfsSetupParams string
	KernelClient   bool
	KernelSrv      bool
	NetFailure     bool
	NodeCrash      bool
	LFSBased       bool
	EnableCsan     bool
	EnableC2san	   bool
	EnableSrvFb    bool
	EnableEval	   bool
	EnableClientFb bool
	Syzkaller	   string
	TSCOFF         string
}

type CallFlags uint32

const (
	CallExecuted      CallFlags = 1 << iota // was started at all
	CallFinished                            // finished executing (rather than blocked forever)
	CallBlocked                             // finished but blocked during execution
	CallFaultInjected                       // fault was injected into this call
)

type CallInfo struct {
	Flags  CallFlags
	Signal []uint32 // feedback signal, filled if FlagSignal is set
	Cover  []uint32 // per-call coverage, filled if FlagSignal is set and cover == true,
	// if dedup == false, then cov effectively contains a trace, otherwise duplicates are removed
	Comps prog.CompMap // per-call comparison operands
	Errno int          // call errno (0 if the call was successful)
}

type ProgInfo struct {
	Calls []CallInfo
	Extra CallInfo // stores Signal and Cover collected from background threads
    FsMd  map[string]prog.FileMetadata
}

type Env struct {
	in   []byte
	outs [][]byte
	callOrder []byte

	cmd       *command
	inFile    *os.File
	outFile   *os.File
	bins      [][]string
	linkedBin string
	pid       int
	config    *Config

	StatExecs    uint64
	StatRestarts uint64
}

type outputControl struct {
	executionFinished byte
	cntTmp            uint32
	outputPosTmp      *uint32
}
/*
type fileMetadata struct {
    stime uint64
    etime uint64
    retv  int64
	statMd syscall.Stat_t
	xattr  map[string]string
	checksum uint32
	symlinkPath  string
}
*/
const (
	outputSize = 16 << 20

	statusFail = 67

	// Comparison types masks taken from KCOV headers.
	compSizeMask  = 6
	compSize8     = 6
	compConstMask = 1

	extraReplyIndex = 0xffffffff // uint32(-1)
)

func SandboxToFlags(sandbox string) (EnvFlags, error) {
	switch sandbox {
	case "none":
		return 0, nil
	case "setuid":
		return FlagSandboxSetuid, nil
	case "namespace":
		return FlagSandboxNamespace, nil
	case "android":
		return FlagSandboxAndroid, nil
	default:
		return 0, fmt.Errorf("sandbox must contain one of none/setuid/namespace/android")
	}
}

func FlagsToSandbox(flags EnvFlags) string {
	if flags&FlagSandboxSetuid != 0 {
		return "setuid"
	} else if flags&FlagSandboxNamespace != 0 {
		return "namespace"
	} else if flags&FlagSandboxAndroid != 0 {
		return "android"
	}
	return "none"
}

func createMapShm(shmId int, size int) []byte {
	fn := fmt.Sprintf("/dev/shm/shm%d", shmId)
	inf, _ := os.OpenFile(fn, os.O_RDWR, 0644)
    mem, err := syscall.Mmap(int(inf.Fd()), 0, size,
								syscall.PROT_WRITE|syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		log.Fatalf("Map shared memory failed")
    }
	return mem
}

func MakeEnv(config *Config, pid int, shmId int) (*Env, error) {
	if config.Timeouts.Slowdown == 0 || config.Timeouts.Scale == 0 ||
		config.Timeouts.Syscall == 0 || config.Timeouts.Program == 0 {
		return nil, fmt.Errorf("ipc.MakeEnv: uninitialized timeouts (%+v)", config.Timeouts)
	}
	var inf, outf *os.File
	var outmems [][]byte
	if !config.UseShmem {
		log.Fatalf("Not in a UseShmem mode")
	}
	//tao added
	//inmem
	inmem := createMapShm(shmId, 1*1024*1024)
	var execCtl executeControl
	for i := 0; i < int(unsafe.Sizeof(execCtl)); i++ {
		inmem[i] = 0
	}

	//memory for recording orders of executed syscalls
	callOrder := createMapShm(shmId+1, 1024)

	//outmem
	for i := 1; i <= len(config.Executor); i++ {
		outmem := createMapShm(shmId+1+i, 1*1024*1024)
		outmem[0] = 0
		outmems = append(outmems, outmem)
	}
	//tao end
	/*
	} else {
		inmem = make([]byte, prog.ExecBufferSize)
		outmem := make([]byte, outputSize)
		outmems = append(outmems, outmem)
	}
	*/

	//split multiple executor with delimiter ";"
	var bins [][]string
	tscoffs := strings.Split(config.TSCOFF, ";")
	for idx, executorCmd := range config.Executor {
		var isClient int
		if idx < config.ServNum {
			isClient = 0
		} else {
			isClient = 1
		}
		bins = append(bins,
			append(append(strings.Split(executorCmd, " "), "exec"), strconv.Itoa(isClient),
				strconv.Itoa(idx), config.DFSName, strconv.Itoa(config.ServNum),
				strconv.Itoa(config.FuzzingVMs), config.InitIp, "0", "\""+config.DfsSetupParams+"\"",
				strconv.FormatBool(config.KernelSrv), strconv.FormatBool(config.KernelClient),
				strconv.FormatBool(config.LFSBased), strconv.FormatBool(config.EnableCsan),
				strconv.FormatBool(config.EnableC2san), tscoffs[idx]))
		//0 => this is original executor starting not restarting
	}

	env := &Env{
		in:      inmem,
		outs:    outmems,
		callOrder: callOrder,
		inFile:  inf,
		outFile: outf,
		bins:    bins, //append(strings.Split(config.Executor, " "), "exec"),
		pid:     pid,
		config:  config,
	}
	if len(env.bins) == 0 {
		return nil, fmt.Errorf("binary is empty string")
	}
	/*
		env.bin[0] = osutil.Abs(env.bin[0]) // we are going to chdir
		// Append pid to binary name.
		// E.g. if binary is 'syz-executor' and pid=15,
		// we create a link from 'syz-executor.15' to 'syz-executor' and use 'syz-executor.15' as binary.
		// This allows to easily identify program that lead to a crash in the log.
		// Log contains pid in "executing program 15" and crashes usually contain "Comm: syz-executor.15".
		// Note: pkg/report knowns about this and converts "syz-executor.15" back to "syz-executor".
		base := filepath.Base(env.bin[0])
		pidStr := fmt.Sprintf(".%v", pid)
		const maxLen = 16 // TASK_COMM_LEN is currently set to 16
		if len(base)+len(pidStr) >= maxLen {
			// Remove beginning of file name, in tests temp files have unique numbers at the end.
			base = base[len(base)+len(pidStr)-maxLen+1:]
		}
		binCopy := filepath.Join(filepath.Dir(env.bin[0]), base+pidStr)
		if err := os.Link(env.bin[0], binCopy); err == nil {
			env.bin[0] = binCopy
			env.linkedBin = binCopy
		}
	*/
	inf = nil
	outf = nil
	return env, nil
}

func (env *Env) Close() error {
	if env.cmd != nil {
		env.cmd.close()
	}
	if env.linkedBin != "" {
		os.Remove(env.linkedBin)
	}
	var err1, err2 error
	if env.inFile != nil {
		err1 = osutil.CloseMemMappedFile(env.inFile, env.in)
	}
	if env.outFile != nil {
		for _, out := range env.outs {
			err2 = osutil.CloseMemMappedFile(env.outFile, out)
		}
	}
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return nil
	}
}

var rateLimit = time.NewTicker(1 * time.Second)

//tao added
type ExecRet struct {
	Output       []byte
	Info         *ProgInfo
	Hanged       bool
	Err          error
	Syscall_rets []int
	Errornos     []int
}

//tao end

// Exec starts executor binary to execute program p and returns information about the execution:
// output: process output
// info: per-call info
// hanged: program hanged and was killed
// err0: failed to start the process or bug in executor itself.
func (env *Env) Exec(opts *ExecOpts, ps []*prog.Prog) (output []byte, infos []*ProgInfo, hanged bool,
    err0 error, fsMds []map[string]prog.FileMetadata, testdirIno uint64) {
	// Copy-in serialized program.
	var req executeReq
	const reqLen = int(unsafe.Sizeof(req))
	var execCtl executeControl
	const ctlLen = int(unsafe.Sizeof(execCtl))

	offset := 0
	//bytesSavePSize := len(ps) * 8
	var progSizes [64]uint64
	var progOffsets [64]uint64
	for idx, p := range ps {
		progSize, err := p.SerializeForExec(env.in[(ctlLen + reqLen + offset):])
		progOffsets[idx] = uint64(ctlLen + reqLen + offset)
		offset += progSize
		progSizes[idx] = uint64(progSize)
		if err != nil {
			err0 = err
			return
		}
	}

	var progData []byte
	/*
		if !env.config.UseShmem {
			progData = env.in[:progSize]
		}
	*/

	// Zero out the first two words (ncmd and nsig), so that we don't have garbage there
	// if executor crashes before writing non-garbage there.
	for j := 0; j < len(env.outs); j++ {
		for i := 0; i < 4; i++ {
			env.outs[j][i] = 0
		}
	}

	atomic.AddUint64(&env.StatExecs, 1)
	if env.cmd == nil {
		if ps[0].Target.OS != targets.TestOS && targets.Get(ps[0].Target.OS, ps[0].Target.Arch).HostFuzzer {
			// The executor is actually ssh,
			// starting them too frequently leads to timeouts.
			<-rateLimit.C
		}
		tmpDirPath := "./"
		atomic.AddUint64(&env.StatRestarts, 1)
		env.cmd, err0 = makeCommand(env.pid, env.bins, env.config, env.inFile, env.outFile, env.in, env.outs,
																					tmpDirPath, env.callOrder)
		if err0 != nil {
			return
		}
	}

	a := time.Now().UnixMilli()
	output, hanged, err0 = env.cmd.exec(opts, progData, progSizes, progOffsets)
	if err0 != nil {
		log.Logf(0, "exec err0 is not nil:%v\n", err0)
		env.cmd.close()
		env.cmd = nil
		return
	}
	b := time.Now().UnixMilli()
	log.Logf(0, "exec time: %d", b-a)

	var executor_idx int
	//var fsMds []map[string]prog.FileMetadata
	infos, err0, executor_idx, _, fsMds, testdirIno = env.parseOutputs(ps)

	if err0 != nil {
		log.Logf(0, "executor %d parseOutput err0 is not nil %v\n", executor_idx, err0)
		return
	}

	if infos != nil && env.config.Flags&FlagSignal == 0 {
		for idx, p := range ps {
			addFallbackSignal(p, infos[idx])
		}
	}
	if !env.config.UseForkServer {
		env.cmd.close()
		env.cmd = nil
	}

	//call semantic sanitizers here
    /*
	if env.config.EnableC2san && ps[0].C2test {
		symc3ProgStr := symc3Prog.SerializeForSymc3()
		err0 = env.semanticSanitizers(fsMds, symc3ProgStr, len(ps))
	}
    */

	return
}

// addFallbackSignal computes simple fallback signal in cases we don't have real coverage signal.
// We use syscall number or-ed with returned errno value as signal.
// At least this gives us all combinations of syscall+errno.
func addFallbackSignal(p *prog.Prog, info *ProgInfo) {
	callInfos := make([]prog.CallInfo, len(info.Calls))
	for i, inf := range info.Calls {
		if inf.Flags&CallExecuted != 0 {
			callInfos[i].Flags |= prog.CallExecuted
		}
		if inf.Flags&CallFinished != 0 {
			callInfos[i].Flags |= prog.CallFinished
		}
		if inf.Flags&CallBlocked != 0 {
			callInfos[i].Flags |= prog.CallBlocked
		}
		callInfos[i].Errno = inf.Errno
	}
	p.FallbackSignal(callInfos)
	for i, inf := range callInfos {
		info.Calls[i].Signal = inf.Signal
	}
}

type parseRet struct {
	idx  int
	info *ProgInfo
	fsMd map[string]prog.FileMetadata
	err  error
	callInfo   *[]prog.FileMetadata
	testdirIno  uint64
}

func (env *Env) parseOutputs(ps []*prog.Prog) ([]*ProgInfo, error, int, *prog.Prog,
    []map[string]prog.FileMetadata, uint64) {

	progsLen := len(ps)
	srvInfos := make([]*ProgInfo, env.config.ServNum)
	clientInfos := make([]*ProgInfo, progsLen-env.config.ServNum)
	fsMds := make([]map[string]prog.FileMetadata, progsLen)
    testdirIno := uint64(0)

	retChan := make(chan parseRet)
	for idx, p := range ps {
		go env.parseClientOutput(p, idx, retChan)
	}

	//TODO sorting
	for i := 0; i < progsLen; i++ {
		ret := <-retChan
		if ret.err != nil {
			return nil, ret.err, ret.idx, nil, nil, 0
		}
		if ret.idx < env.config.ServNum {
			srvInfos[ret.idx] = ret.info
            srvInfos[ret.idx].FsMd = ret.fsMd
		} else {
			clientInfos[ret.idx-env.config.ServNum] = ret.info
            clientInfos[ret.idx-env.config.ServNum].FsMd = ret.fsMd
		}
		fsMds[ret.idx] = ret.fsMd
		if ret.testdirIno != 0 {
			testdirIno = ret.testdirIno
		}
	}
	log.Logf(0, "fsMds: %v", fsMds)

	//parse call orders
	var symc3Prog *prog.Prog
	if env.config.EnableC2san && ps[0].C2test {
		symc3Prog = env.parseCallOrder(ps)
	}

	return append(srvInfos, clientInfos...), nil, 0, symc3Prog, fsMds, testdirIno
}

func (env *Env) semanticSanitizers(fsMds []map[string]prog.FileMetadata, symc3Prog string, progsCnt int) error {

	clientInit := false
	globalClientFsMd := make(map[string]prog.FileMetadata)
    globalSrvFsMd := make(map[string]prog.FileMetadata)

	if env.config.EnableCsan {
		//compare between clients
		for i := env.config.ServNum; i < progsCnt; i++ {
			fsMd := fsMds[i]
			if clientInit {
				env.ConsistencySan(globalClientFsMd, globalSrvFsMd, fsMd, false, false)
			} else {
				for filepath, md := range fsMd {
					globalClientFsMd[filepath] = md
				}
				clientInit = true
			}
		}
		if env.config.LFSBased {
			//compare between servers
			for i := 0; i < env.config.ServNum; i++ {
				env.ConsistencySan(globalClientFsMd, globalSrvFsMd, fsMds[i], true, false)
			}
			//compare clients and servers
			env.ConsistencySan(globalClientFsMd, globalSrvFsMd, nil, false, true)
		}
	}

	if env.config.EnableC2san {
		symc3_stat := ""
		for i := env.config.ServNum; i < progsCnt; i++ {
			statPerNode := ""
			for filepath, fileMd := range fsMds[i] {
				statMd := fileMd.StatMd
				checksum := fileMd.Checksum
				symlinkPath := fileMd.SymlinkPath
				xattrs := ""
				j := 0
				for k,v := range fileMd.Xattr {
					if j != 0 {
						xattrs = xattrs + ";"
					}
					xattrs = xattrs + k + ":" + v
					j += 1
				}

				type_converted := 0;
			    switch statMd.Mode & syscall.S_IFMT {
		            case 0x8000: type_converted = 1 // Regular file
		            case 0x4000: type_converted = 2 // Directory
		            case 0xA000: type_converted = 3 // Symbolic link
		            case 0x1000: type_converted = 4 // Fifo file
		        }

		        //pass metadata to symc3
		        statPerNode = statPerNode + fmt.Sprintf("%s\t%d\t%v\t%v\t%v\t%v\t%v\t%o\t%v\t%s\t%s\n",
                        filepath, type_converted, statMd.Ino, statMd.Nlink, statMd.Size, statMd.Blksize,
                        statMd.Blocks, statMd.Mode & ^uint32(syscall.S_IFMT), checksum, symlinkPath, xattrs)
			}
			if statPerNode == "" {
				statPerNode = "\n"
			}
			if i != env.config.ServNum {
				statPerNode =  "---\n" + statPerNode
			}
			symc3_stat =  symc3_stat + statPerNode
		}
	    output, _ := exec.Command("python2.7", filepath.Join(env.config.Syzkaller,
									"/checker/symc3/monarch_emul.py"), "-v", "-p", "'"+symc3Prog+"'", "-c",
									"'"+symc3_stat+"'").CombinedOutput()
		log.Logf(0, "monarch_emul:" + string(output))
	}
	return nil
}

func (env *Env) ConsistencySan(globalClientFsMd map[string]prog.FileMetadata, globalSrvFsMd map[string]prog.FileMetadata,
	fsMd map[string]prog.FileMetadata, isSrv bool, clientSrvCmp bool) {

	log.Logf(0, "ConsistencySan: len(globalClientFsMd)=%d len(globalSrvFsMd)=%d len(fsMd)=%d",
		len(globalClientFsMd), len(globalSrvFsMd), len(fsMd))
	if clientSrvCmp {
		env.clientSrvCmp(globalClientFsMd, globalSrvFsMd)
	} else if !isSrv {
		env.clientMdCmp(globalClientFsMd, fsMd)
	} else {
		env.serverMdCmp(globalSrvFsMd, fsMd)
	}
}

func xattrCmp(xattr1 map[string]string, xattr2 map[string]string) bool {
	for name, value1 := range xattr1 {
		if value2, ok := xattr2[name]; !ok || value1 != value2 {
			return false
		}
	}
	return true
}

func (env *Env) clientMdCmp(globalFsMd map[string]prog.FileMetadata, fsMd map[string]prog.FileMetadata) {
	log.Logf(0, "----- comparison: clientMdCmp: %v\n%v\n", globalFsMd, fsMd)

	if len(globalFsMd) != len(fsMd) {
		log.Logf(0, "WARNING: consistencySanitizer: doesn't have equal files across clients")
		return
	}

	for filepath1, md1 := range globalFsMd {
		log.Logf(0, "globalFsMd: %s", filepath1)
		md2, ok := fsMd[filepath1]
		outputBuf := fmt.Sprintf("ConsistencySan stat:\n%+v\n%+v\n", md1, md2)
		log.Logf(0, outputBuf)
		if !ok {
			log.Logf(0, "WARNING: consistencySanitizer: globalClientFsMd doesn't contain file %v", filepath1)
			return
		}
		/*
					statMd syscall.Stat_t
					type Stat_t struct {
			            Dev       uint64
			            Ino       uint64
			            Nlink     uint64
			            Mode      uint32
			            Uid       uint32
			            Gid       uint32
			            X__pad0   int32
			            Rdev      uint64
			            Size      int64
			            Blksize   int64
			            Blocks    int64
			            Atim      Timespec
			            Mtim      Timespec
			            Ctim      Timespec
			            X__unused [3]int64
			        }
				    xattr  string
		*/
		if !xattrCmp(md1.Xattr, md2.Xattr) {
			log.Logf(0, "WARNING: consistencySanitizer: %v xattr %v and %v are different.",
				filepath1, md1.Xattr, md2.Xattr)
			return
		}
		if md1.StatMd.Nlink != md2.StatMd.Nlink {
			log.Logf(0, "WARNING: consistencySanitizer: %v Nlink %v and %v are different.",
				filepath1, md1.StatMd.Nlink, md2.StatMd.Nlink)
			return
		}
		if md1.StatMd.Mode != md2.StatMd.Mode {
			log.Logf(0, "WARNING: consistencySanitizer: %v Mode %v and %v are different.",
				filepath1, md1.StatMd.Mode, md2.StatMd.Mode)
			return
		}
		/*
					if md1.statMd.Uid != md2.statMd.Uid {
						log.Logf(0, "WARNING: consistencySanitizer: %v Uid %v %v are different.",
			                                        filepath1, md1.statMd.Uid, md2.statMd.Uid)
						return
					}
					if md1.statMd.Gid != md2.statMd.Gid {
						log.Logf(0, "WARNING: consistencySanitizer: %v Gid %v %v are different.",
			                                        filepath1, md1.statMd.Gid, md2.statMd.Gid)
						return
					}
		*/
		if md1.StatMd.Size != md2.StatMd.Size {
			log.Logf(0, "WARNING: consistencySanitizer: %v Size %v and %v are different.",
				filepath1, md1.StatMd.Size, md2.StatMd.Size)
			return
		}
		/*
					if env.config.DFSName != "gluserfs" {
						if md1.statMd.Atim != md2.statMd.Atim {
							log.Logf(0, "WARNING: consistencySanitizer: %v access time %v %v are different.",
													filepath1, md1.statMd.Atim, md2.statMd.Atim)
							return
						}
						if md1.statMd.Mtim != md2.statMd.Mtim {
							log.Logf(0, "WARNING: consistencySanitizer: %v modify time %v %v are different.",
			                                        filepath1, md1.statMd.Mtim, md2.statMd.Mtim)
							return
						}
						if md1.statMd.Ctim != md2.statMd.Ctim {
							log.Logf(0, "WARNING: consistencySanitizer: %v state change time %v %v are different.",
			                                        filepath1, md1.statMd.Ctim, md2.statMd.Ctim)
							return
						}
					}
		*/
	}
	log.Logf(0, "----- consistency sanitizer: equal")
}

func (env *Env) serverMdCmp(globalFsMd map[string]prog.FileMetadata, fsMd map[string]prog.FileMetadata) {
	log.Logf(0, "----- comparison: serverMdCmp %v\n%v\n", globalFsMd, fsMd)

	for filepath1, md1 := range fsMd {
		md2, ok := globalFsMd[filepath1]
		log.Logf(0, "----- globalFsMd: %s", filepath1)
		if !ok {
			globalFsMd[filepath1] = md1
			continue
		}
		if md1.StatMd.Mode != md2.StatMd.Mode {
			log.Logf(0, "WARNING: consistencySanitizer: %v Mode %v and %v are different.",
				filepath1, md1.StatMd.Mode, md2.StatMd.Mode)
			return
		}
		if md1.StatMd.Nlink != md2.StatMd.Nlink {
			log.Logf(0, "WARNING: consistencySanitizer: %v Nlink %v and %v are different.",
				filepath1, md1.StatMd.Nlink, md2.StatMd.Nlink)
			return
		}
		if !xattrCmp(md1.Xattr, md2.Xattr) {
			log.Logf(0, "WARNING: consistencySanitizer: %v xattr %v and %v are different.",
				filepath1, md1.Xattr, md2.Xattr)
			return
		}
	}
	log.Logf(0, "----- consistency sanitizer: equal")
}

func (env *Env) clientSrvCmp(globalClientFsMd map[string]prog.FileMetadata, globalSrvFsMd map[string]prog.FileMetadata) {

	log.Logf(0, "----- comparison: clientSrvCmp %v\n%v\n", globalClientFsMd, globalSrvFsMd)

	if len(globalClientFsMd) != len(globalSrvFsMd) {
		log.Logf(0, "WARNING: consistencySanitizer: client-server cmp, they don't have the same number of files")
	}

	for filepath1, md1 := range globalClientFsMd {
		md2, ok := globalSrvFsMd[filepath1]
		if !ok {
			log.Logf(0, "WARNING: consistencySanitizer: client-server cmp, file %v doesn't exist in servers", filepath1)
			return
		}
		if md1.StatMd.Mode != md2.StatMd.Mode {
			log.Logf(0, "WARNING: consistencySanitizer: client-server cmp, %v Mode %v and %v are different.",
				filepath1, md1.StatMd.Mode, md2.StatMd.Mode)
			return
		}
		if !xattrCmp(md1.Xattr, md2.Xattr) {
			log.Logf(0, "WARNING: consistencySanitizer: client-server cmp, %v xattr %v and %v are different.",
				filepath1, md1.Xattr, md2.Xattr)
			return
		}
	}
	return
}

func (env *Env) parseCallOrder(ps []*prog.Prog) *prog.Prog {

	callOrder := env.callOrder

	newProg := &prog.Prog{
		Target: ps[0].Target,
	}

	callOrderCtl := &CallOrderControl{}
	size := unsafe.Sizeof(*callOrderCtl)
	callOrderCtlData := (*[unsafe.Sizeof(*callOrderCtl)]byte)(unsafe.Pointer(callOrderCtl))[:]
	copy(callOrderCtlData, callOrder[:size])

	orders := callOrder[size:]
	for i := byte(0); i < callOrderCtl.cnt; i ++ {
		progIdx := orders[2*i]
		callIdx := orders[2*i+1]
		log.Logf(0, "prog: %v, call: %v", progIdx, callIdx)
		newProg.Calls = append(newProg.Calls, ps[progIdx].Calls[callIdx])
	}
	return newProg
}

func (env *Env) parseFsMd(outp *[]byte) (map[string]prog.FileMetadata, error) {

	fsMd := make(map[string]prog.FileMetadata)
	out := *outp
	stat_cnt_uint, ok := readUint32(&out)
	stat_cnt := int(stat_cnt_uint)
	if !ok {
		return nil, fmt.Errorf("failed to read number of stat_cnt")
	}

	log.Logf(0, "------ stat_cnt %d, %v", stat_cnt, out[:10])

	if stat_cnt == -1 {
		return nil, nil
	}

	// |size_of_file_path | size_of_xattr | size_of_symlink_path 
	// | filepath | xattr | checksum(uint32) | symlink path |  stat metadata |
	for i := 0; i < stat_cnt; i++ {
		filepathSize, ok := readUint32(&out)
		if !ok {
			return nil, fmt.Errorf("failed to read filepathSize")
		}
		xattrSize, ok := readUint32(&out)
		if !ok {
			return nil, fmt.Errorf("failed to read xattrSize")
		}
		sympathSize, ok := readUint32(&out)
		if !ok {
			return nil, fmt.Errorf("failed to read sympathSize")
		}
		log.Logf(0, "----- filepathSzie %d xattrSize %d", filepathSize, xattrSize)

		//filepath
		filepath := string(out[:filepathSize])
		out = out[filepathSize:]

        log.Logf(0, "filepath: %v", filepath)

		//xattr
		xattrs := ""
		if xattrSize != 0 {
			xattrs = string(out[:xattrSize-1]) //Get rid of the last byte which is zero
		}
		out = out[xattrSize:]

		xattrsMap := make(map[string]string)
		log.Logf(0, "----- xattrs: %v", xattrs)
		if len(xattrs) > 0 {
			for _, xattr := range strings.Split(xattrs, ";") {
				if xattr_filter(xattr) {
					continue
				}
				ret := strings.Split(xattr, ":")
				name := ret[0]
				if len(ret) == 2 {
					xattrsMap[name] = prog.Serialize2Str([]byte(ret[1])) // ret[1]
					log.Logf(0, "----- xattr: %v : %v", name, xattrsMap[name])
				} else {
					xattrsMap[name] = ""
				}
			}
		}

		//checksum
		checksum, ok := readUint32(&out)
		if !ok {
			return nil, fmt.Errorf("failed to read checksum")
		}

		//sympath link
		symlinkPath := string(out[:sympathSize])
		out = out[sympathSize:]

		//stat
		var statMd syscall.Stat_t
		statSize := uint32(unsafe.Sizeof(statMd))
		statMdData := (*[unsafe.Sizeof(statMd)]byte)(unsafe.Pointer(&statMd))[:]
		copy(statMdData, out[:statSize])
		out = out[statSize:]

		fileMd := prog.FileMetadata{
			StatMd: statMd,
			Xattr:  xattrsMap,
			Checksum: checksum,
			SymlinkPath: symlinkPath,
		}
		if _, ok := fsMd[filepath]; !ok {
			fsMd[filepath] = fileMd
		} else {
			return nil, fmt.Errorf("Duplicated file in received metadata")
		}
	}

	*outp = out[:]
	log.Logf(0, "----- parsed fsMd len %d", len(fsMd))
	return fsMd, nil

	/*
		//sizeof(struct stat) = 144; sizeof(struct dirent) = 280
		stat_bytes := (144 + 280) * stat_cnt
		stat_bytes += XATTR_BUF_LEN
		v := out[:stat_bytes]
		*outp = out[stat_bytes:]
		return v, nil
	*/
}

func (env *Env) parseServerOutput(idx int, isClient bool, retChan chan parseRet) {

	extraParts := make([]CallInfo, 1)
	srvInfo := &extraParts[0]

	out := env.outs[idx][env.cmd.outCtlSize+env.cmd.replySize:]
	//this is the position for storing output_pos in executor
	readUint64(&out)
	ncmd, ok := readUint32(&out)
	if !ok {
		retChan <- parseRet{info: nil, fsMd: nil, err: fmt.Errorf("failed to read number of calls"), idx: idx}
		return
	}

	log.Logf(0, "[SERVER] executor %d has %d replies\n", idx, ncmd)
	for i := uint32(0); i < ncmd; i++ {
		signalSize, ok := readUint32(&out)
		if !ok {
			retChan <- parseRet{info: nil, fsMd: nil,
				err: fmt.Errorf("failed to read number of server signal size"), idx: idx}
			return
		}
		coverSize, ok := readUint32(&out)
		if !ok {
			retChan <- parseRet{info: nil, fsMd: nil,
				err: fmt.Errorf("failed to read number of server cover size"), idx: idx}
			return
		}
		//Compos
		_, ok = readUint32(&out)
		if !ok {
			retChan <- parseRet{info: nil, fsMd: nil,
				err: fmt.Errorf("failed to read number of server comparisons"), idx: idx}
			return
		}

		//log.Logf(0, "----- executor %d %dth reply signalsize %d coversize %d\n", idx, i, signalSize, coverSize);
		Signal, ok := readUint32Array(&out, signalSize)
		if !ok {
			retChan <- parseRet{info: nil, fsMd: nil, err: fmt.Errorf("Fuzzer server executor %d %dth reply: signal overflow: %v/%v", idx, i, signalSize, len(out)), idx: idx}
			return
		}
		Cover, ok := readUint32Array(&out, coverSize)
		if !ok {
			retChan <- parseRet{info: nil, fsMd: nil,
				err: fmt.Errorf("Fuzzer server executor %d: cover overflow: %v/%v", idx, coverSize, len(out)), idx: idx}
			return
		}
		if srvInfo.Signal != nil {
			srvInfo.Signal = append(srvInfo.Signal, Signal...)
		} else {
			srvInfo.Signal = Signal
		}
		if srvInfo.Cover != nil {
			srvInfo.Cover = append(srvInfo.Cover, Cover...)
		} else {
			srvInfo.Cover = Cover
		}
		log.Logf(0, "------- fuzzer executor %d receive %d signal and %d cover from userspace component", idx, signalSize, coverSize)
	}

	info := &ProgInfo{}
	info.Extra = convertExtra(extraParts)

	var fsMd map[string]prog.FileMetadata
	var err error
	//ParseFsMd when it's a client or a LFS-based server
	if env.config.EnableCsan && (isClient || (env.config.LFSBased && !isClient)) {
		fsMd, err = env.parseFsMd(&out)
		if err != nil {
			retChan <- parseRet{info: info, fsMd: nil, err: fmt.Errorf("parseCOnsistencySan error"), idx: idx}
			return
		}
	}

	retChan <- parseRet{info: info, fsMd: fsMd, err: nil, idx: idx}
}

func xattr_filter(str string) bool {
    // black list
    black_list := []string{"system.nfs4_acl", "security.selinux"}
    for _, block := range black_list {
        if strings.Contains(str, block) {
            return true
        }
    }
    return false
}

func (env *Env) parseClientOutput(p *prog.Prog, idx int, retChan chan parseRet) {

	out := env.outs[idx][env.cmd.outCtlSize+env.cmd.replySize:]
	//this is the position for storing output_pos in executor
	readUint64(&out)
	// ncmd
	ncmd, ok := readUint32(&out)
	if !ok {
		retChan <- parseRet{info: nil, fsMd: nil, err: fmt.Errorf("failed to read number of calls"),
                            idx: idx, callInfo: nil}
		return
	}

	// Read the inode of test-dir for ceph semantic checker
	testdirIno, ok := readUint64(&out)
	if !ok {
		retChan <- parseRet{info: nil, fsMd: nil, err: fmt.Errorf("read st_ino fails"),
							idx: idx, callInfo: nil}
		return
	}
	log.Logf(0, "st_ino: %x\n", testdirIno)

	info := &ProgInfo{Calls: make([]CallInfo, len(p.Calls))}
	extraParts := make([]CallInfo, 0)
	//tao added
	syscall_rets := make([]int, 0, ncmd)
	errnos := make([]int, 0, ncmd)
	//tao end
	log.Logf(0, "[CLIENT] executor %d has %d replies\n", idx, ncmd)
	for i := uint32(0); i < ncmd; i++ {
		if len(out) < int(unsafe.Sizeof(callReply{})) {
			retChan <- parseRet{info: nil, fsMd: nil, err: fmt.Errorf("failed to read call %v reply", i),
                                idx: idx, callInfo: nil}
			return
		}
		reply := *(*callReply)(unsafe.Pointer(&out[0]))
		out = out[unsafe.Sizeof(callReply{}):]
		var inf *CallInfo
		if reply.index != extraReplyIndex && idx >= env.config.ServNum {
			if int(reply.index) >= len(info.Calls) {
				retChan <- parseRet{info: nil, fsMd: nil,
					err: fmt.Errorf("bad call %v index %v/%v", i, reply.index, len(info.Calls)),
                    idx: idx, callInfo: nil}
				return
			}
			if num := p.Calls[reply.index].Meta.ID; int(reply.num) != num {
				retChan <- parseRet{info: nil, fsMd: nil,
					err: fmt.Errorf("wrong call %v num %v/%v", i, reply.num, num),
                    idx: idx, callInfo: nil}
				return
			}
			inf = &info.Calls[reply.index]
			if inf.Flags != 0 || inf.Signal != nil {
				retChan <- parseRet{info: nil, fsMd: nil,
					err: fmt.Errorf("duplicate reply for call %v/%v/%v", i, reply.index, reply.num),
                    idx: idx, callInfo: nil}
				return
			}
			inf.Errno = int(reply.errno)
			errnos = append(errnos, int(reply.errno))
			inf.Flags = CallFlags(reply.flags)
		} else {
			extraParts = append(extraParts, CallInfo{})
			inf = &extraParts[len(extraParts)-1]
		}

		if inf.Signal, ok = readUint32Array(&out, reply.signalSize); !ok {
			retChan <- parseRet{info: nil, fsMd: nil, err: fmt.Errorf("call %v/%v/%v: signal overflow: %v/%v",
				i, reply.index, reply.num, reply.signalSize, len(out)), idx: idx, callInfo: nil}
			return
		}
		if inf.Cover, ok = readUint32Array(&out, reply.coverSize); !ok {
			retChan <- parseRet{info: nil, fsMd: nil, err: fmt.Errorf("call %v/%v/%v: cover overflow: %v/%v",
				i, reply.index, reply.num, reply.coverSize, len(out)), idx: idx, callInfo: nil}
			return
		}
		comps, err := readComps(&out, reply.compsSize)
		if err != nil {
			retChan <- parseRet{info: nil, fsMd: nil, err: err, idx: idx, callInfo: nil}
			return
		}
		inf.Comps = comps
		//tao added
		ret, ok := readUint64(&out)
		if !ok {
			retChan <- parseRet{info: nil, fsMd: nil,
                                err: fmt.Errorf("syscall return value read error\n"),
                                idx: idx, callInfo: nil}
			return
		}
		syscall_ret := int(ret)
		syscall_rets = append(syscall_rets, syscall_ret)

        var checkInfo prog.FileMetadata
        if int32(reply.index) == -1 {
            continue
        }
        p.Calls[reply.index].CheckInfo = &checkInfo
        checkInfo.Stime = reply.stime
        checkInfo.Etime = reply.etime
        checkInfo.Retv = int64(ret)
        if (reply.infotype != -1) {
            infotype := reply.infotype
            // read (0), pread64 (17), and readlink (89)
            if infotype == 0 || infotype == 17 || infotype == 89 {
                checkInfo.Checksum = binary.LittleEndian.Uint32(reply.info[:4])
            // stat (4), and fstat (5)
            } else if infotype == 4 || infotype == 5 {
                ptr := unsafe.Pointer(&(reply.info[0]))
                checkInfo.StatMd = *((*syscall.Stat_t)(ptr))
            // getxattr (191), lgetxattr (192), and fgetxattr (193)
            } else if infotype == 191 || infotype == 192 || infotype == 193 {
                log.Logf(0, "receive getxattr: %v\n", string(reply.info[:]))
                size := binary.LittleEndian.Uint32(reply.info[:4])
                xattr := reply.info[4:size]
                checkInfo.Xattr = make(map[string]string)
                checkInfo.Xattr["file"] = prog.Serialize2Str(xattr)
            // listxattr (194), llistxattr (195), and flistxattr (196)
            } else if infotype == 194 || infotype == 195 || infotype == 196 {
                log.Logf(0, "receive xattr: %v\n", string(reply.info[:]))
                idx := 0
                for ; idx < len(reply.info) && reply.info[idx] != 0; idx ++ {
                }
                xattr := ""
                if idx != 0 {
                    xattr = string(reply.info[:idx])
                }

                filtered_xattr_arr := make([]string, 0)
                for _, substr := range strings.Split(xattr, ";") {
                    if !xattr_filter(substr) {
                        log.Logf(0, "substr: %v", substr)
                        filtered_xattr_arr = append(filtered_xattr_arr, substr)
                    }
                }
                filtered_xattr := ""
                log.Logf(0, "filtered_xattr_arr: %v %v", filtered_xattr_arr, len(filtered_xattr_arr))
                if len(filtered_xattr_arr) != 0 {
                    sort.Strings(filtered_xattr_arr)
                    filtered_xattr = strings.Join(filtered_xattr_arr, ";")+";"
                }
                log.Logf(0, "filtered_xattr: %v\n", filtered_xattr)

                if filtered_xattr != "" {
                    checkInfo.Xattr = make(map[string]string)
                    checkInfo.Xattr["file"] = prog.Serialize2Str([]byte(filtered_xattr))
                }
            // getdents (78)
            } else if infotype == 78 {
                checkInfo.Dents = string(reply.info[:])
            }
        }

		// log.Logf(0, "fuzzer receive %d signal and %d cover from executor %v", reply.signalSize, reply.coverSize, idx)
		//tao end
	}
	if len(extraParts) != 0 {
		info.Extra = convertExtra(extraParts)
	}

	//only kernel clients' will be parsed here
	var fsMd map[string]prog.FileMetadata
	var err error
	if env.config.EnableCsan && idx >= env.config.ServNum {
		fsMd, err = env.parseFsMd(&out)
		if err != nil {
			retChan <- parseRet{info: info, fsMd: nil, err: err, idx: idx}
			return
		}
	}
	retChan <- parseRet{info: info, fsMd: fsMd, err: nil, idx: idx, callInfo: nil, testdirIno: testdirIno}
}

func convertExtra(extraParts []CallInfo) CallInfo {
	var extra CallInfo
	extraCover := make(cover.Cover)
	extraSignal := make(signal.Signal)
	for _, part := range extraParts {
		extraCover.Merge(part.Cover)
		extraSignal.Merge(signal.FromRaw(part.Signal, 0))
	}
	extra.Cover = extraCover.Serialize()
	extra.Signal = make([]uint32, len(extraSignal))
	i := 0
	for s := range extraSignal {
		extra.Signal[i] = uint32(s)
		i++
	}
	return extra
}

func readComps(outp *[]byte, compsSize uint32) (prog.CompMap, error) {
	if compsSize == 0 {
		return nil, nil
	}
	compMap := make(prog.CompMap)
	for i := uint32(0); i < compsSize; i++ {
		typ, ok := readUint32(outp)
		if !ok {
			return nil, fmt.Errorf("failed to read comp %v", i)
		}
		if typ > compConstMask|compSizeMask {
			return nil, fmt.Errorf("bad comp %v type %v", i, typ)
		}
		var op1, op2 uint64
		var ok1, ok2 bool
		if typ&compSizeMask == compSize8 {
			op1, ok1 = readUint64(outp)
			op2, ok2 = readUint64(outp)
		} else {
			var tmp1, tmp2 uint32
			tmp1, ok1 = readUint32(outp)
			tmp2, ok2 = readUint32(outp)
			op1, op2 = uint64(tmp1), uint64(tmp2)
		}
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("failed to read comp %v op", i)
		}
		if op1 == op2 {
			continue // it's useless to store such comparisons
		}
		compMap.AddComp(op2, op1)
		if (typ & compConstMask) != 0 {
			// If one of the operands was const, then this operand is always
			// placed first in the instrumented callbacks. Such an operand
			// could not be an argument of our syscalls (because otherwise
			// it wouldn't be const), thus we simply ignore it.
			continue
		}
		compMap.AddComp(op1, op2)
	}
	return compMap, nil
}

func readUint32(outp *[]byte) (uint32, bool) {
	out := *outp
	if len(out) < 4 {
		return 0, false
	}
	v := prog.HostEndian.Uint32(out)
	*outp = out[4:]
	return v, true
}

func readUint64(outp *[]byte) (uint64, bool) {
	out := *outp
	if len(out) < 8 {
		return 0, false
	}
	v := prog.HostEndian.Uint64(out)
	*outp = out[8:]
	return v, true
}

func readUint32Array(outp *[]byte, size uint32) ([]uint32, bool) {
	if size == 0 {
		return nil, true
	}
	out := *outp
	if int(size)*4 > len(out) {
		return nil, false
	}
	var res []uint32
	hdr := (*reflect.SliceHeader)((unsafe.Pointer(&res)))
	hdr.Data = uintptr(unsafe.Pointer(&out[0]))
	hdr.Len = int(size)
	hdr.Cap = int(size)
	*outp = out[size*4:]
	return res, true
}

type command struct {
	pid        int
	config     *Config
	timeout    time.Duration
	cmds       []*exec.Cmd
	dir        string
	readDone   chan []byte
	exited     chan struct{}
	inrp       *os.File
	outwp      *os.File
	outmems    [][]byte
	inmem      []byte
	callOrder  []byte
	inFile     *os.File
	outFile    *os.File
	outCtlSize uint64
	replySize  uint64
}

const (
	inMagic  = uint64(0xbadc0ffeebadface)
	outMagic = uint32(0xbadf00d)
)

type handshakeReq struct {
	magic uint64
	flags uint64 // env flags
	pid   uint64
}

type handshakeReply struct {
	magic uint32
}

type executeControl struct {
	hasTestcase       [64]byte
	coverEnabled      [64]byte
	executionsFinish  [64]byte
	tmpDirEstablished byte
	synchBit          uint64
	lockByte2		  byte
	lockByte3		  byte
	servSetupBit	  uint64
}

type CallOrderControl struct {
  //lockByte byte;
  cnt byte;
}

type executeReq struct {
	magic            uint64
	envFlags         uint64 // env flags
	execFlags        uint64 // exec flags
	pid              uint64
	syscallTimeoutMS uint64
	programTimeoutMS uint64
	slowdownScale    uint64
	executionIdx     uint64
	progSizes        [64]uint64
	progOffsets      [64]uint64
	// This structure is followed by a serialized test program in encodingexec format.
	// Both when sent over a pipe or in shared memory.
}

type executeReply struct {
	magic uint32
	// If done is 0, then this is call completion message followed by callReply.
	// If done is 1, then program execution is finished and status is set.
	done   uint32
	status uint32
}

type callReply struct {
	index      uint32 // call index in the program
	num        uint32 // syscall number (for cross-checking)
	errno      uint32
    infotype   int32
    info       [144]byte
    stime      uint64
    etime      uint64
	flags      uint32 // see CallFlags
	signalSize uint32
	coverSize  uint32
	compsSize  uint32
	// signal/cover/comps follow
}

func makeCommand(pid int, bins [][]string, config *Config, inFile, outFile *os.File, inmem []byte, outmems [][]byte,
	tmpDirPath string, callOrder []byte) (*command, error) {
	dir, err := ioutil.TempDir(tmpDirPath, "syzkaller-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}
	dir = osutil.Abs(dir)

	timeout := config.Timeouts.Program
	if config.UseForkServer {
		// Executor has an internal timeout and protects against most hangs when fork server is enabled,
		// so we use quite large timeout. Executor can be slow due to global locks in namespaces
		// and other things, so let's better wait than report false misleading crashes.
		timeout *= 10
	}

	var outctl outputControl
	var reply executeReply
	c := &command{
		pid:        pid,
		config:     config,
		timeout:    timeout,
		dir:        dir,
		outmems:    outmems,
		inmem:      inmem,
		callOrder:	callOrder,
		inFile:     inFile,
		outFile:    outFile,
		outCtlSize: uint64(unsafe.Sizeof(outctl)),
		replySize:  uint64(unsafe.Sizeof(reply)),
	}
	defer func() {
		if c != nil {
			c.close()
		}
	}()

	//tao del
	/*
		if err := os.Chmod(dir, 0777); err != nil {
			return nil, fmt.Errorf("failed to chmod temp dir: %v", err)
		}
	*/

	c.readDone = make(chan []byte, 1)
	c.exited = make(chan struct{})

	// Output capture pipe.
	rp, wp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer wp.Close()

	if config.Flags&FlagDebug != 0 {
		close(c.readDone)
	} else {
		go func(c *command) {
			// Read out output in case executor constantly prints something.
			const bufSize = 128 << 10
			output := make([]byte, bufSize)
			var size uint64
			for {
				n, err := rp.Read(output[size:])
				if n > 0 {
					size += uint64(n)
					if size >= bufSize*3/4 {
						copy(output, output[size-bufSize/2:size])
						size = bufSize / 2
					}
				}
				if err != nil {
					rp.Close()
					c.readDone <- output[:size]
					close(c.readDone)
					return
				}
			}
		}(c)
	}

	for _, bin := range bins {

		/*
			    // executor->ipc command pipe.
			    inrp, inwp, err := os.Pipe()
			    if err != nil {
				    return nil, fmt.Errorf("failed to create pipe: %v", err)
			    }
			    defer inwp.Close()
			    c.inrp = inrp

			    // ipc->executor command pipe.
			    outrp, outwp, err := os.Pipe()
			    if err != nil {
				    return nil, fmt.Errorf("failed to create pipe: %v", err)
			    }
			    defer outrp.Close()
			    c.outwp = outwp
		*/

		log.Logf(0, "-----run executor: %v\n", bin)

		cmd := osutil.Command(bin[0], bin[1:]...)
		if inFile != nil && outFile != nil {
			cmd.ExtraFiles = []*os.File{inFile, outFile}
		}
		cmd.Dir = dir
		// Tell ASAN to not mess with our NONFAILING.
		cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")

		//cmd.Stdin = outrp
		//cmd.Stdout = inwp
		/*
		if config.Flags&FlagDebug != 0 {
			cmd.Stderr = os.Stdout
		} else {
			cmd.Stderr = wp
		}
		*/
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start executor binary: %v", err)
		}
		c.cmds = append(c.cmds, cmd)
		wp.Close()

		/*
		   // Note: we explicitly close inwp before calling handshake even though we defer it above.
		   // If we don't do it and executor exits before writing handshake reply,
		   // reading from inrp will hang since we hold another end of the pipe open.
		   inwp.Close()
		*/
	}

	if c.config.UseForkServer {
		if err := c.handshake(0, len(c.outmems)); err != nil {
			return nil, err
		}
	}

	tmp := c
	c = nil // disable defer above

	return tmp, nil
}

//TODO, readDone and goroutine
func (c *command) makeOneCommand(bin []string) (error, *exec.Cmd) {

	/*
	rp, wp, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %v", err), nil
	}
	defer wp.Close()

	c.readDone = make(chan []byte, 1)
	c.exited = make(chan struct{})
	*/
	cmd := osutil.Command(bin[0], bin[1:]...)
	if c.inFile != nil && c.outFile != nil {
		cmd.ExtraFiles = []*os.File{c.inFile, c.outFile}
	}
	cmd.Dir = c.dir
	// Tell ASAN to not mess with our NONFAILING.
	cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")
	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stdout
	/*
	if c.config.Flags&FlagDebug != 0 {
		close(c.readDone)
		cmd.Stderr = os.Stdout
	} else {
		cmd.Stderr = wp
		go func(c *command) {
			// Read out output in case executor constantly prints something.
			const bufSize = 128 << 10
			output := make([]byte, bufSize)
			var size uint64
			for {
				n, err := rp.Read(output[size:])
				if n > 0 {
					size += uint64(n)
					if size >= bufSize*3/4 {
						copy(output, output[size-bufSize/2:size])
						size = bufSize / 2
					}
				}
				if err != nil {
					rp.Close()
					c.readDone <- output[:size]
					close(c.readDone)
					return
				}
			}
		}(c)
	}
	*/
	time.Sleep(8 * time.Second)
	log.Logf(0, "before cmd start\n")
	log.Logf(0, "-----run executor: %v\n", bin)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start executor binary: %v", err), nil
	}
	log.Logf(0, "cmd start succeeds\n")
	//wp.Close()
	return nil, cmd
}

func (c *command) close() {
	if c.cmds != nil {
		for idx, cmd := range c.cmds {
			cmd.Process.Kill()
			c.wait(idx)
		}
	}
	osutil.RemoveAll(c.dir)
	if c.inrp != nil {
		c.inrp.Close()
	}
	if c.outwp != nil {
		c.outwp.Close()
	}
}

func (c *command) restartExecutorCmd(idx int) error {

	var argIdx int
	var arg string
	for argIdx, arg = range c.cmds[idx].Args {
		if arg == "/root/syz-executor" {
			break
		}
	}
	argIdx = argIdx + 8

	//set is_restarting = 1
	if len(c.cmds[idx].Args) >= argIdx {
		c.cmds[idx].Args[argIdx] = "1"
	}

	log.Logf(0, "restarting cmd tag bit %d, %v", c.outmems[idx][0], c.cmds[idx].Args)

	err, cmd := c.makeOneCommand(c.cmds[idx].Args)
	if err != nil {
		log.Logf(0, "restarting cmd: failed to makeOneCommand: ", err)
		return err
	}
	c.cmds[idx] = cmd
	log.Logf(0, "restarting cmd finished\n")

	/*
		if err := c.cmds[idx].Process.Kill(); err != nil {
			log.Logf(0, "restarting cmd: failed to kill process: ", err)
		}

		if err := c.cmds[idx].Start(); err != nil {
			log.Logf(0, "restarting cmd failed: %v\n", err)
			return fmt.Errorf("failed to start executor binary: %v", err)
		}
		log.Logf(0, "restarting cmd finished\n")
	*/

	/*
	   if c.config.UseForkServer {
	       if err := c.handshake(idx, idx+1); err != nil {
	           return err
	       }
	   }
	*/
	return nil
}

// handshake sends handshakeReq and waits for handshakeReply.
func (c *command) handshake(startIdx int, stopIdx int) error {
	req := &handshakeReq{
		magic: inMagic,
		flags: uint64(c.config.Flags),
		pid:   uint64(c.pid),
	}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	//tao added
	//inmem = tag | reqData | progData
	/*
	   for {
	       if c.inmem[0] == 0 {
	           break
	       }
	   }
	*/

	execCtl := &executeControl{}
	copy(c.inmem[unsafe.Sizeof(*execCtl):], reqData)
	//len(c.outmems)
	for i := startIdx; i < stopIdx; i++ {
		execCtl.hasTestcase[i] = 1
	}
	execCtlData := (*[unsafe.Sizeof(*execCtl)]byte)(unsafe.Pointer(execCtl))[:]
	copy(c.inmem[:unsafe.Sizeof(*execCtl)], execCtlData)
	//tao end
	//if _, err := c.outwp.Write(reqData); err != nil {
	//	return c.handshakeError(fmt.Errorf("failed to write control pipe: %v", err))
	//}

	read := make(chan error, 1)
	go func() {
		reply := &handshakeReply{}
		replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
		//outmem = tag|executeReply|call count|call reply

		//executorNum := len(c.outmems)
		//var handshakes int = 0

		for i := startIdx; i < stopIdx; i++ {

			for c.outmems[i][0] != 1 {
			}

			log.Logf(0, "----- before executor %d handshake recv reply %v\n", i, reply)

			copy(replyData, c.outmems[i][c.outCtlSize:])
			c.outmems[i][0] = 0

			log.Logf(0, "----- after executor %d handshake recv reply %v at %v\n", i, reply, c.outCtlSize)

			if reply.magic != outMagic {
				read <- fmt.Errorf("executor %d bad handshake reply magic 0x%x", i, reply.magic)
				return
			}

			log.Logf(0, "----- handshake %d finished <- nil\n", i)
		}

		read <- nil
	}()
	// Sandbox setup can take significant time.
	timeout := time.NewTimer(time.Minute * c.config.Timeouts.Scale * 3)
	select {
	case err := <-read:
		timeout.Stop()
		log.Logf(0, "----- handshake timeout\n")
		if err != nil {
			log.Logf(0, "----- handshake error %v\n", err)
			return c.handshakeError(err)
		}
		log.Logf(0, "----- handshake return\n")
		return nil
	case <-timeout.C:
		return c.handshakeError(fmt.Errorf("not serving"))
	}
}

func (c *command) handshakeError(err error) error {
	for i := 0; i < len(c.cmds); i++ {
		c.cmds[i].Process.Kill()
		output := <-c.readDone
		err = fmt.Errorf("executor %v: %v\n%s", c.pid, err, output)
		if err != nil {
			return err
		}
		c.wait(i)
	}
	return nil
}

func (c *command) wait(idx int) error {
	err := c.cmds[idx].Wait()
	select {
	case <-c.exited:
		// c.exited closed by an earlier call to wait.
	default:
		close(c.exited)
	}
	return err
}


func printExecutors(dfsName string) {

	if dfsName != "nfs" {
		return
	}

	args := []string{"-i", "/home/tlyu/dfs-fuzzing/disk-images/nfs-images/stretch.id_rsa", "-o", "StrictHostKeyChecking no", "root@192.168.0.8", "pstree", "-p"}
    out, _ := exec.Command("ssh", args...).Output()
    fmt.Println(string(out))

	args = []string{"-i", "/home/tlyu/dfs-fuzzing/disk-images/nfs-images/stretch.id_rsa", "-o", "StrictHostKeyChecking no", "root@192.168.0.9", "pstree", "-p"}
    out, _ = exec.Command("ssh", args...).Output()
    fmt.Println(string(out))
}

var executionIdx uint64 = 0

func (c *command) exec(opts *ExecOpts, progData []byte, progSizes [64]uint64, progOffsets [64]uint64) (output []byte, hanged bool, err0 error) {

	req := &executeReq{
		magic:            inMagic,
		envFlags:         uint64(c.config.Flags),
		execFlags:        uint64(opts.Flags),
		pid:              uint64(c.pid),
		syscallTimeoutMS: uint64(c.config.Timeouts.Syscall / time.Millisecond),
		programTimeoutMS: uint64(c.config.Timeouts.Program / time.Millisecond),
		slowdownScale:    uint64(c.config.Timeouts.Scale),
		executionIdx:     executionIdx,
		progSizes:        progSizes,
		progOffsets:      progOffsets,
	}

	executionIdx += 1

	err0 = nil
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	zeroOut := make([]byte, unsafe.Sizeof(executeReply{})+1)

	//tao added
	if c.config.UseShmem {

		//zero CallOrderControl
	    callOrderCtl := &CallOrderControl{}
		callOrderCtlData := (*[unsafe.Sizeof(*callOrderCtl)]byte)(unsafe.Pointer(callOrderCtl))[:]
		copy(c.callOrder, callOrderCtlData);

		//inmem = flag(uint64) | dir_create(1 byte) | reqData | progData
		execCtl := &executeControl{}
		copy(c.inmem[unsafe.Sizeof(*execCtl):], reqData)
		for i := 0; i < len(c.outmems); i++ {
			copy(c.outmems[i], zeroOut)
			execCtl.hasTestcase[i] = 1
			//execCtl.hasTestcase[i] = 1
		}
		execCtlData := (*[unsafe.Sizeof(*execCtl)]byte)(unsafe.Pointer(execCtl))[:]
		copy(c.inmem[:unsafe.Sizeof(*execCtl)], execCtlData)

		hang := make(chan bool)
		stop := make(chan bool)
		exitStatusChan := make(chan int)

		//outmem = tag|executeReply|call count|cal reply
		go func() {
			var wg sync.WaitGroup
			for i := len(c.outmems) - 1; i >= 0; i-- {
				wg.Add(1)
				go func(idx int, wg *sync.WaitGroup) {
					defer wg.Done()
					//execution finishes, including crashes or normal finish
					msg := uint32(0)
					for ; msg == 0; {
						select {
						case <-stop:
							return
						default:
							//if c.outmems[i][0] != 0 {
							msg32 := binary.LittleEndian.Uint32(c.outmems[idx])
							msg = atomic.LoadUint32(&msg32) & 0xff
							if msg != 0 {
								log.Logf(0, "for select break: %d", msg)
							}
						}
					}

					//msg32 := binary.LittleEndian.Uint32(c.outmems[i])
					//msg := atomic.LoadUint32(&msg32) & 0xff
					//Non-normal execution finish
					if msg != 1 {
						//time.Sleep(30 * time.Second)
						c.restartExecutorCmd(idx)
						for ; msg != 1; {
							select {
							case <-stop:
								return
							default:
								msg32 := binary.LittleEndian.Uint32(c.outmems[idx])
								msg = atomic.LoadUint32(&msg32) & 0xff
								if msg == 1 {
									log.Logf(0, "for select break 2: %d", msg)
								}
							}
						}
						log.Logf(0, "loop after restartExecutorCmd finishes\n")
					}

					//msg32 = binary.LittleEndian.Uint32(c.outmems[i])
					//msg = atomic.LoadUint32(&msg32) & 0xff
					if msg == 1 {
						//exitStatus := -1
						reply := &executeReply{}
						replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
						copy(replyData, c.outmems[idx][c.outCtlSize:])
						c.outmems[idx][0] = 0

						if reply.magic != outMagic {
							fmt.Fprintf(os.Stderr, "executor %v: got bad reply magic 0x%x %v %v\n", c.pid, reply.magic, reply, c.outmems[idx][:15])
							os.Exit(1)
						}
						log.Logf(0, "--------- executor %d receive reply, reply.done %d\n", idx, reply.done)

						if reply.status != 0 {
							exitStatusChan <- int(reply.status)
							return
						}
					}
				}(i, &wg)
			}
			wg.Wait()
			log.Logf(0, "wg wait finish")
			hang <- false
		}()

		select {
		case exitStatus := <-exitStatusChan:
			//c.cmd.Process.Kill()
			output = <-c.readDone
			//wait()
			/*err := c.wait()
			  if err := c.wait(); <-hang {
			      hanged = true
			      if err != nil {
			          output = append(output, err.Error()...)
			          output = append(output, '\n')
			      }
			      return
			  }
			  if exitStatus == -1 {
			      exitStatus = osutil.ProcessExitStatus(c.cmd.ProcessState)
			  }*/
			// Ignore all other errors.
			// Without fork server executor can legitimately exit (program contains exit_group),
			// with fork server the top process can exit with statusFail if it wants special handling.
			if exitStatus == statusFail {
				err0 = fmt.Errorf("executor %v: exit status %d\n%s", c.pid, exitStatus, output)
			} else {
				err0 = fmt.Errorf("executor %v: exit status %d\n%s", c.pid, exitStatus, output)
			}
		case <-hang:
			log.Logf(0, "------ all executors finish execution")
		case <-time.After(200 * time.Second):
			stop <- true
			err0 = fmt.Errorf("executors hang and timeout")
			output = <-c.readDone
		}
		/*
		   if reply.done != 0 {
		       exitStatus = int(reply.status)
		       break
		   }
		*/
		//c.inmem[8] = 0
		return
	}
	//tao end

	/*
		if _, err := c.outwp.Write(reqData); err != nil {
			output = <-c.readDone
			err0 = fmt.Errorf("executor %v: failed to write control pipe: %v", c.pid, err)
			return
		}
		if progData != nil {
			if _, err := c.outwp.Write(progData); err != nil {
				output = <-c.readDone
				err0 = fmt.Errorf("executor %v: failed to write control pipe: %v", c.pid, err)
				return
			}
		}
		// At this point program is executing.

		done := make(chan bool)
		hang := make(chan bool)
		go func() {
			t := time.NewTimer(c.timeout)
			select {
			case <-t.C:
				c.cmd.Process.Kill()
				hang <- true
			case <-done:
				t.Stop()
				hang <- false
			}
		}()
		exitStatus := -1
		completedCalls := (*uint32)(unsafe.Pointer(&c.outmem[0]))
		outmem := c.outmem[4:]
		for {
			reply := &executeReply{}
			replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
			if _, err := io.ReadFull(c.inrp, replyData); err != nil {
				break
			}
			if reply.magic != outMagic {
				fmt.Fprintf(os.Stderr, "executor %v: got bad reply magic 0x%x\n", c.pid, reply.magic)
				os.Exit(1)
			}
			if reply.done != 0 {
				exitStatus = int(reply.status)
				break
			}
			callReply := &callReply{}
			callReplyData := (*[unsafe.Sizeof(*callReply)]byte)(unsafe.Pointer(callReply))[:]
			if _, err := io.ReadFull(c.inrp, callReplyData); err != nil {
				break
			}
			if callReply.signalSize != 0 || callReply.coverSize != 0 || callReply.compsSize != 0 {
				// This is unsupported yet.
				fmt.Fprintf(os.Stderr, "executor %v: got call reply with coverage\n", c.pid)
				os.Exit(1)
			}

			copy(outmem, callReplyData)
			outmem = outmem[len(callReplyData):]
			*completedCalls++
		}
		close(done)
		if exitStatus == 0 {
			// Program was OK.
			<-hang
			return
		}
		c.cmd.Process.Kill()
		output = <-c.readDone
		if err := c.wait(); <-hang {
			hanged = true
			if err != nil {
				output = append(output, err.Error()...)
				output = append(output, '\n')
			}
			return
		}
		if exitStatus == -1 {
			exitStatus = osutil.ProcessExitStatus(c.cmd.ProcessState)
		}
		// Ignore all other errors.
		// Without fork server executor can legitimately exit (program contains exit_group),
		// with fork server the top process can exit with statusFail if it wants special handling.
		if exitStatus == statusFail {
			err0 = fmt.Errorf("executor %v: exit status %d\n%s", c.pid, exitStatus, output)
		}
	*/
	return
}
