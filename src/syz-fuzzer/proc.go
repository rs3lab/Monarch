// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
    "bytes"
    "fmt"
    "math/rand"
    "os"
    //"runtime/debug"
    "sync/atomic"
    "syscall"
    "time"
    //"sync"
    //"io/ioutil"
    //"strings"

    "monarch/checker"
    "monarch/pkg/cover"
    "monarch/pkg/hash"
    "monarch/pkg/ipc"
    "monarch/pkg/log"
    "monarch/pkg/rpctype"
    "monarch/pkg/signal"
    "monarch/prog"
    "gonum.org/v1/gonum/stat/combin"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
    fuzzer *Fuzzer
    pid    int
    env    *ipc.Env
    rnd               *rand.Rand
    execOpts          *ipc.ExecOpts
    execOptsCover     *ipc.ExecOpts
    execOptsComps     *ipc.ExecOpts
    execOptsNoCollide *ipc.ExecOpts
    freqCov           int32
    cltTick           chan bool
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
    env, err := ipc.MakeEnv(fuzzer.config, pid, fuzzer.config.InitShmId)
    if err != nil {
        return nil, err
    }
    rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
    execOptsNoCollide := *fuzzer.execOpts
    execOptsNoCollide.Flags &= ^ipc.FlagCollide
    execOptsCover := execOptsNoCollide
    execOptsCover.Flags |= ipc.FlagCollectCover
    execOptsComps := execOptsNoCollide
    execOptsComps.Flags |= ipc.FlagCollectComps

    freqCov := int32(10)
    cltTick := make(chan bool)

    go func() {
        ticker := time.NewTicker(3 * time.Minute).C
        for {
            select {
                case <- ticker:
                    atomic.StoreInt32(&freqCov, 0)
                case <- cltTick:
                    atomic.AddInt32(&freqCov, 1)
            }
        }
    }()

    proc := &Proc{
        fuzzer: fuzzer,
        pid:    pid,
        env:    env,
        rnd:               rnd,
        execOpts:          fuzzer.execOpts,
        execOptsCover:     &execOptsCover,
        execOptsComps:     &execOptsComps,
        execOptsNoCollide: &execOptsNoCollide,
        freqCov: freqCov,
        cltTick: cltTick,
    }
    return proc, nil
}

func (proc *Proc) loop() {
    generatePeriod := 100
    if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
        // If we don't have real coverage signal, generate programs more frequently
        // because fallback signal is weak.
        generatePeriod = 2
    }
    for i := 0; ; i++ {
        item := proc.fuzzer.workQueue.dequeue()
        if item != nil {
            switch item := item.(type) {
            case *WorkTriage:
                proc.triageInput(item)
            case *WorkCandidate:
                proc.execute(proc.execOpts, item.ps, item.flags, StatCandidate)
            case *WorkSmash:
                proc.smashInput(item)
            default:
                log.Fatalf("unknown work type: %#v", item)
            }
            continue
        }

        ct := proc.fuzzer.choiceTable
        fuzzerSnapshot := proc.fuzzer.snapshot()
        if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
            // Generate a new prog.
            //tao modified
            var ps []*prog.Prog
            rand.Seed(time.Now().UnixNano())
            //Generate empty subtestcase for servers
            for idx := 0; idx < proc.fuzzer.config.ServNum; idx++ {
                p, _ := proc.fuzzer.target.Generate(proc.rnd, 0, nil, nil, true, proc.fuzzer.sCalls,
                                                    proc.fuzzer.config.EnableC2san)
                ps = append(ps, p)
            }
            //Generate subtestcases for clients
            subTsNum := proc.fuzzer.config.FuzzingVMs - proc.fuzzer.config.ServNum
            var files map[string]bool
            for idx := 0; idx < subTsNum; {
                repeatNum := rand.Intn(subTsNum-idx) + 1
                p, newFiles := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct, files, false,
                                                            proc.fuzzer.sCalls, proc.fuzzer.config.EnableC2san)
                log.Logf(0, "%v", newFiles)
                files = newFiles
                ps = append(ps, p)
                for i := 0; i < repeatNum-1; i++ {
                    cpyProg := p.Clone()
                    ps = append(ps, cpyProg)
                }
                idx += repeatNum
            }
            //tao end
            log.Logf(1, "#%v: generated", proc.pid)
            proc.execute(proc.execOpts, ps, ProgNormal, StatGenerate)
        } else {
            // Mutate an existing prog.
            //tao modified
            var ps []*prog.Prog
            seedPS := fuzzerSnapshot.chooseProgram(proc.rnd)
            if !seedPS[0].HasCrashFail && !seedPS[0].HasNetFail &&
              (proc.fuzzer.config.NetFailure || proc.fuzzer.config.NodeCrash) &&
              prog.OutOfWrap(proc.rnd, seedPS[0].Target, 1, 5) {
                ps = prog.Clones(seedPS)
                prog.RandomInsertFailure(ps, proc.fuzzer.config.ServNum, proc.rnd, proc.fuzzer.sCalls,
                                                                                        proc.fuzzer.config.InitIp)
                log.Logf(1, "#%v: random insert failure", proc.pid)
                proc.execute(proc.execOptsCover, ps, ProgNormal, StatFailureEnum)
            } else {
                for idx, tmp_p := range seedPS {
                    p := tmp_p.Clone()
                    if idx >= proc.fuzzer.config.ServNum {
                        p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus,
                                proc.fuzzer.sCalls, proc.fuzzer.config.ServNum,
                                seedPS[0].HasCrashFail||seedPS[0].HasNetFail, proc.fuzzer.config.EnableC2san)
                    } else {
                    }
                    ps = append(ps, p)
                }
                log.Logf(1, "#%v: mutated", proc.pid)
                proc.execute(proc.execOpts, ps, ProgNormal, StatFuzz)
            }
            //tao end
        }
    }
}

func (proc *Proc) triageInput(item *WorkTriage) {
    log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

    prio := signalPrio(item.ps[item.subNum], &item.info, item.call)
    inputSignal := signal.FromRaw(item.info.Signal, prio)
    newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
    if newSignal.Empty() {
        return
    }
    callName := ".extra"
    logCallName := "extra"
    if item.call != -1 {
        callName = item.ps[item.subNum].Calls[item.call].Meta.Name
        logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
    }
    log.Logf(3, "1 triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
    var SrvCover, CliCover cover.Cover
    const (
        signalRuns       = 3
        minimizeAttempts = 3
    )
    // Compute input coverage and non-flaky signal for minimization.
    notexecuted := 0
    for i := 0; i < signalRuns; i++ {
        infos, _, _ := proc.executeRaw(proc.execOptsCover, item.ps, StatTriage)
        if !reexecutionSuccess(infos[item.subNum], &item.info, item.call) {
            // The call was not executed or failed.
            notexecuted++
            if notexecuted > signalRuns/2+1 {
                log.Logf(0, "----- triage return due to unsuccessful execution %s", logCallName)
                return // if happens too often, give up
            }
            continue
        }
        thisSignal, _ := getSignalAndCover(item.ps[item.subNum], infos[item.subNum], item.call)
        newSignal = newSignal.Intersection(thisSignal)
        // Without !minimized check manager starts losing some considerable amount
        // of coverage after each restart. Mechanics of this are not completely clear.
        if newSignal.Empty() && item.flags&ProgMinimized == 0 {
            log.Logf(0, "----- triage return due to empty signal %s", logCallName)
            return
        }
    }

    if item.flags&ProgMinimized == 0 && item.subNum >= proc.fuzzer.config.ServNum {
        item.ps, item.call = prog.Minimize(item.ps, item.call, item.subNum, false, proc.fuzzer.config.ServNum,
            func(ps1 []*prog.Prog, call1 int) bool {
                for i := 0; i < minimizeAttempts; i++ {
                    infos := proc.execute(proc.execOptsNoCollide, ps1, ProgNormal, StatMinimize)
                    if !reexecutionSuccess(infos[item.subNum], &item.info, call1) {
                        // The call was not executed or failed.
                        continue
                    }
                    thisSignal, _ := getSignalAndCover(ps1[item.subNum], infos[item.subNum], call1)
                    if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
                        return true
                    }
                }
                return false
            })
    }

    //#issue: why the testcase after minimized is empty.
    totalLen := 0
    for _, p := range item.ps {
        totalLen += len(p.Calls)
    }
    if totalLen == 0 {
        return
    }

    //Merge server coverage
    var inputCliSignal, inputSrvSignal signal.Signal
    srvNum := proc.fuzzer.config.ServNum
    for i := 0; i < signalRuns; i++ {
        infos, _, _ := proc.executeRaw(proc.execOptsCover, item.ps, StatTriage) //TODO
        thisSignal, thisCover := getSignalAndCover(item.ps[item.subNum], infos[item.subNum], item.call)
        if item.triageClient {
            CliCover.Merge(thisCover)
            inputCliSignal.Merge(thisSignal)
            for idx, info := range infos[:srvNum] {
                //proc.fuzzer.checkNewSignal(item.ps[idx], info)
                thisSignal, thisCover := getSignalAndCover(item.ps[idx], info, -1)
                inputSrvSignal.Merge(thisSignal)
                SrvCover.Merge(thisCover)
            }
        } else {
            SrvCover.Merge(thisCover)
            inputSrvSignal.Merge(thisSignal)
            for idx, info := range infos {
                if idx < srvNum {
                    continue
                }
                //proc.fuzzer.checkNewSignal(item.ps[idx], info)
                thisSignal, thisCover := getAllSignalAndCover(item.ps[idx], info)
                inputCliSignal.Merge(thisSignal)
                CliCover.Merge(thisCover)
            }
        }
    }

    var data [][]byte
    var dataForHash []byte
    for _, p := range item.ps {
        prog := p.Serialize()
        data = append(data, prog)
        dataForHash = append(dataForHash, prog...)
    }
    sig := hash.Hash(dataForHash)

    log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, dataForHash)
    proc.fuzzer.sendInputToManager(rpctype.RPCInput{
        Call:      callName,
        Prog:      data,
        CliSignal: inputCliSignal.Serialize(),
        SrvSignal: inputSrvSignal.Serialize(),
        SrvCover:  SrvCover.Serialize(),
        CliCover:  CliCover.Serialize(),
    })

    if item.call != -1 {
        proc.cltTick <- true
    }

    log.Logf(0, "triageInput addInputToCorpus: HasCrashFail: %v, HasNetFail: %v", item.ps[0].HasCrashFail, item.ps[0].HasNetFail)
    proc.fuzzer.addInputToCorpus(item.ps, inputCliSignal, inputSrvSignal, sig)

    if item.flags&ProgSmashed == 0 {
        proc.fuzzer.workQueue.enqueue(&WorkSmash{item.ps, item.call, item.subNum})
    }
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
    if info == nil {
        return false
    }
    if call != -1 {
        // Don't minimize calls from successful to unsuccessful.
        // Successful calls are much more valuable.
        if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
            return false
        }
        return len(info.Calls[call].Signal) != 0
    }
    return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
    inf := &info.Extra
    if call != -1 {
        inf = &info.Calls[call]
    }
    return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func getAllSignalAndCover(p *prog.Prog, info *ipc.ProgInfo) (signals signal.Signal, covers []uint32) {
    for call, inf := range info.Calls {
        infp := &inf
        signals.Merge(signal.FromRaw(infp.Signal, signalPrio(p, infp, call)))
        covers = append(covers, infp.Cover...)
    }
    return
}

func (proc *Proc) smashInput(item *WorkSmash) {
    if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
        proc.executeHintSeed(item.ps, item.call, item.subNum)
    }
    //
    rand.Seed(time.Now().UnixNano())
    srvNum := proc.fuzzer.config.ServNum
    psNum := len(item.ps)
    fuzzerSnapshot := proc.fuzzer.snapshot()

    //Failure enumeration
    if (proc.fuzzer.config.NetFailure || proc.fuzzer.config.NodeCrash) && !(item.ps[0].HasNetFail || item.ps[0].HasCrashFail) {
        proc.enumFailures(item.ps)
    }

    //Normal mutation
    for i := 0; i < 100; i++ {
        ps := prog.Clones(item.ps)
        /*
            Each time only mutate one sub-testcase because: If we do multiple mutations and only one of them trigger new
            coverage, we can't know which one contributes to the coverage and thus the testcases will have redudant
            syscalls. However, this non-mutual mutation might not generate testcases towards more interleavings.
        */
        //Tao TODO

        var randIdx int
        log.Logf(0, "NetFailure, Node crash: %v %v", proc.fuzzer.config.NetFailure, proc.fuzzer.config.NodeCrash)
        randIdx = rand.Intn(psNum-srvNum) + srvNum
        ps[randIdx].Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus,
            proc.fuzzer.sCalls, proc.fuzzer.config.ServNum, ps[0].HasCrashFail||ps[0].HasNetFail,
            proc.fuzzer.config.EnableC2san)
        log.Logf(1, "#%v: smash mutated %d-th subtestcase", proc.pid, randIdx)
        proc.execute(proc.execOpts, ps, ProgNormal, StatSmash)
    }
}

/*
    For partiton between a (server) and b (server/client), 
    check whether a has already has other partitions with other nodes.
    If yes, combine them into the PartNodes.
    Otherwise, add a new SrvFailInfo
*/
func updateComb(comb []prog.SrvFailInfo, node int, partNode int) ([]prog.SrvFailInfo) {
    for _, item := range comb {
        if item.Srv == node {
            item.PartNodes = append(item.PartNodes, partNode)
            log.Logf(0, "updateComb: %v", comb)
            return comb
        }
    }
    comb = append(comb, prog.SrvFailInfo{node, []int{partNode}})
    return comb
}

func subset1(cluster []int, cnt int) (ret []int) {
    numMap := make(map[int]bool)
    rand.Seed(time.Now().UnixNano())
    length := len(cluster)
    for i:=0; i<cnt; i++ {
        idx := 0
        for ; true ; {
            idx = rand.Intn(length)
            if _, ok := numMap[cluster[idx]]; !ok {
                break
            }
        }
        numMap[cluster[idx]] = true
        ret = append(ret, cluster[idx])
    }
    return ret
}

func subset2(cluster []prog.Conn, cnt int) (ret []prog.Conn) {
    numMap := make(map[prog.Conn]bool)
    rand.Seed(time.Now().UnixNano())
    length := len(cluster)
    for i:=0; i<cnt; i++ {
        idx := 0
        for ; true ; {
            idx = rand.Intn(length)
            if _, ok := numMap[cluster[idx]]; !ok {
                break
            }
        }
        numMap[cluster[idx]] = true
        ret = append(ret, cluster[idx])
    }
    return ret
}

/*
genNodeCombs: generate all combinations of srvNum.
*/
func genNodeCombs(srvNum int) (combs [][]prog.SrvFailInfo) {
    //for sub := 1; sub <= srvNum; sub++ {
    for sub := 1; sub <= 1; sub++ {
        //Generate combinations
        idxCombs := combin.Combinations(srvNum, sub)
        for _, c := range idxCombs {
            comb := make([]prog.SrvFailInfo, 0)
            for _, i := range c {
                comb = append(comb, prog.SrvFailInfo{i, nil})
            }
            combs = append(combs, comb)
        }
    }
    log.Logf(0, "genNodeCombs: %v", combs)
    return combs
}

func genEdgeCombs(srvNum int, cltNum int) (combs [][]prog.SrvFailInfo) {

    conns := make([]prog.Conn, 0)
    //Generate edges
    for i := 0;  i < srvNum; i++ {
        for j := i+1;  j < srvNum + cltNum; j++ {
            conns = append(conns, prog.Conn{i, j})
        }
    }

    //Combinations
    //for sub := 1; sub <= len(conns); sub++ {
    for sub := 1; sub <= 1; sub++ {
        for _, c := range combin.Combinations(len(conns), sub) {
            comb := make([]prog.SrvFailInfo, 0)
            for _, i := range c {
                if conns[i].From <= srvNum {
                    comb = updateComb(comb, conns[i].From, conns[i].To)
                } else if conns[i].To <= srvNum {
                    comb = updateComb(comb, conns[i].To, conns[i].From)
                }
            }
            combs = append(combs, comb)
        }
    }
    log.Logf(0, "combs: %v", combs)
    return combs
}

func (proc *Proc) enumInner(combs [][]prog.SrvFailInfo, ps []*prog.Prog, isCrashFail bool) {

    ch := make(chan []*prog.Prog)
    go func() {
        for _, srvComb := range combs {
            //connClts := getConnClts(srvComb, conns, proc.fuzzer.config.ServNum)
            //Insert failures between the servers srvComb and clients connected to the servComb.
            log.Logf(0, "enumInner comb: %v", srvComb)
            prog.InsertFailure(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, ps, srvComb, ch,
                proc.fuzzer.sCalls, ps[0].SyncIdx, isCrashFail, proc.fuzzer.config.InitIp,
                proc.fuzzer.config.ServNum)
        }
        close(ch)
    }()

    for ps1 := range ch {
        log.Logf(0, "failure smash: %v %v", ps1[0].HasCrashFail, ps1[0].HasNetFail)
        proc.execute(proc.execOptsCover, ps1, ProgNormal, StatFailureEnum)
    }
    log.Logf(0, "enumInner finish %v", isCrashFail)
}

func (proc *Proc) enumFailures(ps []*prog.Prog) {

    srvNum := proc.fuzzer.config.ServNum
    cltNum := len(ps) - srvNum

    log.Logf(0, "Crash failure smash:%v %v", ps[0].HasCrashFail, ps[0].HasNetFail)
    if !ps[0].HasCrashFail {
        combs := genNodeCombs(srvNum)
        proc.enumInner(combs, ps, true) //isCrashFailure
    }

    log.Logf(0, "Net failure smash: %v %v", ps[0].HasCrashFail, ps[0].HasNetFail)
    if !ps[0].HasNetFail {
        combs := genEdgeCombs(srvNum, cltNum)
        log.Logf(0, "edge combs: %v", combs)
        proc.enumInner(combs, ps, false)
    }
}

func (proc *Proc) failCall(ps []*prog.Prog, call int, subNum int) {
    for nth := 1; nth <= 100; nth++ {
        log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
        newProgs := prog.Clones(ps)
        newProgs[subNum].Calls[call].Props.FailNth = nth
        infos, _, _ := proc.executeRaw(proc.execOpts, newProgs, StatSmash)
        if infos != nil && len(infos[proc.fuzzer.config.ServNum+subNum].Calls) > call && infos[proc.fuzzer.config.ServNum+subNum].Calls[call].Flags&ipc.CallFaultInjected == 0 {
            break
        }
    }
}

func (proc *Proc) executeHintSeed(ps []*prog.Prog, call int, subNum int) {
    log.Logf(1, "#%v: collecting comparisons on call %d", proc.pid, call)
    // First execute the original program to dump comparisons from KCOV.
    infos := proc.execute(proc.execOptsComps, ps, ProgNormal, StatSeed)
    if infos == nil {
        return
    }

    // Then mutate the initial program for every match between
    // a syscall argument and a comparison operand.
    // Execute each of such mutants to check if it gives new coverage.
    comps := infos[subNum].Calls[call].Comps
    for i := 0; i < proc.fuzzer.config.ServNum; i++ {
        for k, v := range infos[i].Extra.Comps {
            if _, ok := comps[k]; !ok {
                comps[k] = v
            }
        }
    }
    log.Logf(0, "------ executing comparison hint: %d", len(comps))
    prog.MutateWithHints(ps, subNum, call, comps, func(ps []*prog.Prog) {
        log.Logf(1, "#%v: executing comparison hint", proc.pid)
        proc.execute(proc.execOpts, ps, ProgNormal, StatHint)
    })
}

func (proc *Proc) triageFailure(ps []*prog.Prog, infos []*ipc.ProgInfo) {

    var SrvCover, CliCover cover.Cover
    var inputCliSignal, inputSrvSignal, newSignal signal.Signal
    for i, info := range infos {
        if i < proc.fuzzer.config.ServNum {
            proc.fuzzer.checkNewSignal(nil, info)
            //callInfo := info.Extra
            //prio := signalPrio(ps[i], &callInfo, -1)
            //inputSignal := signal.FromRaw(callInfo.Signal, prio)
            //
            thisSignal, thisCover := getSignalAndCover(ps[i], info, -1)
            inputSrvSignal.Merge(thisSignal)
            SrvCover.Merge(thisCover)
            if proc.fuzzer.config.EnableSrvFb {
                newSignal.Merge(proc.fuzzer.corpusSignalDiff(thisSignal))
            }
        } else {
            proc.fuzzer.checkNewSignal(ps[i], info)
            for j, _ := range ps[i].Calls {
                //
                thisSignal, thisCover := getSignalAndCover(ps[i], info, j)
                inputCliSignal.Merge(thisSignal)
                CliCover.Merge(thisCover)
                //
                //callInfo := info.Calls[j]
                //prio := signalPrio(ps[i], &callInfo, j)
                //inputSignal := signal.FromRaw(callInfo.Signal, prio)
                if proc.fuzzer.config.EnableClientFb {
                    newSignal.Merge(proc.fuzzer.corpusSignalDiff(thisSignal))
                }
            }
        }
    }
    if newSignal.Empty() {
        return
    }

    //stable signals
    for i := 0; i < 1; i++ {
        infos, _, _ := proc.executeRaw(proc.execOptsCover, ps, StatTriage)
        var oneRunSig signal.Signal
        for idx, info := range infos {
            if idx >= proc.fuzzer.config.ServNum {
                thisSignal, thisCover := getAllSignalAndCover(ps[idx], info)
                inputCliSignal.Merge(thisSignal)
                CliCover.Merge(thisCover)
                if proc.fuzzer.config.EnableClientFb {
                    oneRunSig.Merge(thisSignal)
                }
            }

            if idx < proc.fuzzer.config.ServNum {
                thisSignal, thisCover := getSignalAndCover(ps[idx], info, -1)
                inputSrvSignal.Merge(thisSignal)
                SrvCover.Merge(thisCover)
                if proc.fuzzer.config.EnableSrvFb {
                    oneRunSig.Merge(thisSignal)
                }
            }
        }
        newSignal = newSignal.Intersection(oneRunSig)
        if newSignal.Empty() {
            return
        }
    }

    //sendToManager, saveToCorpus, sendToSmash
    var data [][]byte
    var dataForHash []byte
    for _, p := range ps {
        prog := p.Serialize()
        data = append(data, prog)
        dataForHash = append(dataForHash, prog...)
    }
    sig := hash.Hash(dataForHash)

    proc.fuzzer.sendInputToManager(rpctype.RPCInput{
        Call:      "failure",
        Prog:      data,
        CliSignal: inputCliSignal.Serialize(),
        SrvSignal: inputSrvSignal.Serialize(),
        SrvCover:  SrvCover.Serialize(),
        CliCover:  CliCover.Serialize(),
    })

    proc.fuzzer.addInputToCorpus(ps, inputCliSignal, inputSrvSignal, sig)
    proc.fuzzer.workQueue.enqueue(&WorkFSmash{ps})
}

func (proc *Proc) useSrvCovNow() bool {
    return true
    if atomic.LoadInt32(&proc.freqCov) > 5 {
        return false
    } else {
        return true
    }
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, ps []*prog.Prog, flags ProgTypes, stat Stat) []*ipc.ProgInfo {
    log.Logf(0, "HasCrashFail: %v, .HasNetFail: %v", ps[0].HasCrashFail, ps[0].HasNetFail)
    infos, _, _ := proc.executeRaw(execOpts, ps, stat)
    if infos == nil {
        return nil
    }

    if stat == StatFailureEnum {
        //check new signal
        proc.triageFailure(ps, infos)
        return infos
    }

    servNum := proc.fuzzer.config.ServNum
    clientHasNew := false
    if proc.fuzzer.config.EnableClientFb {
        for idx, info := range infos {
            //TODO: how to check the signal from servers and clients
            if idx < servNum {
                continue
            } else {
                calls, extra := proc.fuzzer.checkNewSignal(ps[idx], info)
                for _, callIndex := range calls {
                    proc.enqueueCallTriage(ps, flags, callIndex, info.Calls[callIndex], idx, true) //idx -> subNum
                    clientHasNew = true
                }
                if extra {
                    proc.enqueueCallTriage(ps, flags, -1, info.Extra, idx, true)
                }
            }
        }
    }

    //(1). With failures, exploit server feedback
    //(2). Client doesn't have feedback for a while
    if proc.fuzzer.config.EnableSrvFb && (
       ((!clientHasNew && proc.useSrvCovNow()) || ps[0].HasNetFail || ps[0].HasCrashFail)) {
        log.Logf(0, "----- no new client coverage: %v, %v", clientHasNew, proc.fuzzer.config.EnableEval)
        for idx, info := range infos[:servNum] {
            _, extra := proc.fuzzer.checkNewSignal(nil, info)
            if extra {
                log.Logf(0, "----- enqueue testcases with server coveraged")
                proc.enqueueCallTriage(ps, flags, -1, info.Extra, idx, false)
            }
        }
    }

    //Execute again for crash consistency bugs
    //TODO
    if proc.fuzzer.config.EnableC2san &&
       (stat == StatFuzz || stat == StatSmash || stat == StatHint || stat == StatGenerate) {
        r := prog.NewRand(ps[0].Target, proc.rnd)
        //crash all
        ps1 := prog.ProgCrashAll(ps, proc.fuzzer.config.ServNum, r, proc.fuzzer.sCalls)
        proc.executeRaw(execOpts, ps1, stat)
        if proc.fuzzer.config.ServNum > 1 {
            //random crash with proc.fuzzer.config.ServNum times
            for i := 0; i < proc.fuzzer.config.ServNum; i++ {
                ps1 = prog.ProgCrashRand(ps, proc.fuzzer.config.ServNum, r, proc.fuzzer.sCalls)
                proc.executeRaw(execOpts, ps1, stat)
            }
        }
    }

    return infos
}

func (proc *Proc) enqueueCallTriage(ps []*prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo, subNum int,
                                    triageClient bool) {
    // info.Signal points to the output shmem region, detach it before queueing.
    info.Signal = append([]uint32{}, info.Signal...)
    // None of the caller use Cover, so just nil it instead of detaching.
    // Note: triage input uses executeRaw to get coverage.
    info.Cover = nil
    proc.fuzzer.workQueue.enqueue(&WorkTriage{
        ps:           prog.Clones(ps),
        call:         callIndex,
        info:         info,
        flags:        flags,
        subNum:       subNum,
        triageClient: triageClient,
    })
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, ps []*prog.Prog, stat Stat) ([]*ipc.ProgInfo, []map[string]prog.FileMetadata, uint64) {

    if opts.Flags&ipc.FlagDedupCover == 0 {
        log.Fatalf("dedup cover is not enabled")
    }

    for _, p := range ps {
        proc.fuzzer.checkDisabledCalls(p)
    }

    // Limit concurrency window and do leak checking once in a while.
    ticket := proc.fuzzer.gate.Enter()
    defer proc.fuzzer.gate.Leave(ticket)

    if ps[0].HasCrashFail || ps[0].HasNetFail || proc.fuzzer.config.EnableCsan {
        opts.Flags &= ^ipc.FlagCollide
        opts.Flags &= ^ipc.FlagThreaded
        log.Logf(0, "disable threaded and collide")
    }

    proc.logProgram(opts, ps)

    atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
    output, infos, hanged, err, fsMds, testdirIno := proc.env.Exec(opts, ps)
    if err != nil {
        log.Fatalf("execution errors or hangs: %v\n", err)
    }
    log.Logf(2, "result hanged=%v: %s", hanged, output)

    // Concurrent semantic checker
    if proc.fuzzer.config.EnableCsan {
        if !checker.ConcFSCheck(ps, infos, fsMds, proc.fuzzer.config.ServNum,
                            proc.fuzzer.config.DFSName, proc.fuzzer.config.DfsSetupParams,
                            proc.fuzzer.config.InitIp, testdirIno) {
            log.Logf(0, "Concurrent semantic checker detects a bug")
        }
    }

    return infos, fsMds, testdirIno
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, ps []*prog.Prog) {
    if proc.fuzzer.outputType == OutputNone {
        return
    }

    delimiter := []byte("---\n")
    var data []byte
    for _, p := range ps {
        if len(p.Calls) != 0 {
            log.Logf(0, "prog length: %d\n", len(p.Calls))
        }
        data = append(data, p.Serialize()...)
        data = append(data, delimiter...)
    }

    log.Logf(0, "HasCrashFail:%v HasNetFail:%v\n", ps[0].HasCrashFail, ps[0].HasNetFail)
    // The following output helps to understand what program crashed kernel.
    // It must not be intermixed.
    switch proc.fuzzer.outputType {
    case OutputStdout:
        now := time.Now()
        proc.fuzzer.logMu.Lock()
        fmt.Printf("%02v:%02v:%02v ---executing program %v:\n%s\nend of program\n",
            now.Hour(), now.Minute(), now.Second(),
            proc.pid, data)
        proc.fuzzer.logMu.Unlock()
    case OutputDmesg:
        fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
        if err == nil {
            buf := new(bytes.Buffer)
            fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n",
                proc.pid, data)
            syscall.Write(fd, buf.Bytes())
            syscall.Close(fd)
        }
    case OutputFile:
        f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
        if err == nil {
            f.Write(data)
            f.Close()
        }
    default:
        log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
    }
}
