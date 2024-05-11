// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"strings"
)

// Minimize minimizes program p into an equivalent program using the equivalence
// predicate pred. It iteratively generates simpler programs and asks pred
// whether it is equal to the original program or not. If it is equivalent then
// the simplification attempt is committed and the process continues.
func Minimize(ps0 []*Prog, callIndex0 int, subNum int, crash bool, srvNum int,
															pred0 func([]*Prog, int) bool,) ([]*Prog, int) {
	pred := func(ps []*Prog, callIndex int) bool {
		for _, p := range ps {
			p.sanitizeFix()
			p.debugValidate()
		}
		return pred0(ps, callIndex)
	}
	name0 := ""
	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(ps0[subNum].Calls) {
			panic("bad call index")
		}
		name0 = ps0[subNum].Calls[callIndex0].Meta.Name
	}

	// Try to remove all calls except the last one one-by-one.
	ps0, callIndex0 = removeCalls(ps0, callIndex0, subNum, crash, srvNum, pred)

	// Try to minimize individual calls.
	for j := srvNum; j < len(ps0); j++ {
		for i := 0; i < len(ps0[j].Calls); i++ {
			if strings.Contains(ps0[j].Calls[i].Meta.Name, "syz_failure") {
				continue
			}
			ctx := &minimizeArgsCtx{
				target:     ps0[j].Target,
				ps0:        &ps0,
				callIndex0: callIndex0,
				crash:      crash,
				pred:       pred,
				triedPaths: make(map[string]bool),
			}
		again:
			ctx.ps = Clones(ps0)
			ctx.call = ctx.ps[j].Calls[i]
			for m, field := range ctx.call.Meta.Args {
				if ctx.do(ctx.call.Args[m], field.Name, "") {
					goto again
				}
			}
			ps0 = minimizeCallProps(ps0, j, i, callIndex0, pred)
		}
	}

	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(ps0[subNum].Calls) || name0 != ps0[subNum].Calls[callIndex0].Meta.Name {
			panic(fmt.Sprintf("bad call index after minimization: ncalls=%v index=%v call=%v/%v",
				len(ps0[subNum].Calls), callIndex0, name0, ps0[subNum].Calls[callIndex0].Meta.Name))
		}
	}
	return ps0, callIndex0
}

func removeCalls(ps0 []*Prog, CallIndex0 int, subNum int, crash bool, srvNum int, pred func([]*Prog, int) bool) ([]*Prog, int) {

	for j, _ := range ps0 {
		if j < srvNum {
			continue
		}
		for i := len(ps0[j].Calls) - 1; i >= 0; i-- {
			if j == subNum {
				if i == CallIndex0 || strings.Contains(ps0[j].Calls[i].Meta.Name, "syz_failure") {
					continue
				}
				CallIndex := CallIndex0
				if i < CallIndex {
					CallIndex--
				}
				ps := Clones(ps0)
				ps[j].RemoveCall(i)
				if !pred(ps, CallIndex) {
					continue
				}
				ps0[j] = ps[j]
				CallIndex0 = CallIndex
			} else {
				ps := Clones(ps0)
				ps[j].RemoveCall(i)
				if !pred(ps, CallIndex0) {
					continue
				}
				ps0[j] = ps[j]
			}
		}
	}
	return ps0, CallIndex0
}

func minimizeCallProps(ps0 []*Prog, subNum, callIndex, callIndex0 int, pred func([]*Prog, int) bool) []*Prog {

	props := ps0[subNum].Calls[callIndex].Props
	// Try to drop fault injection.
	if props.FailNth > 0 {
		ps := Clones(ps0)
		ps[subNum].Calls[callIndex].Props.FailNth = 0
		if pred(ps, callIndex0) {
			ps0 = ps
		}
	}
	return ps0
}

type minimizeArgsCtx struct {
	target     *Target
	ps0        *[]*Prog
	ps         []*Prog
	call       *Call
	callIndex0 int
	crash      bool
	pred       func([]*Prog, int) bool
	triedPaths map[string]bool
}

func compareSlices(slice1 []*Prog, slice2 []*Prog) bool {

	if len(slice1) != len(slice2) {
		return false
	}

	for i := 0; i < len(slice1); i++ {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}

func (ctx *minimizeArgsCtx) do(arg Arg, field, path string) bool {
	path += fmt.Sprintf("-%v", field)
	if ctx.triedPaths[path] {
		return false
	}
	ps0 := *ctx.ps0
	if arg.Type().minimize(ctx, arg, path) {
		return true
	}
	if compareSlices(*ctx.ps0, ctx.ps) {
		//if *ctx.ps0 == ctx.ps {
		// If minimize committed a new program, it must return true.
		// Otherwise *ctx.p0 and ctx.p will point to the same program
		// and any temp mutations to ctx.p will unintentionally affect ctx.p0.
		panic("shared program committed")
	}
	if !compareSlices(*ctx.ps0, ps0) {
		//if *ctx.ps0 != ps0 {
		// New program was committed, but we did not start iteration anew.
		// This means we are iterating over a stale tree and any changes won't be visible.
		panic("iterating over stale program")
	}
	ctx.triedPaths[path] = true
	return false
}

func (typ *TypeCommon) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return false
}

func (typ *StructType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*GroupArg)
	for i, innerArg := range a.Inner {
		if ctx.do(innerArg, typ.Fields[i].Name, path) {
			return true
		}
	}
	return false
}

func (typ *UnionType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*UnionArg)
	return ctx.do(a.Option, typ.Fields[a.Index].Name, path)
}

func (typ *PtrType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*PointerArg)
	if a.Res == nil {
		return false
	}
	if path1 := path + ">"; !ctx.triedPaths[path1] {
		removeArg(a.Res)
		replaceArg(a, MakeSpecialPointerArg(a.Type(), a.Dir(), 0))
		ctx.target.assignSizesCall(ctx.call)
		if ctx.pred(ctx.ps, ctx.callIndex0) {
			*ctx.ps0 = ctx.ps
		}
		ctx.triedPaths[path1] = true
		return true
	}
	return ctx.do(a.Res, "", path)
}

func (typ *ArrayType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*GroupArg)
	for i := len(a.Inner) - 1; i >= 0; i-- {
		elem := a.Inner[i]
		elemPath := fmt.Sprintf("%v-%v", path, i)
		// Try to remove individual elements one-by-one.
		if !ctx.crash && !ctx.triedPaths[elemPath] &&
			(typ.Kind == ArrayRandLen ||
				typ.Kind == ArrayRangeLen && uint64(len(a.Inner)) > typ.RangeBegin) {
			ctx.triedPaths[elemPath] = true
			copy(a.Inner[i:], a.Inner[i+1:])
			a.Inner = a.Inner[:len(a.Inner)-1]
			removeArg(elem)
			ctx.target.assignSizesCall(ctx.call)
			if ctx.pred(ctx.ps, ctx.callIndex0) {
				*ctx.ps0 = ctx.ps
			}
			return true
		}
		if ctx.do(elem, "", elemPath) {
			return true
		}
	}
	return false
}

func (typ *IntType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return minimizeInt(ctx, arg, path)
}

func (typ *FlagsType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return minimizeInt(ctx, arg, path)
}

func (typ *ProcType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if !typ.Optional() {
		// Default value for ProcType is 0 (same for all PID's).
		// Usually 0 either does not make sense at all or make different PIDs collide
		// (since we use ProcType to separate value ranges for different PIDs).
		// So don't change ProcType to 0 unless the type is explicitly marked as opt
		// (in that case we will also generate 0 anyway).
		return false
	}
	return minimizeInt(ctx, arg, path)
}

func minimizeInt(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	// TODO: try to reset bits in ints
	// TODO: try to set separate flags
	if ctx.crash {
		return false
	}
	a := arg.(*ConstArg)
	def := arg.Type().DefaultArg(arg.Dir()).(*ConstArg)
	if a.Val == def.Val {
		return false
	}
	v0 := a.Val
	a.Val = def.Val
	if ctx.pred(ctx.ps, ctx.callIndex0) {
		*ctx.ps0 = ctx.ps
		ctx.triedPaths[path] = true
		return true
	}
	a.Val = v0
	return false
}

func (typ *ResourceType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if ctx.crash {
		return false
	}
	a := arg.(*ResultArg)
	if a.Res == nil {
		return false
	}
	r0 := a.Res
	delete(a.Res.uses, a)
	a.Res, a.Val = nil, typ.Default()
	if ctx.pred(ctx.ps, ctx.callIndex0) {
		*ctx.ps0 = ctx.ps
	} else {
		a.Res, a.Val = r0, 0
		a.Res.uses[a] = true
	}
	ctx.triedPaths[path] = true
	return true
}

func (typ *BufferType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	// TODO: try to set individual bytes to 0
	if typ.Kind != BufferBlobRand && typ.Kind != BufferBlobRange || arg.Dir() == DirOut {
		return false
	}
	a := arg.(*DataArg)
	len0 := len(a.Data())
	minLen := int(typ.RangeBegin)
	for step := len(a.Data()) - minLen; len(a.Data()) > minLen && step > 0; {
		if len(a.Data())-step >= minLen {
			a.data = a.Data()[:len(a.Data())-step]
			ctx.target.assignSizesCall(ctx.call)
			if ctx.pred(ctx.ps, ctx.callIndex0) {
				continue
			}
			a.data = a.Data()[:len(a.Data())+step]
			ctx.target.assignSizesCall(ctx.call)
		}
		step /= 2
		if ctx.crash {
			break
		}
	}
	if len(a.Data()) != len0 {
		*ctx.ps0 = ctx.ps
		ctx.triedPaths[path] = true
		return true
	}
	return false
}
