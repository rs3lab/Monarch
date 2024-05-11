// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"encoding/binary"
	"fmt"
	"monarch/pkg/log"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
)

// Maximum length of generated binary blobs inserted into the program.
const maxBlobLen = uint64(100 << 10)

// Mutate program p.
//
// p:       The program to mutate.
// rs:      Random source.
// ncalls:  The allowed maximum calls in mutated program.
// ct:      ChoiceTable for syscalls.
// corpus:  The entire corpus, including original program p.
func (p *Prog) Mutate(rs rand.Source, ncalls int, ct *ChoiceTable, corpus [][]*Prog, sCalls *SpecialCalls,
											srvNum int, hasFail bool, enableC2san bool) {
	r := newRand(p.Target, rs)
	if ncalls < len(p.Calls) {
		ncalls = len(p.Calls)
	}
	ctx := &mutator{
		p:               p,
		r:               r,
		ncalls:          ncalls,
		ct:              ct,
		corpus:          corpus,
		sCalls:			 sCalls,
		srvNum:			 srvNum,
		enableC2san:     enableC2san,
	}

	log.Logf(0, "mutate testcase with failures\n")

	for stop, ok := false, false; !stop; stop = ok && len(p.Calls) != 0 && r.oneOf(3) {
		switch {
		case r.oneOf(5):
			//log.Logf(0, "----- squashAny()")
			// Not all calls have anything squashable,
			// so this has lower priority in reality.
			ok = ctx.squashAny()
		case r.nOutOf(1, 100):
			log.Logf(0, "----- splice()")
			if hasFail {
				ok = false
			} else {
				ok = ctx.splice()
			}
		case r.nOutOf(20, 31):
			log.Logf(0, "----- insertCall()")
			ok = ctx.insertCall()
		case r.nOutOf(10, 11):
			log.Logf(0, "----- mutateArg()")
			ok = ctx.mutateArg()
		case r.nOutOf(9, 10):
			if hasFail {
			    log.Logf(0, "----- mutateFailPos()")
			    ok = ctx.mutateFailPos()
			} else {
				ok = false
			}
		default:
			log.Logf(0, "----- removeCall()")
			ok = ctx.removeCall()
		}
	}
	p.sanitizeFix()
	p.debugValidate()
	if got := len(p.Calls); (got < 1 || got > ncalls) {
		panic(fmt.Sprintf("bad number of calls after mutation: %v, want [1, %v]", got, ncalls))
	}
}

// Internal state required for performing mutations -- currently this matches
// the arguments passed to Mutate().
type mutator struct {
	p               *Prog        // The program to mutate.
	r               *randGen     // The randGen instance.
	ncalls          int          // The allowed maximum calls in mutated program.
	ct              *ChoiceTable // ChoiceTable for syscalls.
	corpus          [][]*Prog    // The entire corpus, including original program p.
	initIp          string
	srvNum          int
	sCalls          *SpecialCalls
	enableC2san		bool
}

// This function selects a random other program p0 out of the corpus, and
// mutates ctx.p as follows: preserve ctx.p's Calls up to a random index i
// (exclusive) concatenated with p0's calls from index i (inclusive).
func (ctx *mutator) splice() bool {
	p, r := ctx.p, ctx.r
	if len(ctx.corpus) == 0 || len(p.Calls) == 0 || len(p.Calls) >= ctx.ncalls {
		return false
	}
	//tao modified
	//p0 := ctx.corpus[r.Intn(len(ctx.corpus))]
	var p0 *Prog
	subTsNum := len(ctx.corpus[0]) - ctx.srvNum
	for {
		ps := ctx.corpus[r.Intn(len(ctx.corpus))]
		if !ps[0].HasCrashFail && !ps[0].HasNetFail {
			p0 = ps[r.Intn(subTsNum)+ctx.srvNum]
			break
		}
	}
	//log.Logf(0, "splice this program srvNum %d subTsNum %d:\n", ctx.srvNum, subTsNum)
	//logProgram(append(make([]*Prog, 0), p0))
	//tao end
	p0c := p0.Clone()
	idx := r.Intn(len(p.Calls))
	p.Calls = append(p.Calls[:idx], append(p0c.Calls, p.Calls[idx:]...)...)
	for i := len(p.Calls) - 1; i >= ctx.ncalls; i-- {
		p.RemoveCall(i)
	}
	return true
}

// Picks a random complex pointer and squashes its arguments into an ANY.
// Subsequently, if the ANY contains blobs, mutates a random blob.
func (ctx *mutator) squashAny() bool {
	p, r := ctx.p, ctx.r
	complexPtrs := p.complexPtrs()
	if len(complexPtrs) == 0 {
		return false
	}
	ptr := complexPtrs[r.Intn(len(complexPtrs))]
	if !p.Target.isAnyPtr(ptr.Type()) {
		p.Target.squashPtr(ptr)
	}
	var blobs []*DataArg
	var bases []*PointerArg
	ForeachSubArg(ptr, func(arg Arg, ctx *ArgCtx) {
		if data, ok := arg.(*DataArg); ok && arg.Dir() != DirOut {
			blobs = append(blobs, data)
			bases = append(bases, ctx.Base)
		}
	})
	if len(blobs) == 0 {
		return false
	}
	// TODO(dvyukov): we probably want special mutation for ANY.
	// E.g. merging adjacent ANYBLOBs (we don't create them,
	// but they can appear in future); or replacing ANYRES
	// with a blob (and merging it with adjacent blobs).
	idx := r.Intn(len(blobs))
	arg := blobs[idx]
	base := bases[idx]
	baseSize := base.Res.Size()
	arg.data = mutateData(r, arg.Data(), 0, maxBlobLen)
	// Update base pointer if size has increased.
	if baseSize < base.Res.Size() {
		s := analyze(ctx.ct, ctx.corpus, p, p.Calls[0])
		newArg := r.allocAddr(s, base.Type(), base.Dir(), base.Res.Size(), base.Res)
		*base = *newArg
	}
	return true
}

// Inserts a new call at a randomly chosen point (with bias towards the end of
// existing program). Does not insert a call if program already has ncalls.
func (ctx *mutator) insertCall() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) >= ctx.ncalls {
		return false
	}
	idx := r.biasedRand(len(p.Calls)+1, 5)
	var c *Call
	if idx < len(p.Calls) {
		c = p.Calls[idx]
	}
	s := analyze(ctx.ct, ctx.corpus, p, c)
	calls := r.generateCall(s, p, idx, ctx.sCalls, ctx.enableC2san)
	if len(calls) == 0 {
		return false
	}
	p.insertBefore(c, calls)
	for len(p.Calls) > ctx.ncalls {
		p.RemoveCall(idx)
	}
	return true
}

// Removes a random call from program.
func (ctx *mutator) removeCall() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) == 0 {
		return false
	}

	stop := false
	idx := 0
	cnt := 0
	for !stop {
		if cnt > 20 {
			return false
		}
		idx = r.Intn(len(p.Calls))
		if !strings.Contains(p.Calls[idx].Meta.Name, "syz_failure") {
			stop = true
		}
		cnt += 1
	}
	p.RemoveCall(idx)
	return true
}

// Mutate an argument of a random call.
func (ctx *mutator) mutateArg() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) == 0 {
		return false
	}


    stop := false
    idx := 0
	cnt := 0
    for !stop {
		idx = chooseCall(p, r)
		if idx < 0 || cnt > 20 {
			return false
		}
        if !strings.Contains(p.Calls[idx].Meta.Name, "syz_failure") {
            stop = true
        }
		cnt += 1
    }

	c := p.Calls[idx]
	updateSizes := true
	for stop, ok := false, false; !stop; stop = ok && r.oneOf(3) {
		ok = true
		ma := &mutationArgs{target: p.Target}
		ForeachArg(c, ma.collectArg)
		if len(ma.args) == 0 {
			return false
		}
		s := analyze(ctx.ct, ctx.corpus, p, c)
		arg, argCtx := ma.chooseArg(r.Rand)
		calls, ok1 := p.Target.mutateArg(r, s, arg, argCtx, &updateSizes)
		if !ok1 {
			ok = false
			continue
		}
		p.insertBefore(c, calls)
		idx += len(calls)
		for len(p.Calls) > ctx.ncalls {
			idx--
			p.RemoveCall(idx)
		}
		if idx < 0 || idx >= len(p.Calls) || p.Calls[idx] != c {
			panic(fmt.Sprintf("wrong call index: idx=%v calls=%v p.Calls=%v ncalls=%v",
				idx, len(calls), len(p.Calls), ctx.ncalls))
		}
		if updateSizes {
			p.Target.assignSizesCall(c)
		}
	}
	return true
}

// Select a call based on the complexity of the arguments.
func chooseCall(p *Prog, r *randGen) int {
	var prioSum float64
	var callPriorities []float64
	for _, c := range p.Calls {
		var totalPrio float64
		ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
			prio, stopRecursion := arg.Type().getMutationPrio(p.Target, arg, false)
			totalPrio += prio
			ctx.Stop = stopRecursion
		})
		prioSum += totalPrio
		callPriorities = append(callPriorities, prioSum)
	}
	if prioSum == 0 {
		return -1 // All calls are without arguments.
	}
	return sort.SearchFloat64s(callPriorities, prioSum*r.Float64())
}

func (target *Target) mutateArg(r *randGen, s *state, arg Arg, ctx ArgCtx, updateSizes *bool) ([]*Call, bool) {
	var baseSize uint64
	if ctx.Base != nil {
		baseSize = ctx.Base.Res.Size()
	}
	calls, retry, preserve := arg.Type().mutate(r, s, arg, ctx)
	if retry {
		return nil, false
	}
	if preserve {
		*updateSizes = false
	}
	// Update base pointer if size has increased.
	if base := ctx.Base; base != nil && baseSize < base.Res.Size() {
		newArg := r.allocAddr(s, base.Type(), base.Dir(), base.Res.Size(), base.Res)
		replaceArg(base, newArg)
	}
	return calls, true
}

func regenerate(r *randGen, s *state, arg Arg) (calls []*Call, retry, preserve bool) {
	var newArg Arg
	newArg, calls = r.generateArg(s, arg.Type(), arg.Dir())
	replaceArg(arg, newArg)
	return
}

func mutateInt(r *randGen, a *ConstArg, t *IntType) uint64 {
	switch {
	case r.nOutOf(1, 3):
		return a.Val + (uint64(r.Intn(4)) + 1)
	case r.nOutOf(1, 2):
		return a.Val - (uint64(r.Intn(4)) + 1)
	default:
		return a.Val ^ (1 << uint64(r.Intn(int(t.TypeBitSize()))))
	}
}

func mutateAlignedInt(r *randGen, a *ConstArg, t *IntType) uint64 {
	rangeEnd := t.RangeEnd
	if t.RangeBegin == 0 && int64(rangeEnd) == -1 {
		// Special [0:-1] range for all possible values.
		rangeEnd = uint64(1<<t.TypeBitSize() - 1)
	}
	index := (a.Val - t.RangeBegin) / t.Align
	misalignment := (a.Val - t.RangeBegin) % t.Align
	switch {
	case r.nOutOf(1, 3):
		index += uint64(r.Intn(4)) + 1
	case r.nOutOf(1, 2):
		index -= uint64(r.Intn(4)) + 1
	default:
		index ^= 1 << uint64(r.Intn(int(t.TypeBitSize())))
	}
	lastIndex := (rangeEnd - t.RangeBegin) / t.Align
	index %= lastIndex + 1
	return t.RangeBegin + index*t.Align + misalignment
}

func (t *IntType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	if r.bin() {
		return regenerate(r, s, arg)
	}
	a := arg.(*ConstArg)
	if t.Align == 0 {
		a.Val = mutateInt(r, a, t)
	} else {
		a.Val = mutateAlignedInt(r, a, t)
	}
	a.Val = truncateToBitSize(a.Val, t.TypeBitSize())
	return
}

func (t *FlagsType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	a := arg.(*ConstArg)
	for oldVal := a.Val; oldVal == a.Val; {
		a.Val = r.flags(t.Vals, t.BitMask, a.Val)
	}
	return
}

func (t *LenType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	if !r.mutateSize(arg.(*ConstArg), *ctx.Parent, ctx.Fields) {
		retry = true
		return
	}
	preserve = true
	return
}

func (t *ResourceType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return regenerate(r, s, arg)
}

func (t *VmaType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return regenerate(r, s, arg)
}

func (t *ProcType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return regenerate(r, s, arg)
}

func (t *BufferType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	minLen, maxLen := uint64(0), maxBlobLen
	if t.Kind == BufferBlobRange {
		minLen, maxLen = t.RangeBegin, t.RangeEnd
	}
	a := arg.(*DataArg)
	if a.Dir() == DirOut {
		mutateBufferSize(r, a, minLen, maxLen)
		return
	}
	switch t.Kind {
	case BufferBlobRand, BufferBlobRange:
		data := append([]byte{}, a.Data()...)
		a.data = mutateData(r, data, minLen, maxLen)
	case BufferString:
		if len(t.Values) != 0 {
			a.data = r.randString(s, t)
		} else {
			if t.TypeSize != 0 {
				minLen, maxLen = t.TypeSize, t.TypeSize
			}
			data := append([]byte{}, a.Data()...)
			a.data = mutateData(r, data, minLen, maxLen)
		}
	case BufferFilename:
		a.data = []byte(r.filename(s, t))
	case BufferGlob:
		if len(t.Values) != 0 {
			a.data = r.randString(s, t)
		} else {
			a.data = []byte(r.filename(s, t))
		}
	case BufferText:
		data := append([]byte{}, a.Data()...)
		a.data = r.mutateText(t.Text, data)
	default:
		panic("unknown buffer kind")
	}
	return
}

func mutateBufferSize(r *randGen, arg *DataArg, minLen, maxLen uint64) {
	for oldSize := arg.Size(); oldSize == arg.Size(); {
		arg.size += uint64(r.Intn(33)) - 16
		if arg.size < minLen {
			arg.size = minLen
		}
		if arg.size > maxLen {
			arg.size = maxLen
		}
	}
}

func (t *ArrayType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	// TODO: swap elements of the array
	a := arg.(*GroupArg)
	count := uint64(0)
	switch t.Kind {
	case ArrayRandLen:
		if r.bin() {
			for count = uint64(len(a.Inner)); r.bin(); {
				count++
			}
		} else {
			for count == uint64(len(a.Inner)) {
				count = r.randArrayLen()
			}
		}
	case ArrayRangeLen:
		if t.RangeBegin == t.RangeEnd {
			panic("trying to mutate fixed length array")
		}
		for count == uint64(len(a.Inner)) {
			count = r.randRange(t.RangeBegin, t.RangeEnd)
		}
	}
	if count > uint64(len(a.Inner)) {
		for count > uint64(len(a.Inner)) {
			newArg, newCalls := r.generateArg(s, t.Elem, a.Dir())
			a.Inner = append(a.Inner, newArg)
			calls = append(calls, newCalls...)
			for _, c := range newCalls {
				s.analyze(c)
			}
		}
	} else if count < uint64(len(a.Inner)) {
		for _, arg := range a.Inner[count:] {
			removeArg(arg)
		}
		a.Inner = a.Inner[:count]
	}
	return
}

func (t *PtrType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	a := arg.(*PointerArg)
	if r.oneOf(1000) {
		removeArg(a.Res)
		index := r.rand(len(r.target.SpecialPointers))
		newArg := MakeSpecialPointerArg(t, a.Dir(), index)
		replaceArg(arg, newArg)
		return
	}
	newArg := r.allocAddr(s, t, a.Dir(), a.Res.Size(), a.Res)
	replaceArg(arg, newArg)
	return
}

func (t *StructType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	gen := r.target.SpecialTypes[t.Name()]
	if gen == nil {
		panic("bad arg returned by mutationArgs: StructType")
	}
	var newArg Arg
	newArg, calls = gen(&Gen{r, s}, t, arg.Dir(), arg)
	a := arg.(*GroupArg)
	for i, f := range newArg.(*GroupArg).Inner {
		replaceArg(a.Inner[i], f)
	}
	return
}

func (t *UnionType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	if gen := r.target.SpecialTypes[t.Name()]; gen != nil {
		var newArg Arg
		newArg, calls = gen(&Gen{r, s}, t, arg.Dir(), arg)
		replaceArg(arg, newArg)
		return
	}
	a := arg.(*UnionArg)
	index := r.Intn(len(t.Fields) - 1)
	if index >= a.Index {
		index++
	}
	optType, optDir := t.Fields[index].Type, t.Fields[index].Dir(a.Dir())
	removeArg(a.Option)
	var newOpt Arg
	newOpt, calls = r.generateArg(s, optType, optDir)
	replaceArg(arg, MakeUnionArg(t, a.Dir(), newOpt, index))
	return
}

func (t *CsumType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	panic("CsumType can't be mutated")
}

func (t *ConstType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	panic("ConstType can't be mutated")
}

type mutationArgs struct {
	target        *Target
	ignoreSpecial bool
	prioSum       float64
	args          []mutationArg
	argsBuffer    [16]mutationArg
}

type mutationArg struct {
	arg      Arg
	ctx      ArgCtx
	priority float64
}

const (
	maxPriority = float64(10)
	minPriority = float64(1)
	dontMutate  = float64(0)
)

func (ma *mutationArgs) collectArg(arg Arg, ctx *ArgCtx) {
	ignoreSpecial := ma.ignoreSpecial
	ma.ignoreSpecial = false

	typ := arg.Type()
	prio, stopRecursion := typ.getMutationPrio(ma.target, arg, ignoreSpecial)
	ctx.Stop = stopRecursion

	if prio == dontMutate {
		return
	}

	_, isArrayTyp := typ.(*ArrayType)
	_, isBufferTyp := typ.(*BufferType)
	if !isBufferTyp && !isArrayTyp && arg.Dir() == DirOut || !typ.Varlen() && typ.Size() == 0 {
		return
	}

	if len(ma.args) == 0 {
		ma.args = ma.argsBuffer[:0]
	}
	ma.prioSum += prio
	ma.args = append(ma.args, mutationArg{arg, *ctx, ma.prioSum})
}

func (ma *mutationArgs) chooseArg(r *rand.Rand) (Arg, ArgCtx) {
	goal := ma.prioSum * r.Float64()
	chosenIdx := sort.Search(len(ma.args), func(i int) bool { return ma.args[i].priority >= goal })
	arg := ma.args[chosenIdx]
	return arg.arg, arg.ctx
}

// TODO: find a way to estimate optimal priority values.
// Assign a priority for each type. The boolean is the reference type and it has
// the minimum priority, since it has only two possible values.
func (t *IntType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	// For a integer without a range of values, the priority is based on
	// the number of bits occupied by the underlying type.
	plainPrio := math.Log2(float64(t.TypeBitSize())) + 0.1*maxPriority
	if t.Kind != IntRange {
		return plainPrio, false
	}

	size := t.RangeEnd - t.RangeBegin + 1
	if t.Align != 0 {
		if t.RangeBegin == 0 && int64(t.RangeEnd) == -1 {
			// Special [0:-1] range for all possible values.
			size = (1<<t.TypeBitSize()-1)/t.Align + 1
		} else {
			size = (t.RangeEnd-t.RangeBegin)/t.Align + 1
		}
	}
	switch {
	case size <= 15:
		// For a small range, we assume that it is effectively
		// similar with FlagsType and we need to try all possible values.
		prio = rangeSizePrio(size)
	case size <= 256:
		// We consider that a relevant range has at most 256
		// values (the number of values that can be represented on a byte).
		prio = maxPriority
	default:
		// Ranges larger than 256 are equivalent with a plain integer.
		prio = plainPrio
	}
	return prio, false
}

func (t *StructType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if target.SpecialTypes[t.Name()] == nil || ignoreSpecial {
		return dontMutate, false
	}
	return maxPriority, true
}

func (t *UnionType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if target.SpecialTypes[t.Name()] == nil && len(t.Fields) == 1 || ignoreSpecial {
		return dontMutate, false
	}
	// For a non-special type union with more than one option
	// we mutate the union itself and also the value of the current option.
	if target.SpecialTypes[t.Name()] == nil {
		return maxPriority, false
	}
	return maxPriority, true
}

func (t *FlagsType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	prio = rangeSizePrio(uint64(len(t.Vals)))
	if t.BitMask {
		// We want a higher priority because the mutation will include
		// more possible operations (bitwise operations).
		prio += 0.1 * maxPriority
	}
	return prio, false
}

// Assigns a priority based on the range size.
func rangeSizePrio(size uint64) (prio float64) {
	switch size {
	case 0:
		prio = dontMutate
	case 1:
		prio = minPriority
	default:
		// Priority proportional with the number of values. After a threshold, the priority is constant.
		// The threshold is 15 because most of the calls have <= 15 possible values for a flag.
		prio = math.Min(float64(size)/3+0.4*maxPriority, 0.9*maxPriority)
	}
	return prio
}

func (t *PtrType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if arg.(*PointerArg).IsSpecial() {
		// TODO: we ought to mutate this, but we don't have code for this yet.
		return dontMutate, false
	}
	return 0.3 * maxPriority, false
}

func (t *ConstType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return dontMutate, false
}

func (t *CsumType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return dontMutate, false
}

func (t *ProcType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return 0.5 * maxPriority, false
}

func (t *ResourceType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return 0.5 * maxPriority, false
}

func (t *VmaType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return 0.5 * maxPriority, false
}

func (t *LenType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	// Mutating LenType only produces "incorrect" results according to descriptions.
	return 0.1 * maxPriority, false
}

func (t *BufferType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if arg.Dir() == DirOut && !t.Varlen() {
		return dontMutate, false
	}
	if t.Kind == BufferString && len(t.Values) == 1 {
		// These are effectively consts (and frequently file names).
		return dontMutate, false
	}
	return 0.8 * maxPriority, false
}

func (t *ArrayType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if t.Kind == ArrayRangeLen && t.RangeBegin == t.RangeEnd {
		return dontMutate, false
	}
	return maxPriority, false
}

func mutateData(r *randGen, data []byte, minLen, maxLen uint64) []byte {
	for stop := false; !stop; stop = stop && r.oneOf(3) {
		f := mutateDataFuncs[r.Intn(len(mutateDataFuncs))]
		data, stop = f(r, data, minLen, maxLen)
	}
	return data
}

// The maximum delta for integer mutations.
const maxDelta = 35

var mutateDataFuncs = [...]func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool){
	// TODO(dvyukov): duplicate part of data.
	// Flip bit in byte.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if len(data) == 0 {
			return data, false
		}
		byt := r.Intn(len(data))
		bit := r.Intn(8)
		data[byt] ^= 1 << uint(bit)
		return data, true
	},
	// Insert random bytes.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if len(data) == 0 || uint64(len(data)) >= maxLen {
			return data, false
		}
		n := r.Intn(16) + 1
		if r := int(maxLen) - len(data); n > r {
			n = r
		}
		pos := r.Intn(len(data))
		for i := 0; i < n; i++ {
			data = append(data, 0)
		}
		copy(data[pos+n:], data[pos:])
		for i := 0; i < n; i++ {
			data[pos+i] = byte(r.Int31())
		}
		if uint64(len(data)) > maxLen || r.bin() {
			data = data[:len(data)-n] // preserve original length
		}
		return data, true
	},
	// Remove bytes.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if len(data) == 0 {
			return data, false
		}
		n := r.Intn(16) + 1
		if n > len(data) {
			n = len(data)
		}
		pos := 0
		if n < len(data) {
			pos = r.Intn(len(data) - n)
		}
		copy(data[pos:], data[pos+n:])
		data = data[:len(data)-n]
		if uint64(len(data)) < minLen || r.bin() {
			for i := 0; i < n; i++ {
				data = append(data, 0) // preserve original length
			}
		}
		return data, true
	},
	// Append a bunch of bytes.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if uint64(len(data)) >= maxLen {
			return data, false
		}
		const max = 256
		n := max - r.biasedRand(max, 10)
		if r := int(maxLen) - len(data); n > r {
			n = r
		}
		for i := 0; i < n; i++ {
			data = append(data, byte(r.rand(256)))
		}
		return data, true
	},
	// Replace int8/int16/int32/int64 with a random value.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		width := 1 << uint(r.Intn(4))
		if len(data) < width {
			return data, false
		}
		i := r.Intn(len(data) - width + 1)
		storeInt(data[i:], r.Uint64(), width)
		return data, true
	},
	// Add/subtract from an int8/int16/int32/int64.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		width := 1 << uint(r.Intn(4))
		if len(data) < width {
			return data, false
		}
		i := r.Intn(len(data) - width + 1)
		v := loadInt(data[i:], width)
		delta := r.rand(2*maxDelta+1) - maxDelta
		if delta == 0 {
			delta = 1
		}
		if r.oneOf(10) {
			v = swapInt(v, width)
			v += delta
			v = swapInt(v, width)
		} else {
			v += delta
		}
		storeInt(data[i:], v, width)
		return data, true
	},
	// Set int8/int16/int32/int64 to an interesting value.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		width := 1 << uint(r.Intn(4))
		if len(data) < width {
			return data, false
		}
		i := r.Intn(len(data) - width + 1)
		value := r.randInt64()
		if r.oneOf(10) {
			value = swap64(value)
		}
		storeInt(data[i:], value, width)
		return data, true
	},
}

func swap16(v uint16) uint16 {
	v0 := byte(v >> 0)
	v1 := byte(v >> 8)
	v = 0
	v |= uint16(v1) << 0
	v |= uint16(v0) << 8
	return v
}

func swap32(v uint32) uint32 {
	v0 := byte(v >> 0)
	v1 := byte(v >> 8)
	v2 := byte(v >> 16)
	v3 := byte(v >> 24)
	v = 0
	v |= uint32(v3) << 0
	v |= uint32(v2) << 8
	v |= uint32(v1) << 16
	v |= uint32(v0) << 24
	return v
}

func swap64(v uint64) uint64 {
	v0 := byte(v >> 0)
	v1 := byte(v >> 8)
	v2 := byte(v >> 16)
	v3 := byte(v >> 24)
	v4 := byte(v >> 32)
	v5 := byte(v >> 40)
	v6 := byte(v >> 48)
	v7 := byte(v >> 56)
	v = 0
	v |= uint64(v7) << 0
	v |= uint64(v6) << 8
	v |= uint64(v5) << 16
	v |= uint64(v4) << 24
	v |= uint64(v3) << 32
	v |= uint64(v2) << 40
	v |= uint64(v1) << 48
	v |= uint64(v0) << 56
	return v
}

func swapInt(v uint64, size int) uint64 {
	switch size {
	case 1:
		return v
	case 2:
		return uint64(swap16(uint16(v)))
	case 4:
		return uint64(swap32(uint32(v)))
	case 8:
		return swap64(v)
	default:
		panic(fmt.Sprintf("swapInt: bad size %v", size))
	}
}

func loadInt(data []byte, size int) uint64 {
	switch size {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(data))
	case 4:
		return uint64(binary.LittleEndian.Uint32(data))
	case 8:
		return binary.LittleEndian.Uint64(data)
	default:
		panic(fmt.Sprintf("loadInt: bad size %v", size))
	}
}

func storeInt(data []byte, v uint64, size int) {
	switch size {
	case 1:
		data[0] = uint8(v)
	case 2:
		binary.LittleEndian.PutUint16(data, uint16(v))
	case 4:
		binary.LittleEndian.PutUint32(data, uint32(v))
	case 8:
		binary.LittleEndian.PutUint64(data, v)
	default:
		panic(fmt.Sprintf("storeInt: bad size %v", size))
	}
}


/*
	mutateFailPos()
*/

func (ctx *mutator) lastNNonFailCall(calls []*Call, idx int) (loc int) {
	for i:=idx; i >= 0; i-- {
		if strings.Contains(calls[i].Meta.Name, "syz_failure") {
			return loc
		} else if ctx.r.nOutOf(8, 10) {
			return i
		}
    }
	loc = -1
    return loc
}

func (ctx *mutator) nextNNonFailCall(calls []*Call, idx int) int {
	for i:=idx; i < len(calls); i++ {
		if !strings.Contains(calls[i].Meta.Name, "syz_failure") && ctx.r.nOutOf(6, 10) {
			return i
		}
	}
	return -1
}

func (ctx *mutator) mutateFailPos() bool {
	p, r := ctx.p, ctx.r
    if len(p.Calls) == 0 {
        return false
    }

    stop := false
    idx := 0
    cnt := 0
	insertPoint := 0
    for !stop {
        if cnt > 20 {
            return false
        }
		cnt += 1
        idx = r.Intn(len(p.Calls))
		if strings.Contains(p.Calls[idx].Meta.Name, "syz_failure_sync") {
			id := p.Calls[idx].Args[0].(*ConstArg).Val //TODO
			if id % 2 == 0 { //failure start point
				//look up for an non-failure call upside
				insertPoint = ctx.lastNNonFailCall(p.Calls, idx)
				if insertPoint == -1 {
					continue
				}
				p.Calls = append(append(append(append(make([]*Call, 0), p.Calls[:insertPoint]...), p.Calls[idx]),
									p.Calls[insertPoint:idx]...), p.Calls[idx+1:]...)
				log.Logf(0, "insert call %v at pos %v\n", idx, insertPoint)
				stop = true
			} else {
				//look up for an non-failure call downside
				insertPoint = ctx.nextNNonFailCall(p.Calls, idx)
				if insertPoint == -1 {
                    continue
                }
				p.Calls = append(p.Calls[:idx], append(append(append(make([]*Call, 0),
								p.Calls[idx+1:insertPoint+1]...), p.Calls[idx]), p.Calls[insertPoint+1:]...)...)
				log.Logf(0, "insert call %v at pos %v\n", idx, insertPoint)
				stop = true
			}
		}
	}
	return true
}


/*********************************** InsertFailures() *****************************************/
/*
	Example: recv(1); syz_down(); send(2); recv(3); syz_up(); send(4)
*/
func (ctx *mutator) genSrvFailCalls(startIdx *uint64, crashFailure bool, failInfo SrvFailInfo, ps []*Prog, idx int) {
	calls := make([]*Call, 0)
	calls = append(calls, ctx.genRecvCall(startIdx)...)
	calls = append(calls, ctx.genDownCall(crashFailure, failInfo)...)
	calls = append(calls, ctx.genSendCall(startIdx)...)
	calls = append(calls, ctx.genRecvCall(startIdx)...)
	calls = append(calls, ctx.genUpCall(crashFailure, failInfo)...)
	calls = append(calls, ctx.genSendCall(startIdx)...)
	ps[idx].insertEnd(calls)
}

func (ctx *mutator) genSyncCall(idxArg *uint64, cltArg int) (calls []*Call) {
	meta := ctx.r.target.Syscalls[ctx.sCalls.SyncfailId]
	c := MakeCall(meta, nil)
	c.IsFCall = true
	c.Args = make([]Arg, len(meta.Args))
	c.Args[0] = &ConstArg{ArgCommon: ArgCommon{ref: meta.Args[0].Type.ref(), dir: DirIn}, Val: *idxArg}
	c.Args[1] = &ConstArg{ArgCommon: ArgCommon{ref: meta.Args[1].Type.ref(), dir: DirIn}, Val: uint64(cltArg)}
	ctx.r.target.assignSizesCall(c)
	*idxArg = *idxArg + 1
	return append(calls, c)
}

func (ctx *mutator) genRecvCall(idxArg *uint64) (calls []*Call) {
	meta := ctx.r.target.Syscalls[ctx.sCalls.RecvId]
	c := MakeCall(meta, nil)
	c.IsFCall = true
	c.Args = make([]Arg, len(meta.Args))
	c.Args[0] = &ConstArg{ArgCommon: ArgCommon{ref: meta.Args[0].Type.ref(), dir: DirIn}, Val: *idxArg}
	ctx.r.target.assignSizesCall(c)
	//*idxArg = *idxArg + 1
	return append(calls, c)
}

func (ctx *mutator) genSendCall(arg *uint64) (calls []*Call) {
	meta := ctx.r.target.Syscalls[ctx.sCalls.SendId]
	c := MakeCall(meta, nil)
	c.IsFCall = true
	c.Args = make([]Arg, len(meta.Args))
	c.Args[0] = &ConstArg{ArgCommon: ArgCommon{ref: meta.Args[0].Type.ref(), dir: DirIn}, Val: *arg}
	ctx.r.target.assignSizesCall(c)
	*arg = *arg + 1
	return append(calls, c)
}

func (ctx *mutator) genNetCmd(failInfo SrvFailInfo) []byte {
	//PartNodes
	bytes := strings.Split(ctx.initIp, ".")
	lastByte, _ := strconv.Atoi(bytes[3])
	inputChanStr := ""
	outputChanStr := ""
	log.Logf(0, "part nodes: %v", failInfo.PartNodes)
	for _, node := range failInfo.PartNodes {
		inputChanStr += fmt.Sprintf("iptables -A INPUT -s %s.%s.%s.%d -j DROP;",
															bytes[0], bytes[1], bytes[2], lastByte+node)
		outputChanStr += fmt.Sprintf("iptables -A OUTPUT -d %s.%s.%s.%d -j DROP;",
															bytes[0], bytes[1], bytes[2], lastByte+node)
	}
	return []byte(inputChanStr + outputChanStr)
}

func (ctx *mutator) genDownCall(crashFailure bool, failInfo SrvFailInfo) []*Call {
	if crashFailure {
		meta := ctx.r.target.Syscalls[ctx.sCalls.DownId]
		calls := ctx.r.generateParticularCall(nil, meta)
		calls[len(calls)-1].IsFCall = true
		return calls
	} else {
		meta := ctx.r.target.Syscalls[ctx.sCalls.NetDownId]
		c := MakeCall(meta, nil)
		c.IsFCall = true
		s := newState(ctx.r.target, ctx.ct, nil)
		s.custData = append([]byte{}, ctx.genNetCmd(failInfo)...)
		c.Args, _ = ctx.r.generateArgs(s, meta.Args, DirIn)
		ctx.r.target.assignSizesCall(c)
		return append(make([]*Call, 0), c)
	}
}

func (ctx *mutator) genUpCall(crashFailure bool, failInfo SrvFailInfo) []*Call {
	callId := 0
	if crashFailure {
		callId = ctx.sCalls.UpId
	} else {
		callId = ctx.sCalls.NetUpId
	}
	meta := ctx.r.target.Syscalls[callId]
	calls := ctx.r.generateParticularCall(nil, meta)
	calls[len(calls)-1].IsFCall = true
	return calls
}

func (ctx *mutator) insertAtLast(cltSyncIdx *uint64, ps []*Prog, clt int) (loc int) {
	newCalls := ctx.genSyncCall(cltSyncIdx, clt)
	ps[clt].insertEnd(newCalls)
	return len(ps[clt].Calls)-1
}

func (ctx *mutator) findAndInsert(cltSyncIdx *uint64, ps []*Prog, clt int, targetCall *Call) (loc int) {
	for idx, call := range ps[clt].Calls {
		if call == targetCall {
			newCalls := ctx.genSyncCall(cltSyncIdx, clt)
			ps[clt].insertBefore(ps[clt].Calls[idx], newCalls)
			loc = idx
			log.Logf(0, "findAndInsert at %v", loc)
			return loc
		}
	}
	log.Fatalf("findAndInsert failed: can't find the call")
	return
}

/*
	Generate the insertable postion ranges for failure start sync and end sync.
	1. The sync order of failures in all clients have to be the same.
	2. Insert postions range from [0, callNum], the callNum-th postion means at the end of calls.
*/
func InsertablePos(ps1 []*Prog, clt int, srv int, srvNum int) ([]int, []int) {

	//func define: filter the insertable postions that are before failure calls
	filterFailureCalls := func(start int, end int, p *Prog) (posList []int) {
		i, callNum := start, len(p.Calls)
		for ; i <= end && i < callNum; i++ {
			//if !strings.Contains(p.Calls[i].Meta.Name, "syz_failure") {
			posList = append(posList, i)
			//}
		}
		if end >= callNum {
			posList = append(posList, callNum)
		}
		return posList
	}

	callNum := len(ps1[clt].Calls)
	startPosList, endPosList := make([]int, 0), make([]int, 0)


	//For the first client, we don't need to know the server failures orders
	if clt == srvNum {

		startPosList = filterFailureCalls(0, callNum, ps1[clt])
		endPosList = make([]int, len(startPosList))
		copy(endPosList, startPosList)

	} else {

		//func define: according to the server failure orders in the first client, get the insertion positions.
		getPosRange := func(srvFailOrder []int, p *Prog, curSrvIdx int) (posList []int) {

			srvFailPos := p.SrvFailPos
			CallNum := len(p.Calls)

			//func define
			arraySearch := func(srvFailPos [][]int, srv int) int {
				for _, item := range srvFailPos {
					if item[0] == srv {
						return item[1]
					}
				}
				return -1
			}

			posRange := []int{0, CallNum}
			for i:=curSrvIdx; i>=0; i-- {
				srv := srvFailOrder[i]
				ret := arraySearch(srvFailPos, srv)
				if ret != -1 {
					posRange[0] = ret+1
					break
				}
			}
		
			for i:=curSrvIdx; i<len(srvFailOrder); i++ {
				srv := srvFailOrder[i]
				ret := arraySearch(srvFailPos, srv)
				if ret != -1 {
					posRange[1] = ret
					break
				}
			}
			return filterFailureCalls(posRange[0], posRange[1], p)
		}

		//SrvFailOrder is descended ordered acrording to failure positions.
		for idx, s1 := range ps1[srvNum].SrvFailOrder {
			if s1 == srv*100+0*10+1 {
				startPosList = getPosRange(ps1[srvNum].SrvFailOrder, ps1[clt], idx)
			}
			if s1 == srv*100+0*10+2 {
				endPosList = getPosRange(ps1[srvNum].SrvFailOrder, ps1[clt], idx)
			}
		}
	}
	log.Logf(0, "filter Disconn Calls: %v %v, %v %v", clt, srv, startPosList, endPosList)
	return startPosList, endPosList
}

func (ctx *mutator) insertSync(start int, end int, cltSyncIdx *uint64, ps []*Prog, clt int, srv int) {
	loc1, loc2 := 0, 0
	log.Logf(0, "insertSync %v %v %v", start, end, len(ps[clt].Calls))

	if clt == 0 {
		log.Fatalf("clt is zero")
	}

	if start == -1 && end == -1 {

		loc1 = ctx.insertAtLast(cltSyncIdx, ps, clt)
		loc2 = ctx.insertAtLast(cltSyncIdx, ps, clt)

	} else {

		callNum := len(ps[clt].Calls)

		var endCall *Call
		if end < callNum {
			endCall = ps[clt].Calls[end]
		}

		if start < callNum {
			loc1 = ctx.findAndInsert(cltSyncIdx, ps, clt, ps[clt].Calls[start])
		} else {
			loc1 = ctx.insertAtLast(cltSyncIdx, ps, clt)
		}

		if end < callNum {
			loc2 = ctx.findAndInsert(cltSyncIdx, ps, clt, endCall)
		} else {
			loc2 = ctx.insertAtLast(cltSyncIdx, ps, clt)
		}
	}

	//The newly inserted sync syscalls effect the recorded locations of previous syncs, update them here.
	for idx, item := range ps[clt].SrvFailPos {
		loc := item[1]
		if loc >= start && loc >= end {
			loc += 2
		} else if loc >= start || loc >= end {
			loc += 1
		}
		ps[clt].SrvFailPos[idx][1] = loc
	}

	ps[clt].SrvFailPos = append(ps[clt].SrvFailPos, []int{srv*100+0*10+1, loc1}) //srv, failures, start/end
    ps[clt].SrvFailPos = append(ps[clt].SrvFailPos, []int{srv*100+0*10+2, loc2})
}

func LogProgram(ps []*Prog){
	delimiter := []byte("---\n")
    var data []byte
    for _, p := range ps {
        data = append(data, p.Serialize()...)
        data = append(data, delimiter...)
    }
}


func (ctx *mutator) enumSyncPoint(ps1 []*Prog, clt int, srv int) (newPs [][]*Prog) {

	//If this client doesn't have syscalls, insert sync and return here
	if len(ps1[clt].Calls) == 0 {
		ps2 := Clones(ps1)
        cltSyncIdx := ps2[clt].SyncIdx
		ctx.insertSync(-1, -1, &cltSyncIdx, ps2, clt, srv)
		ps2[clt].SyncIdx = cltSyncIdx
		newPs = append(newPs, ps2)
		return newPs
	}

	/*
		Decide whether call1 is before call2, and there is only one normal syscall between them.
	*/
	isAdjacent := func(p *Prog, call1 int, call2 int) bool {
		if call1 > call2 {
			return false
		}
		/*
		cnt := 0
		for i:=call1; i<call2; i++ {
			name := p.Calls[i].Meta.Name
			length := len(name)
			if length > 11 && name[:11] == "syz_failure" {
				continue
			}
			cnt ++
		}
		if cnt == 1 {
			return true
		}
		return false
		*/
		return true
	}

	startPosList, endPosList := InsertablePos(ps1, clt, srv, ctx.srvNum)

	//Enumerate all possbile failure start and end synchronization points
	for _, call1 := range startPosList {
		for _, call2 := range endPosList {
			if isAdjacent(ps1[clt], call1, call2) {
				ps2 := Clones(ps1)
				cltSyncIdx := ps2[clt].SyncIdx
				ctx.insertSync(call1, call2, &cltSyncIdx, ps2, clt, srv)
				ps2[clt].SyncIdx = cltSyncIdx
				newPs = append(newPs, ps2)
			}
		}
	}
	return newPs
}


func extractOrder(srvFailPos [][]int) (srvs []int) {
	sort.SliceStable(srvFailPos, func(i, j int) bool {
        return srvFailPos[i][1] < srvFailPos[j][1]
    })

	//server orders according to start points
	for _, item := range srvFailPos {
		srvs = append(srvs, item[0])
	}
	log.Logf(0, "extractOrder: %v, %v", srvFailPos, srvs)
	return srvs
}


func InsertFailure(rs rand.Source, ncalls int, ct *ChoiceTable, ps []*Prog, srvComb []SrvFailInfo,
	ch chan []*Prog, sCalls *SpecialCalls,
	syncStartIdx uint64, crashFailure bool, initIp string, srvNum int) {

	r := newRand(ps[0].Target, rs)
	ctx := &mutator{
		r:         r,
		ncalls:    ncalls,
		ct:        ct,
		sCalls:	   sCalls,
		initIp:    initIp,
		srvNum:    srvNum,
	}

	ps = Clones(ps)

	if crashFailure {
		ps[0].HasCrashFail = true
	} else {
		ps[0].HasNetFail = true
	}

	log.Logf(0, "InsertFailure: %v, %v", ps[0].HasCrashFail, ps[0].HasNetFail)

	srvSyncIdx := syncStartIdx
	for _, srvItem := range srvComb {
		srvIdx := srvItem.Srv
		ctx.genSrvFailCalls(&srvSyncIdx, crashFailure, srvItem, ps, srvIdx)
	}

	queue := make([][]*Prog, 0)
	queue = append(queue, ps)

	for clt := srvNum; clt < len(ps); clt++ {
		for _, srvItem := range srvComb {
			tmpQueue := make([][]*Prog, 0)
			for _, ps1 := range queue {
				//Extract the failures orders of servers
				if clt > srvNum && ps1[srvNum].SrvFailOrder == nil {
					ps1[srvNum].SrvFailOrder = extractOrder(ps1[srvNum].SrvFailPos)
				}
				//Enumerate the sync betwen one client and 1 failures of the server
				ret := ctx.enumSyncPoint(ps1, clt, srvItem.Srv)
				tmpQueue = append(tmpQueue, ret...)
			}
			queue = tmpQueue
			log.Logf(0, "clt %v srv %v queue %v", clt, srvItem.Srv, len(queue))
		}
	}
	log.Logf(0, "failure queue %v", len(queue))
	for _, ps1 := range queue {
		log.Logf(0, "send to channel: %v, %v", ps1[0].HasCrashFail, ps1[0].HasNetFail)
		//logProgram(ps1)
		ch <- ps1
	}
}

/******************************* RandomInsertFailure() ************************************/
func RandomInsertFailure(ps []*Prog, srvNum int, rs rand.Source, sCalls *SpecialCalls, initIp string) {

	log.Logf(0, "RandomInsertFailure()\n")

	r := newRand(ps[0].Target, rs)
	srvStartIdx := uint64(0)

	ctx := &mutator{
        r:              r,
		sCalls:			sCalls,
        initIp:			initIp,
		srvNum:         srvNum,
    }

	randomSrvs := r.RandSet(0, srvNum-1, r.Intn(srvNum)+1)
	log.Logf(0, "failed servers: %v\n", randomSrvs)
	for i, srv := range randomSrvs {

		crashFail := r.nOutOf(1,2)
		failInfo := SrvFailInfo{srv, make([]int, 0)}
		if !crashFail {
			failInfo.PartNodes = r.RandSetExcept(0, len(ps)-1, r.Intn(len(ps))+1, srv)
		}
		ctx.genSrvFailCalls(&srvStartIdx, crashFail, failInfo, ps, srv)

		for clt := srvNum; clt < len(ps); clt ++ {
			cltSyncIdx := uint64(0)
			if i != 0 {
				cltSyncIdx = ps[clt].SyncIdx
			}

			//Extract the failures orders of servers
			if clt > srvNum && ps[srvNum].SrvFailOrder == nil {
				ps[srvNum].SrvFailOrder = extractOrder(ps[srvNum].SrvFailPos)
			}

			//func define
			randSelectCandidates := func(startPosList []int, endPosList []int) (int, int) {
				candidates := make([][]int, 0)
				for _, call1 := range startPosList {
					for _, call2 := range endPosList {
						if call1 <= call2 {
							candidates = append(candidates, []int{call1, call2})
						}
					}
				}
				if len(candidates) == 0 {
					log.Fatalf("random insert failure: there is no positions")
				}
				randIdx := r.Intn(len(candidates))
				startPos, endPos := candidates[randIdx][0], candidates[randIdx][1]
				return startPos, endPos
			}

			startPosList, endPosList := InsertablePos(ps, clt, srv, srvNum)
			startPos, endPos := randSelectCandidates(startPosList, endPosList)

			ctx.insertSync(startPos, endPos, &cltSyncIdx, ps, clt, srv)
			ps[clt].SyncIdx = cltSyncIdx
		}
		if crashFail {
			ps[0].HasCrashFail = true
		} else {
			ps[0].HasNetFail = true
		}
	}
}



/*************** Insert crashes to servers and clients for crash consistency bugs *****************/

func InsertSrvCrash(p *Prog, r *randGen, sCalls *SpecialCalls) {
	meta := r.target.Syscalls[sCalls.CrashServer]
    c := MakeCall(meta, nil)
    c.Args = make([]Arg, len(meta.Args))
    r.target.assignSizesCall(c)
    p.Calls = append(p.Calls, c)
}

func InsertCltCrash(p *Prog, willCrash int, r *randGen, sCalls *SpecialCalls) {
	meta := r.target.Syscalls[sCalls.CrashClient]
	c := MakeCall(meta, nil)
    c.Args = make([]Arg, len(meta.Args))
    c.Args[0] = &ConstArg{ArgCommon: ArgCommon{ref: meta.Args[0].Type.ref(), dir: DirIn}, Val: uint64(willCrash)}
    r.target.assignSizesCall(c)
	p.Calls = append(p.Calls, c)
}

func ProgCrashAll(ps []*Prog, servNum int, r *randGen, sCalls *SpecialCalls) []*Prog {
	ps1 := Clones(ps)
	ps1[0].C2test = true
	for idx, p := range ps1 {
		if idx < servNum {
			InsertSrvCrash(p, r, sCalls)
		} else {
			InsertCltCrash(p, 1, r, sCalls)
		}
	}
	return ps1
}

func ProgCrashRand(ps []*Prog, servNum int, r *randGen, sCalls *SpecialCalls) []*Prog {
	ps1 := Clones(ps)
	ps1[0].C2test = true
	//psLen := len(ps1)
	psIdx := r.RandSet(0, servNum-1, r.Intn(servNum)+1)
	for _, idx := range psIdx {
		if idx < servNum {
			InsertSrvCrash(ps1[idx], r, sCalls)
		}
	}

	for i := servNum; i < len(ps1); i++ {
		if IsIn(psIdx, i) {
			InsertCltCrash(ps1[i], 1, r, sCalls)
		} else {
			InsertCltCrash(ps1[i], 0, r, sCalls)
		}
	}
	return ps1
}
