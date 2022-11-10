// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"sort"
)

// Calulation of call-to-call priorities.
// For a given pair of calls X and Y, the priority is our guess as to whether
// additional of call Y into a program containing call X is likely to give
// new coverage or not.
// The current algorithm has two components: static and dynamic.
// The static component is based on analysis of argument types. For example,
// if call X and call Y both accept fd[sock], then they are more likely to give
// new coverage together.
// The dynamic component is based on frequency of occurrence of a particular
// pair of syscalls in a single program in corpus. For example, if socket and
// connect frequently occur in programs together, we give higher priority to
// this pair of syscalls.
// Note: the current implementation is very basic, there is no theory behind any
// constants.

func (target *Target) CalculatePriorities(corpus []*Prog) [][]int32 {
	static := target.calcStaticPriorities()
	if len(corpus) != 0 {
		dynamic := target.calcDynamicPrio(corpus, static)
		// for i, prios := range dynamic {
		// 	dst := static[i]
		// 	for j, p := range prios {
		// 		dst[j] = dst[j] * p / prioHigh
		// 	}
		// }
		// for i, v0 := range static { //Test can remove
		// 	key := false
		// 	for j, _ := range v0 {
		// 		if static[i][j] != dynamic[i][j] {
		// 			fmt.Println("success")
		// 			key = true
		// 			break
		// 		}
		// 	}
		// 	if key {
		// 		break
		// 	}
		// }
		return dynamic
	}
	return static
}

func (target *Target) calcStaticPriorities() [][]int32 {
	uses := target.calcResourceUsage()
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, weights := range uses {
		for _, w0 := range weights {
			for _, w1 := range weights {
				if w0.call == w1.call {
					// Self-priority is assigned below.
					continue
				}
				// The static priority is assigned based on the direction of arguments. A higher priority will be
				// assigned when c0 is a call that produces a resource and c1 a call that uses that resource.
				prios[w0.call][w1.call] += w0.inout*w1.in*3/2 + w0.inout*w1.inout
			}
		}
	}
	normalizePrio(prios)
	// The value assigned for self-priority (call wrt itself) have to be high, but not too high.
	for c0, pp := range prios {
		pp[c0] = prioHigh * 9 / 10
	}
	return prios
}

func (target *Target) calcResourceUsage() map[string]map[int]weights {
	uses := make(map[string]map[int]weights)
	ForeachType(target.Syscalls, func(t Type, ctx *TypeCtx) {
		c := ctx.Meta
		switch a := t.(type) {
		case *ResourceType:
			if target.AuxResources[a.Desc.Name] {
				noteUsage(uses, c, 1, ctx.Dir, "res%v", a.Desc.Name)
			} else {
				str := "res"
				for i, k := range a.Desc.Kind {
					str += "-" + k
					w := int32(10)
					if i < len(a.Desc.Kind)-1 {
						w = 2
					}
					noteUsage(uses, c, w, ctx.Dir, str)
				}
			}
		case *PtrType:
			if _, ok := a.Elem.(*StructType); ok {
				noteUsage(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if _, ok := a.Elem.(*UnionType); ok {
				noteUsage(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if arr, ok := a.Elem.(*ArrayType); ok {
				noteUsage(uses, c, 10, ctx.Dir, "ptrto-%v", arr.Elem.Name())
			}
		case *BufferType:
			switch a.Kind {
			case BufferBlobRand, BufferBlobRange, BufferText:
			case BufferString, BufferGlob:
				if a.SubKind != "" {
					noteUsage(uses, c, 2, ctx.Dir, fmt.Sprintf("str-%v", a.SubKind))
				}
			case BufferFilename:
				noteUsage(uses, c, 10, DirIn, "filename")
			default:
				panic("unknown buffer kind")
			}
		case *VmaType:
			noteUsage(uses, c, 5, ctx.Dir, "vma")
		case *IntType:
			switch a.Kind {
			case IntPlain, IntRange:
			default:
				panic("unknown int kind")
			}
		}
	})
	return uses
}

type weights struct {
	call  int
	in    int32
	inout int32
}

type NGraph struct {
	Graph [][]int
	IDmap map[int]int
}

type TwoGramTable struct {
	NGraph
	Paths [][]int
	Fre   map[int]map[int]int32
	Prope map[int]map[int]float32
}

func MakeNgraph() *NGraph {
	NewGraph := &NGraph{
		Graph: make([][]int, 0),
		IDmap: make(map[int]int),
	}
	return NewGraph
}

func MakeTwoGram() *TwoGramTable {
	return &TwoGramTable{
		Fre:    make(map[int]map[int]int32),
		Prope:  make(map[int]map[int]float32),
		Paths:  make([][]int, 0),
		NGraph: *MakeNgraph(),
	}
}

func (twogram *TwoGramTable) GenerateSeqence(p *Prog, static [][]int32) {
	IDmap := make(map[int]int) //将static映射到一个子图中，子图的1-n与原ID映射
	idNumber := []int{}
	globalVisit := []int{}
	for i, call := range p.Calls { //一些初始化操作
		idNumber = append(idNumber, call.Meta.ID)
		globalVisit = append(globalVisit, 0)
		IDmap[i] = call.Meta.ID
	}
	Graph := make([][]int, len(idNumber))
	for i := range Graph {
		Graph[i] = make([]int, len(idNumber))
	}
	for i, valuei := range idNumber { //构建子图
		for j, valuej := range idNumber {
			Graph[i][j] = int(static[valuei][valuej])
		}
	}
	var Paths [][]int
	var path []int
	var DFS func(int, []int)
	DFS = func(i int, globalVisit []int) {
		path = append(path, i)
		globalVisit[i] = 1
		defer func() {
			path = path[:len(path)-1]
		}()

		if NoAppend(i, Graph) {
			ans := make([]int, len(path))
			copy(ans, path)
			Paths = append(Paths, ans)
			return
		}
		value := Graph[i]

		for j, val := range value {
			if j > i && val != 0 {
				DFS(j, globalVisit)
			}
		}
	}
	for i := range globalVisit {
		if globalVisit[i] != 1 {
			globalVisit[i] = 1
			DFS(i, globalVisit)
		}
	}
	twogram.Graph = Graph
	twogram.IDmap = IDmap
	twogram.Paths = Paths
}

func (twogram *TwoGramTable) CalculateFrequency() {
	Myfre := twogram.Fre
	if Myfre == nil {
		fmt.Println("error")
	}
	Paths := twogram.Paths
	IDmap := twogram.IDmap
	for _, path := range Paths {
		for i := 0; i < len(path)-1; i++ {
			if Myfre[IDmap[path[i]]] == nil {
				Myfre[IDmap[path[i]]] = make(map[int]int32)
			}
			if Myfre[IDmap[path[i]]][IDmap[path[i+1]]] == 0 {
				Myfre[IDmap[path[i]]][IDmap[path[i+1]]] = 1
			} else {
				Myfre[IDmap[path[i]]][IDmap[path[i+1]]] += 1
			}
		}
	}
}

func (twogram *TwoGramTable) CalculateProbalility() {
	Prope := twogram.Prope
	value := twogram.Fre
	for i, v0 := range value {
		var fenmu float32
		fenmu = 0
		for _, v2 := range v0 {
			fenmu += float32(v2)
		}
		for j, v1 := range v0 {
			if Prope[i] == nil {
				Prope[i] = make(map[int]float32)
			}
			v1f := float32(v1)
			Prope[i][j] = v1f / fenmu
		}
	}
}

func NoAppend(i int, Graph [][]int) bool { //到达的该点没有可达的后继节点
	if i == len(Graph[i]) {
		return true
	}
	value := Graph[i]
	for _, val := range value[i+1:] {
		if val != 0 {
			return false
		}
	}
	return true

}

func noteUsage(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, str string, args ...interface{}) {
	id := fmt.Sprintf(str, args...)
	if uses[id] == nil {
		uses[id] = make(map[int]weights)
	}
	callWeight := uses[id][c.ID]
	callWeight.call = c.ID
	if dir != DirOut {
		if weight > uses[id][c.ID].in {
			callWeight.in = weight
		}
	}
	if weight > uses[id][c.ID].inout {
		callWeight.inout = weight
	}
	uses[id][c.ID] = callWeight
}

// func (target *Target) calcDynamicPrio(corpus []*Prog) [][]int32 {
// 	prios := make([][]int32, len(target.Syscalls))
// 	for i := range prios {
// 		prios[i] = make([]int32, len(target.Syscalls))
// 	}
// 	for _, p := range corpus {
// 		for idx0, c0 := range p.Calls {
// 			for _, c1 := range p.Calls[idx0+1:] {
// 				prios[c0.Meta.ID][c1.Meta.ID]++
// 			}
// 		}
// 	}
// 	normalizePrio(prios)
// 	return prios
// }
var twogram *TwoGramTable

//TODO:
func (target *Target) calcDynamicPrio(corpus []*Prog, static [][]int32) [][]int32 {
	ret := make([][]int32, len(target.Syscalls))
	for i := range ret {
		ret[i] = make([]int32, len(target.Syscalls))
	}
	twogram = MakeTwoGram()
	for _, p := range corpus {
		if len(p.Calls) > 1 {
			twogram.GenerateSeqence(p, static) //生成序列
			twogram.CalculateFrequency()
		}
	}
	twogram.CalculateProbalility()
	//2-gram所得结果与静态结果修正
	copy(ret, static)
	for i, v0 := range twogram.Prope {
		var sum float32
		sum = 0
		for j, _ := range v0 {
			sum += float32(ret[i][j])
		}
		for j, v1 := range v0 {
			//fmt.Println("before", ret[i][j])
			ret[i][j] += int32(sum * v1)
			//fmt.Println("after", ret[i][j])
		}
	}
	return ret
}

const (
	prioLow  = 10
	prioHigh = 1000
)

// normalizePrio normalizes priorities to [prioLow..prioHigh] range.
func normalizePrio(prios [][]int32) {
	for _, prio := range prios {
		max := int32(1)
		for _, p := range prio {
			if max < p {
				max = p
			}
		}
		for i, p := range prio {
			prio[i] = prioLow + p*(prioHigh-prioLow)/max
		}
	}
}

//TODO
func (target *Target) BuildTwoGramTable() (map[int]map[int]float32, map[int]map[int]int32) {
	if twogram == nil {
		panic("no twogram build")
	}
	return twogram.Prope, twogram.Fre
}

// ChooseTable allows to do a weighted choice of a syscall for a given syscall
// based on call-to-call priorities and a set of enabled and generatable syscalls.
type ChoiceTable struct {
	target          *Target
	runs            [][]int32
	calls           []*Syscall
	noGenerateCalls map[int]bool
}

func (target *Target) BuildChoiceTable(corpus []*Prog, enabled map[*Syscall]bool) *ChoiceTable {
	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
		}
	}
	noGenerateCalls := make(map[int]bool)
	for call := range enabled {
		if call.Attrs.Disabled {
			delete(enabled, call)
		} else if call.Attrs.NoGenerate {
			noGenerateCalls[call.ID] = true
			delete(enabled, call)
		}
	}
	var generatableCalls []*Syscall
	for c := range enabled {
		generatableCalls = append(generatableCalls, c)
	}
	if len(generatableCalls) == 0 {
		panic("no syscalls enabled and generatable")
	}
	sort.Slice(generatableCalls, func(i, j int) bool {
		return generatableCalls[i].ID < generatableCalls[j].ID
	})
	for _, p := range corpus {
		for _, call := range p.Calls {
			if !enabled[call.Meta] && !noGenerateCalls[call.Meta.ID] {
				fmt.Printf("corpus contains disabled syscall %v\n", call.Meta.Name)
				panic("disabled syscall")
			}
		}
	}
	prios := target.CalculatePriorities(corpus)
	run := make([][]int32, len(target.Syscalls))
	for i := range run {
		if !enabled[target.Syscalls[i]] {
			continue
		}
		run[i] = make([]int32, len(target.Syscalls))
		var sum int32
		for j := range run[i] {
			if enabled[target.Syscalls[j]] {
				sum += prios[i][j]
			}
			run[i][j] = sum
		}
	}
	return &ChoiceTable{target, run, generatableCalls, noGenerateCalls}
}

func (ct *ChoiceTable) Enabled(call int) bool {
	return ct.Generatable(call) || ct.noGenerateCalls[call]
}

func (ct *ChoiceTable) Generatable(call int) bool {
	return ct.runs[call] != nil
}

func NotInSlice(call int, globalVisit []int) bool {
	ret := true
	for _, v := range globalVisit {
		if v == call {
			ret = false
			break
		}
	}
	return ret
}

func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int { //choiceTable根据bias选后一个
	if bias < 0 {
		bias = ct.calls[r.Intn(len(ct.calls))].ID
	}
	if !ct.Generatable(bias) {
		fmt.Printf("bias to disabled or non-generatable syscall %v\n", ct.target.Syscalls[bias].Name)
		panic("disabled or non-generatable syscall")
	}
	run := ct.runs[bias]
	x := int32(r.Intn(int(run[len(run)-1])) + 1)
	res := sort.Search(len(run), func(i int) bool {
		return run[i] >= x
	})
	if !ct.Generatable(res) {
		panic("selected disabled or non-generatable syscall")
	}
	return res
}

func (ct *ChoiceTable) chooseFront(r *rand.Rand, globalVisit []int, bias int) int { //choiceTable根据bias选前一个
	runs := ct.runs
	run := make([]int32, 0)
	for _, v0 := range runs {
		if bias == 0 {
			run = append(run, v0[bias])
		} else {
			run = append(run, v0[bias]-v0[bias-1])
		}
	}
	for i := 1; i < len(run); i++ {
		run[i] += run[i-1]
	}
	x := int32(r.Intn(int(run[len(run)-1])) + 1)
	res := sort.Search(len(run), func(i int) bool {
		return run[i] >= x
	})
	// if !ct.Generatable(res) {
	// 	panic("selected disabled or non-generatable syscall")
	// }
	for ; res < len(run); res++ { //选一个不在globalVisit的调用
		if NotInSlice(res, globalVisit) {
			return res
		}
	}
	return -1
}

func (ct *ChoiceTable) NgramChoose(r *rand.Rand, prope map[int]map[int]float32, globalVisit []int, bias int) int { //根据ngram选后一个
	if bias < 0 {
		var callslice []int
		for k := range prope {
			callslice = append(callslice, k)
		}
		biasID := r.Intn(len(callslice))
		bias = callslice[biasID]
	}
	run := prope[bias]
	for i := 1; i < len(run); i++ {
		run[i] += run[i-1]
	}
	x := r.Float32()
	res := sort.Search(len(run), func(i int) bool {
		return run[i] >= x
	})
	for ; res < len(run); res++ {
		if NotInSlice(res, globalVisit) {
			return res
		}
	}
	return -1
}

func (ct *ChoiceTable) NgramChooseFront(r *rand.Rand, prope map[int]map[int]int32, globalVisit []int, bias int) int { //根据ngram选前一个
	var ret int
	ret = -1
	var max int32
	max = 0
	for k0, v0 := range prope {
		for k1, v1 := range v0 {
			if k1 == bias && NotInSlice(k0, globalVisit) {
				if v1 > max {
					max = v1
					ret = k0
				}
			}
		}
	}
	return ret
}
