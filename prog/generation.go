// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
)

//choose one program
func (target *Target) ChooseOne(rs rand.Source, globalVisit []int, ct *ChoiceTable, isFirst bool) (id int, dir int) {
	Prope, Fre := target.BuildTwoGramTable()
	if isFirst { //选首个调用，选取2-gram表中的出度最大值
		var maxNum int32 //每行的最值
		var outgree int  //最大的出度
		maxNum = 0
		for i, v0 := range Fre {
			var sumLine int32
			sumLine = 0 //一行的和
			for _, v1 := range v0 {
				sumLine += v1
			}
			if maxNum < sumLine {
				maxNum = sumLine
				outgree = i
			}
		}
		return outgree, 0

	} else { //其他位置调用
		rd := rand.Intn(2)                       //随机数选前面还是后面
		biasIndex := rand.Intn(len(globalVisit)) //选择bias的下标随机数
		bias := globalVisit[biasIndex]
		r := newRand(target, rs)
		//1选前向
		if rd == 1 {
			if ct.NgramChooseFront(r.Rand, Fre, globalVisit, bias) != -1 { //在N-gram表中没有该项
				return ct.NgramChooseFront(r.Rand, Fre, globalVisit, bias), rd
			} else {
				return ct.chooseFront(r.Rand, globalVisit, bias), rd
			}
		} else { //0选后向
			if ct.NgramChoose(r.Rand, Prope, globalVisit, bias) != -1 {
				return ct.NgramChoose(r.Rand, Prope, globalVisit, bias), rd
			} else {
				return ct.choose(r.Rand, bias), rd
			}
		}
	}
}

func AppendGraph(ngraph *NGraph, before int, choose int, dir int) { //扩展选择的子图
	idmap := ngraph.IDmap
	if dir == 1 {
		ngraph.Graph[idmap[choose]] = make([]int, 100) //如果是选前向，需要开辟数组
		ngraph.Graph[idmap[choose]][idmap[before]] = 1 //choose后是before
	} else {
		ngraph.Graph[idmap[before]][idmap[choose]] = 1 //before后是choose
	}
}

//Generate graph,生成无向图
func (target *Target) GenGraph(rs rand.Source, ncalls int, ct *ChoiceTable) *NGraph {
	globalVisit := make([]int, 0)
	ngraph := &NGraph{
		IDmap: make(map[int]int),
		Graph: make([][]int, ncalls),
	}
	choose, _ := target.ChooseOne(rs, globalVisit, ct, true) //选择第一个调用
	globalVisit = append(globalVisit, choose)
	ngraph.Graph[0] = make([]int, 0)
	ngraph.IDmap[choose] = 0
	i := 1
	var dir int
	for len(globalVisit) < ncalls {
		before := choose
		choose, dir = target.ChooseOne(rs, globalVisit, ct, false)
		globalVisit = append(globalVisit, choose)
		ngraph.IDmap[choose] = i
		if dir == 0 {
			ngraph.Graph[i] = make([]int, 0)
		}
		i++
		AppendGraph(ngraph, before, choose, dir)
	}
	return ngraph
}

//使用拓扑排序构建调用序列
func GenFromGraph(ngraph *NGraph) [][]int {
	return TopoSort(ngraph.Graph)
}

// // Generate generates a random program with ncalls calls.
// // ct contains a set of allowed syscalls, if nil all syscalls are used.
// func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
// 	p := &Prog{
// 		Target: target,
// 	}
// 	r := newRand(target, rs)
// 	s := newState(target, ct, nil)
// 	for len(p.Calls) < ncalls {
// 		calls := r.generateCall(s, p, len(p.Calls))
// 		for _, c := range calls {
// 			s.analyze(c)
// 			p.Calls = append(p.Calls, c)
// 		}
// 	}
// 	// For the last generated call we could get additional calls that create
// 	// resources and overflow ncalls. Remove some of these calls.
// 	// The resources in the last call will be replaced with the default values,
// 	// which is exactly what we want.
// 	for len(p.Calls) > ncalls {
// 		p.RemoveCall(ncalls - 1)
// 	}
// 	p.sanitizeFix()
// 	p.debugValidate()
// 	return p
// }

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	ngragh := target.GenGraph(rs, ncalls, ct)
	calls := GenFromGraph(ngragh)
	//for _,call:=range calls {
	call := calls[0] //先实验一波
	for _, item := range call {
		idx := ngragh.IDmap[item]
		meta := s.target.Syscalls[idx]
		gencalls := r.generateParticularCall(s, meta)
		for _, c := range gencalls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	//}
	// for len(p.Calls) < ncalls {
	// 	calls := r.generateCall(s, p, len(p.Calls))
	// 	for _, c := range calls {
	// 		s.analyze(c)
	// 		p.Calls = append(p.Calls, c)
	// 	}
	// }
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}
