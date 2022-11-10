package main

import (
	"fmt"

	. "github.com/google/syzkaller/pkg/signal"
)

func main() {
	var raw []uint32
	var i uint32
	for i = 0; i < 5; i++ {
		raw = append(raw, i)
	}
	a := FromRaw(raw, 1)
	fmt.Println(a.Len())
	for i, key := range a { //a
		fmt.Println(i, " :", key)
	}
	fmt.Println("==============")
	b := a.Copy()
	fmt.Println(b.Len())
	for i, _ := range b { //b copy from a
		b[i] += 1
		//fmt.Println(i, " :", key)
	}
	fmt.Println("==============")
	for i, key := range b {
		fmt.Println(i, " :", key)
	}
	fmt.Println("==============")
	a.Split(2)
	fmt.Println(a.Len())
	for i, key := range a {
		fmt.Println(i, " :", key)
	}
	for i, key := range b {
		fmt.Println(i, " :", key)
	}
	fmt.Println("==============")
	seria := a.Serialize()
	fmt.Println(seria)
	fmt.Println("==============")
	deseri := seria.Deserialize()
	fmt.Println(deseri)
	fmt.Println("==============")
	diffab := a.Diff(b)
	fmt.Println(diffab)
	fmt.Println("==============")

	diffba := b.Diff(a)
	fmt.Println(diffba)
	fmt.Println("==============")
	interab := b.Intersection(a)
	fmt.Println(interab)
	fmt.Println("===============")
	interba := a.Intersection(b)
	fmt.Println(interba)
	fmt.Println("===============")
	(a).Merge(b)
	fmt.Println(a)
	fmt.Println("===============")

}
