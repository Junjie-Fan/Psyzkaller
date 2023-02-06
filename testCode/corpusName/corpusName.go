package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS      = flag.String("os", runtime.GOOS, "target os")
	flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
	flagCorpus1 = flag.String("pcorpus", "", "name of the corpus file")
	flagCorpus2 = flag.String("ocorpus", "", "name of the corpus file")
)

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	pcorpus, err := db.ReadCorpus(*flagCorpus1, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read corpus: %v\n", err)
		os.Exit(1)
	}
	pnameHash := make(map[hash.Sig]struct{})
	puniqueHash := make(map[hash.Sig]struct{})
	plength := make(map[int]int)
	olength := make(map[int]int)
	for _, v := range pcorpus {
		corpusStr := ""
		for _, v1 := range v.Calls {
			corpusStr += v1.Meta.Name + "-"
		}
		strings.TrimRight(corpusStr, "-")
		var data []byte = []byte(corpusStr)
		sig := hash.Hash(data)
		pnameHash[sig] = struct{}{}
		if _, ok := plength[len(v.Calls)]; !ok {
			plength[len(v.Calls)] = 1
		} else {
			plength[len(v.Calls)]++
		}
	}

	ocorpus, err := db.ReadCorpus(*flagCorpus2, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read corpus: %v\n", err)
		os.Exit(1)
	}
	onameHash := make(map[hash.Sig]struct{})
	ouniqueHash := make(map[hash.Sig]struct{})
	for _, v := range ocorpus {
		corpusStr := ""
		for _, v1 := range v.Calls {
			corpusStr += v1.Meta.Name + "-"
		}
		strings.TrimRight(corpusStr, "-")
		var data []byte = []byte(corpusStr)
		sig := hash.Hash(data)
		if _, ok := pnameHash[sig]; !ok {
			ouniqueHash[sig] = struct{}{}
		}
		onameHash[sig] = struct{}{}
		if _, ok := olength[len(v.Calls)]; !ok {
			olength[len(v.Calls)] = 1
		} else {
			olength[len(v.Calls)]++
		}
	}

	for k, _ := range pnameHash {
		if _, ok := onameHash[k]; !ok {
			puniqueHash[k] = struct{}{}
		}
	}
	fmt.Println("length of psyz corpus:", len(pcorpus))
	fmt.Println("length of pname corpus", len(pnameHash))
	fmt.Println("length of punique corpus:", len(puniqueHash))
	fmt.Println("length of osyz corpus:", len(ocorpus))
	fmt.Println("length of oname corpus", len(onameHash))
	fmt.Println("length of ounique corpus:", len(ouniqueHash))
	fmt.Printf("\n")
	fmt.Println("plengh:", plength)
	fmt.Printf("\n")
	fmt.Println("olength:", olength)
}
