package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS      = flag.String("os", runtime.GOOS, "target os")
	flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
	flagCorpus1 = flag.String("pcorpus", "", "name of the psyz corpus file")
	flagCorpus2 = flag.String("ocorpus", "", "name of the other corpus file")
)

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	//psyz corpus start
	corpus1, err := db.ReadCorpus(*flagCorpus1, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read corpus: %v\n", err)
		os.Exit(1)
	}
	pcorpusHash1 := make(map[hash.Sig]struct{})
	pcorpusHash2 := make(map[hash.Sig]struct{})
	for _, v := range corpus1 {
		data := v.Serialize()
		sig := hash.Hash(data)
		pcorpusHash1[sig] = struct{}{}
	}
	//psyz corpus ends!

	//other corpus start
	corpus2, err := db.ReadCorpus(*flagCorpus2, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read corpus: %v\n", err)
		os.Exit(1)
	}
	ocorpusHash1 := make(map[hash.Sig]struct{})
	ocorpusHash2 := make(map[hash.Sig]struct{})
	for _, v := range corpus2 {
		data := v.Serialize()
		sig := hash.Hash(data)
		ocorpusHash1[sig] = struct{}{}
		if _, ok := pcorpusHash1[sig]; !ok {
			ocorpusHash2[sig] = struct{}{}
		}
	}
	//other corpus ends!

	for _, v := range corpus1 {
		data := v.Serialize()
		sig := hash.Hash(data)
		if _, ok := ocorpusHash1[sig]; !ok {
			pcorpusHash2[sig] = struct{}{}
		}
	}
	fmt.Println("length of psyz corpus:", len(corpus1))
	fmt.Println("length of psyzcorpusHash1:", len(pcorpusHash1))
	fmt.Println("length of psyzcorpusHash2:", len(pcorpusHash2))
	fmt.Println("length of other corpus:", len(corpus2))
	fmt.Println("length of other corpusHash1:", len(ocorpusHash1))
	fmt.Println("length of other corpusHash2:", len(ocorpusHash2))
}
