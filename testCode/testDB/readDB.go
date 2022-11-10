package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS     = flag.String("os", runtime.GOOS, "target os")
	flagArch   = flag.String("arch", runtime.GOARCH, "target arch")
	flagCorpus = flag.String("corpus", "", "name of the corpus file")
)

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	corpus, err := db.ReadCorpus(*flagCorpus, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read corpus: %v\n", err)
		os.Exit(1)
	}
	for _, v := range corpus {
		for j, v1 := range v.Calls {
			fmt.Printf("序号%d ,ID:%v, Name:%v\n", j, v1.Meta.ID, v1.Meta.Name)
		}
		fmt.Printf("\n")
	}
	fmt.Println("length of corpus:", len(corpus))
}
