package main

import (
	"fmt"
	"os"
	"strings"

	"monarch/pkg/db"
	"monarch/prog"
    //"monarch/sys/targets"
    _ "monarch/sys/linux/gen" // import the target we use for fuzzing
)

var fuzzTarget, fuzzChoiceTable = func() (*prog.Target, *prog.ChoiceTable) {
    prog.Debug()
    target, err := prog.GetTarget("linux", "amd64")
    if err != nil {
        panic(err)
    }
    return target, target.DefaultChoiceTable()
}()

func main() {
	corpusDB, err := db.Open(os.Args[1])
	if err != nil {
		fmt.Printf("open db error\n")
	}

	failT := 0
	nonfailedT := 0
	progCnt := 0
	callCnt := 0

	for _, rec := range corpusDB.Records {
		p0, err0 := fuzzTarget.Deserialize(rec.Val, prog.NonStrict)
		if err0 != nil {
			fmt.Printf("Extraction error %v\n", err0);
		} else {
			progStr := fmt.Sprintf("%v", p0)
			if strings.Contains(progStr, "syz_failure") {
				failT += 1
			} else {
				nonfailedT += 1
			}
		}
		for _, p := range p0 {
			callCnt += len(p.Calls)
		}
		progCnt += 1
	}

	fmt.Printf("Rate:%v, (%v:%v), callAvg:%v\n", float64(failT)/float64(failT+nonfailedT), failT, nonfailedT, float64(callCnt)/float64(progCnt))
}
