package main

import (
	"fmt"

	"monarch/pkg/host"
)

func main() {

	for _, check := range host.CheckFeature {
		if check == nil {
			continue
		}
		reason := check()
		fmt.Printf("%v\n", reason)
	}
	//return res, nil
}
