package main

import (
	"github.com/ggaaooppeenngg/dufu"
)

func main() {
	tap, err := dufu.NewTAP("tap_dufu")
	if err != nil {
		panic(err)
	}
	_ := NewL2Layer(tap)
	select {}
}
