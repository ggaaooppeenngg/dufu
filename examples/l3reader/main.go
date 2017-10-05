package main

import "fmt"

func main() {
	tap, err := dufu.NewTAP("tap_dufu")
	if err != nil {
		panic(err)
	}
	l3 := NewL3Layer(NewL2Layer(tap))
}
