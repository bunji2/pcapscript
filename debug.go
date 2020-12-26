package main

import (
	"fmt"
	"os"
)

var debugFlag = false // = true

func debug(msg ...interface{}) {
	if !debugFlag {
		return
	}
	fmt.Fprint(os.Stderr, "[DEBUG] ")
	fmt.Fprintln(os.Stderr, msg...)
}
