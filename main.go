package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	usageFmt = "Usage: %s [ -D ] script.js file.pcap [ outdir ] \n"
)

func main() {
	os.Exit(run())
}

func run() (exitCode int) {

	args := os.Args[1:]

	if len(args) > 0 && args[0] == "-D" { // debug mode
		debugFlag = true
		args = args[1:]
	}

	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, usageFmt, os.Args[0])
		exitCode = 1
		return
	}

	scriptFile := args[0]
	pcapFile := args[1]

	outdir := "."
	if len(args) > 2 {
		outdir = args[2]
	}

	outdir = strings.TrimSpace(outdir)
	if outdir == "" || outdir == "/" {
		outdir = "."
	}

	debug("scriptFile =", scriptFile)
	debug("pcapFile =", pcapFile)
	debug("outdir =", outdir)

	err := process(scriptFile, pcapFile, outdir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitCode = 2
	}

	return
}
