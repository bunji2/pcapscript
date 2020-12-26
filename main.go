package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	usageFmt = "Usage: %s script.js file.pcap [outdir] \n"
)

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, usageFmt, os.Args[0])
		exitCode = 1
		return
	}

	scriptFile := os.Args[1]
	pcapFile := os.Args[2]

	outdir := "."
	if len(os.Args) > 3 {
		outdir = os.Args[3]
	}

	outdir = strings.TrimSpace(outdir)
	if outdir == "" || outdir == "/" {
		outdir = "."
	}

	err := process(scriptFile, pcapFile, outdir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitCode = 2
	}

	return
}
