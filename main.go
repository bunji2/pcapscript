package main

import (
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	usageFmt = "Usage: %s file.pcap script.js\n"
)

var (
	handle *pcap.Handle
	err    error
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, usageFmt, os.Args[0])
		return 1
	}

	pcapFile := os.Args[1]
	scriptFile := os.Args[2]

	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer handle.Close()

	param := &Param{
		filePath: scriptFile,
	}

	err = param.Init()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		var packet gopacket.Packet
		packet, err = packetSource.NextPacket()
		if err != nil {
			break
		}

		err = param.processPacket(packet)
		if err != nil {
			break
		}
	}

	if err == io.EOF {
		err = nil
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}
