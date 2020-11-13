package main

import (
	"encoding/hex"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/robertkrimen/otto"
)

// Param パラメータ
type Param struct {
	//
	Count    int
	filePath string
	vm       *otto.Otto
	script   *otto.Script
}

// Init 初期化
func (p *Param) Init() (err error) {
	p.vm = otto.New()
	p.script, err = p.vm.Compile(p.filePath, nil)
	return
}

// Packet パケット
type Packet struct {
	Ethernet *layers.Ethernet
	ARP      *layers.ARP
	IPv4     *layers.IPv4
	ICMPv4   *layers.ICMPv4
	TCP      *layers.TCP
	UDP      *layers.UDP
}

func (p *Param) processPacket(packet gopacket.Packet) (err error) {

	/*
		fmt.Println("--------")
		pack := readPacket(packet)
		if pack.TCP != nil {
			processTCP(pack)
		} else if pack.UDP != nil {
			processUDP(pack)
		} else if pack.ICMPv4 != nil {
			processICMPv4(pack)
		} else if pack.ARP != nil {
			processARP(pack)
		}
	*/

	if p.vm == nil {
		return
	}

	//fmt.Println("--------")

	pack := readPacket(packet)
	err = p.vm.Set("count", p.Count)
	if err != nil {
		return
	}
	err = p.vm.Set("eth", pack.Ethernet)
	if err != nil {
		return
	}
	err = p.vm.Set("ip", pack.IPv4)
	if err != nil {
		return
	}
	err = p.vm.Set("arp", pack.ARP)
	if err != nil {
		return
	}
	err = p.vm.Set("tcp", pack.TCP)
	if err != nil {
		return
	}
	err = p.vm.Set("udp", pack.UDP)
	if err != nil {
		return
	}
	err = p.vm.Set("icmp", pack.ICMPv4)
	if err != nil {
		return
	}
	err = p.vm.Set("hex", hex.Dump)
	if err != nil {
		return
	}
	err = p.vm.Set("hwaddr", func(bb []byte) string {
		return net.HardwareAddr(bb).String()
	})
	if err != nil {
		return
	}
	err = p.vm.Set("ipaddr", func(bb []byte) string {
		return net.IP(bb).String()
	})
	if err != nil {
		return
	}
	err = p.vm.Set("str", func(bb []byte) string {
		return string(bb)
	})
	if err != nil {
		return
	}
	err = p.vm.Set("save", saveFile)
	if err != nil {
		return
	}
	_, err = p.vm.Run(p.script)
	if err != nil {
		return
	}

	p.Count = p.Count + 1
	return
}

func readPacket(packet gopacket.Packet) (r Packet) {
	r = Packet{}
	layer := packet.Layer(layers.LayerTypeEthernet)
	if layer != nil {
		r.Ethernet, _ = layer.(*layers.Ethernet)
		switch r.Ethernet.EthernetType {
		case layers.EthernetTypeARP:
			layer = packet.Layer(layers.LayerTypeARP)
			if layer != nil {
				r.ARP, _ = layer.(*layers.ARP)
			}
		case layers.EthernetTypeIPv4:
			layer := packet.Layer(layers.LayerTypeIPv4)
			if layer != nil {
				r.IPv4, _ = layer.(*layers.IPv4)
				switch r.IPv4.Protocol {
				case layers.IPProtocolICMPv4:
					layer = packet.Layer(layers.LayerTypeICMPv4)
					if layer != nil {
						r.ICMPv4, _ = layer.(*layers.ICMPv4)
					}
				case layers.IPProtocolTCP:
					layer = packet.Layer(layers.LayerTypeTCP)
					if layer != nil {
						r.TCP, _ = layer.(*layers.TCP)
					}
				case layers.IPProtocolUDP:
					layer = packet.Layer(layers.LayerTypeUDP)
					if layer != nil {
						r.UDP, _ = layer.(*layers.UDP)
					}
				}
			}
		}
	}
	return
}

func saveFile(filePath string, bb []byte) {
	w, err := os.Create(filePath)
	if err != nil {
		panic(err)
	}
	defer func() {
		err := w.Close()
		if err != nil {
			panic(err)
		}
	}()
	_, err = w.Write(bb)
	if err != nil {
		panic(err)
	}
}

/*
func processARP(p Packet) {
	eth := p.Ethernet
	arp := p.ARP
	fmt.Printf("[Ethernet] %s -> %s\n", eth.SrcMAC, eth.DstMAC)
	fmt.Printf("[ARP] AddrType: %s, Protocol: %s\n", arp.AddrType.String(), arp.Protocol.String())
	fmt.Printf("\tOperation: %d\n", arp.Operation)
	fmt.Printf("\tSrcHWAddr: %s\n", net.HardwareAddr(arp.SourceHwAddress).String())
	fmt.Printf("\tSrcPortAddr: %s\n", net.IP(arp.SourceProtAddress).String())
	fmt.Printf("\tDstHWAddr: %s\n", net.HardwareAddr(arp.DstHwAddress).String())
	fmt.Printf("\tDstPortAddr: %s\n", net.IP(arp.DstProtAddress).String())
}

func processICMPv4(p Packet) {
	eth := p.Ethernet
	ip := p.IPv4
	icmp := p.ICMPv4
	fmt.Printf("[Ethernet] %s -> %s\n", eth.SrcMAC, eth.DstMAC)
	fmt.Printf("[IPv4] %s -> %s\n", ip.SrcIP, ip.DstIP)
	fmt.Printf("[ICMPv4] TypeCode: %s\n", icmp.TypeCode.GoString())
	if len(icmp.Payload) > 0 {
		fmt.Printf("\tPayload: \n%s", hex.Dump(icmp.Payload))
	}
}

func processTCP(p Packet) {
	eth := p.Ethernet
	ip := p.IPv4
	tcp := p.TCP
	fmt.Printf("[Ethernet] %s -> %s\n", eth.SrcMAC, eth.DstMAC)
	fmt.Printf("[TCP] %s:%d -> %s:%d\n", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
	fmt.Printf("\tSeq: %d, Ack: %d\n", tcp.Seq, tcp.Ack)
	flags := []string{}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	fmt.Printf("\tFlags: %s\n", strings.Join(flags, ","))
	if len(tcp.Payload) > 0 {
		fmt.Printf("\tPayload: \n%s", hex.Dump(tcp.Payload))
	}
}

func processUDP(p Packet) {
	eth := p.Ethernet
	ip := p.IPv4
	udp := p.UDP
	fmt.Printf("[Ethernet] %s -> %s\n", eth.SrcMAC, eth.DstMAC)
	fmt.Printf("[UDP] %s:%d -> %s:%d\n", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
	if len(udp.Payload) > 0 {
		fmt.Printf("\tPayload: \n%s", hex.Dump(udp.Payload))
	}
}
*/

// http://mrtc0.hateblo.jp/entry/2016/03/19/232252
// https://godoc.org/github.com/google/gopacket
// https://godoc.org/github.com/google/gopacket/layers
