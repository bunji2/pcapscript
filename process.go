package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/robertkrimen/otto"
)

func process(scriptFile, pcapFile, outdir string) (err error) {
	var handle *pcap.Handle

	var ctx *JSCtx
	ctx, err = NewJSCtx(scriptFile, outdir)
	if err != nil {
		return
	}

	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		return
	}
	defer handle.Close()

	_, err = ctx.vm.Call("BEGIN", nil, version+"; "+pcap.Version(), scriptFile, pcapFile)
	if err != nil && err.Error()[0:15] == "ReferenceError:" {
		err = nil
	}
	if err != nil {
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		var packet gopacket.Packet
		packet, err = packetSource.NextPacket()
		if err != nil {
			break
		}

		debug("[packet]", packet.String())

		err = ctx.processPacket(packet)
		if err != nil {
			break
		}

		ctx.Count = ctx.Count + 1
	}

	if err == io.EOF {
		err = nil
	}

	if err != nil {
		return
	}

	_, err = ctx.vm.Call("END", nil, ctx.Count)
	if err != nil && err.Error()[0:15] == "ReferenceError:" {
		err = nil
	}

	return
}

// JSCtx JavaScript実行コンテクスト
type JSCtx struct {
	//
	Count    int
	filePath string
	vm       *otto.Otto
	script   *otto.Script
}

// NewJSCtx 新規JavaSript実行コンテクストの生成
func NewJSCtx(filePath, outdir string) (r *JSCtx, err error) {
	vm := otto.New()
	var script *otto.Script
	script, err = vm.Compile(filePath, nil)
	if err != nil {
		return
	}

	/*
		err = vm.Set("hex", hex.Dump)
		if err != nil {
			return
		}
		err = vm.Set("hwaddr", func(bb []byte) string {
			return net.HardwareAddr(bb).String()
		})
		if err != nil {
			return
		}
		err = vm.Set("ipaddr", func(bb []byte) string {
			return net.IP(bb).String()
		})
		if err != nil {
			return
		}
		err = vm.Set("str", func(bb []byte) string {
			return string(bb)
		})
		if err != nil {
			return
		}
	*/

	// バイト列をファイルに保存する組み込み関数
	addBuiltIn("save", func(filePath string, bb []byte) {
		saveFile(outdir, filePath, bb)
	})

	// 組み込み関数をJavaSript実行コンテクストに登録
	for name, value := range BuiltIns {
		err = vm.Set(name, value)
		if err != nil {
			return
		}
	}

	/*
		//err = vm.Set("save", saveFile)
		err = vm.Set("save", func(filePath string, bb []byte) {
			saveFile(outdir, filePath, bb)
		})
		if err != nil {
			return
		}
	*/

	/*
		values := map[string]interface{}{}
		err = vm.Set("set", func(key string, value interface{}) {
			values[key] = value
		})
		if err != nil {
			return
		}
		err = vm.Set("get", func(key string) interface{} {
			return values[key]
		})
		if err != nil {
			return
		}
	*/

	_, err = vm.Run(script)
	if err != nil {
		return
	}

	r = &JSCtx{
		filePath: filePath,
		vm:       vm,
		script:   script,
	}
	return
}

// Packet パケットコンテナ
type Packet struct {
	Ethernet *layers.Ethernet
	ARP      *layers.ARP
	IPv4     *layers.IPv4
	ICMPv4   *layers.ICMPv4
	TCP      *layers.TCP
	UDP      *layers.UDP
	DNS      *layers.DNS
	/*
			ADD HERE

		NTP	     *layers.NTP

	*/
}

func (p *JSCtx) processPacket(packet gopacket.Packet) (err error) {

	if p.vm == nil {
		err = fmt.Errorf("initializing error")
		return
	}

	//fmt.Println("--------")

	//pack := readPacket(packet)
	pack := readPacket2(packet)
	ts := packet.Metadata().Timestamp

	if pack.TCP != nil {
		_, err = p.vm.Call("TCP", nil, p.Count, ts, pack.TCP, pack.IPv4, pack.Ethernet)
		//fmt.Println(err)
		if err == nil {
			return
		}
		//fmt.Printf("err.Error()[0:15] = [%s]\n", err.Error()[0:15])
		if err.Error()[0:15] == "ReferenceError:" {
			err = nil
		}
		if err != nil {
			return
		}
	}

	if pack.DNS != nil {
		_, err = p.vm.Call("DNS", nil, p.Count, ts, pack.DNS, pack.UDP, pack.IPv4, pack.Ethernet)
		//fmt.Println(err)
		if err == nil {
			return
		}
		if err.Error()[0:15] == "ReferenceError:" {
			err = nil
		}
		if err != nil {
			return
		}
	}

	if pack.UDP != nil {
		_, err = p.vm.Call("UDP", nil, p.Count, ts, pack.UDP, pack.IPv4, pack.Ethernet)
		if err == nil {
			return
		}
		if err.Error()[0:15] == "ReferenceError:" {
			err = nil
		}
		if err != nil {
			return
		}
	}

	if pack.ICMPv4 != nil {
		_, err = p.vm.Call("ICMP", nil, p.Count, ts, pack.ICMPv4, pack.IPv4, pack.Ethernet)
		if err == nil {
			return
		}
		if err.Error()[0:15] == "ReferenceError:" {
			err = nil
		}
		if err != nil {
			return
		}
	}

	if pack.IPv4 != nil {
		_, err = p.vm.Call("IP", nil, p.Count, ts, pack.IPv4, pack.Ethernet)
		if err == nil {
			return
		}
		if err.Error()[0:15] == "ReferenceError:" {
			err = nil
		}
		if err != nil {
			return
		}
	}

	if pack.ARP != nil {
		_, err = p.vm.Call("ARP", nil, p.Count, ts, pack.ARP, pack.Ethernet)
		if err == nil {
			return
		}
		if err.Error()[0:15] == "ReferenceError:" {
			err = nil
		}
		if err != nil {
			return
		}
	}

	if pack.Ethernet != nil {
		_, err = p.vm.Call("Eth", nil, p.Count, ts, pack.Ethernet)
		if err != nil && err.Error()[0:15] == "ReferenceError:" {
			err = nil
		}
	}

	return
}

func readPacket2(packet gopacket.Packet) (r Packet) {
	r = Packet{}

	for _, layer := range packet.Layers() {
		switch layer.(type) {
		case *layers.DNS:
			r.DNS, _ = layer.(*layers.DNS)
		case *layers.TCP:
			r.TCP, _ = layer.(*layers.TCP)
		case *layers.UDP:
			r.UDP, _ = layer.(*layers.UDP)
		case *layers.ICMPv4:
			r.ICMPv4, _ = layer.(*layers.ICMPv4)
		case *layers.ARP:
			r.ARP, _ = layer.(*layers.ARP)
		case *layers.IPv4:
			r.IPv4, _ = layer.(*layers.IPv4)
		case *layers.Ethernet:
			r.Ethernet, _ = layer.(*layers.Ethernet)
			/*
					ADD HERE
				case *layers.NTP:
					r.NTP, _ = layer.(*layers.NTP)
			*/
		default:
			debug("layer", layer.LayerType().String())
		}
	}
	//fmt.Println(r)
	return
}

/*
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
*/

// saveFile saves byte sequence to file
func saveFile(outdir, filePath string, bb []byte) {
	filePath = outdir + "/" + filepath.Base(filePath)
	w, err := os.Create(filepath.Clean(filePath))
	if err != nil {
		panic(err)
	}

	_, err = w.Write(bb)
	if err != nil {
		panic(err)
	}

	err = w.Close()
	if err != nil {
		panic(err)
	}
}

// http://mrtc0.hateblo.jp/entry/2016/03/19/232252
// https://godoc.org/github.com/google/gopacket
// https://godoc.org/github.com/google/gopacket/layers
